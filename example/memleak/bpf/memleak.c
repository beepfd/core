// go:build ignore

#include "vmlinux.h"
#include "vmlinux-x86.h"
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_tracing.h"
#include "asm-generic/errno.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct alloc_info
{
    __u64 size;
    __u64 timestamp_ns;
    int stack_id;
};

union combined_alloc_info
{
    struct
    {
        __u64 total_size : 40;
        __u64 number_of_allocs : 24;
    } t;
    __u64 bits;
};

#define HV_DEBUG

#define ALLOCS_MAX_ENTRIES 1000000
#define COMBINED_ALLOCS_MAX_ENTRIES 10240

#define PERF_MAX_STACK_DEPTH 127

const volatile size_t min_size = 0;
const volatile size_t max_size = -1;
const volatile __u64 stack_flags = 0;

static union combined_alloc_info initial_cinfo;

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, pid_t);
    __type(value, u64);
    __uint(max_entries, 10240);
} sizes SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64); /* address */
    __type(value, struct alloc_info);
    __uint(max_entries, ALLOCS_MAX_ENTRIES);
} allocs SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64); /* stack id */
    __type(value, union combined_alloc_info);
    __uint(max_entries, COMBINED_ALLOCS_MAX_ENTRIES);
} combined_allocs SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, u64);
    __uint(max_entries, 10240);
} memptrs SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(key_size, sizeof(u32));
    __uint(value_size, PERF_MAX_STACK_DEPTH * sizeof(u64));
    __uint(max_entries, 10000);
} stack_traces SEC(".maps");

static __always_inline void *
bpf_map_lookup_or_try_init(void *map, const void *key, const void *init)
{
    void *val;
    long err;

    val = bpf_map_lookup_elem(map, key);
    if (val)
        return val;

    err = bpf_map_update_elem(map, key, init, BPF_NOEXIST);
    if (err && err != -EEXIST)
        return 0;

    return bpf_map_lookup_elem(map, key);
}

static void update_statistics_add(u64 stack_id, u64 sz)
{
    union combined_alloc_info *existing_cinfo;

    existing_cinfo = bpf_map_lookup_or_try_init(&combined_allocs, &stack_id, &initial_cinfo);
    if (!existing_cinfo)
        return;

    const union combined_alloc_info incremental_cinfo = {
        .t = {
            .total_size = sz,
            .number_of_allocs = 1}};

    __sync_fetch_and_add(&existing_cinfo->bits, incremental_cinfo.bits);
}

static void update_statistics_del(u64 stack_id, u64 sz)
{
    union combined_alloc_info *existing_cinfo;

    existing_cinfo = bpf_map_lookup_elem(&combined_allocs, &stack_id);
    if (!existing_cinfo)
    {
        bpf_printk("failed to lookup combined allocs\n");

        return;
    }

    const union combined_alloc_info decremental_cinfo = {
        .t = {
            .total_size = sz,
            .number_of_allocs = 1}};

    __sync_fetch_and_sub(&existing_cinfo->bits, decremental_cinfo.bits);
}

static int gen_alloc_enter(size_t size)
{
    if (size < min_size || size > max_size)
    {
        return 0;
    }

    const pid_t pid = bpf_get_current_pid_tgid() >> 32;
    bpf_map_update_elem(&sizes, &pid, &size, BPF_ANY);

#ifdef HV_DEBUG
    bpf_printk("alloc entered, size = %lu\n", size);
#endif

    return 0;
}

static int gen_alloc_exit2(void *ctx, u64 address)
{
    const pid_t pid = bpf_get_current_pid_tgid() >> 32;
    struct alloc_info info;

    const u64 *size = bpf_map_lookup_elem(&sizes, &pid);
    if (!size)
    {
        return 0; // missed alloc entry
    }

    __builtin_memset(&info, 0, sizeof(info));

    info.size = *size;
    bpf_map_delete_elem(&sizes, &pid);

    if (address != 0)
    {
        info.timestamp_ns = bpf_ktime_get_ns();

        info.stack_id = bpf_get_stackid(ctx, &stack_traces, stack_flags);

        bpf_map_update_elem(&allocs, &address, &info, BPF_ANY);

        update_statistics_add(info.stack_id, info.size);
    }

#ifdef HV_DEBUG
    bpf_printk("alloc exited, size = %lu, result = %lx\n",
               info.size, address);
#endif

    return 0;
}

static int gen_alloc_exit(struct pt_regs *ctx)
{
    return gen_alloc_exit2(ctx, PT_REGS_RC(ctx));
}

static int gen_free_enter(const void *address)
{
    const u64 addr = (u64)address;

    const struct alloc_info *info = bpf_map_lookup_elem(&allocs, &addr);
    if (!info)
        return 0;

    bpf_map_delete_elem(&allocs, &addr);
    update_statistics_del(info->stack_id, info->size);

#ifdef HV_DEBUG
    bpf_printk("free entered, address = %lx, size = %lu\n",
               address, info->size);
#endif

    return 0;
}

SEC("uprobe")
int malloc_enter(struct pt_regs *ctx)
{
    size_t size = (size_t)PT_REGS_PARM1(ctx);
    return gen_alloc_enter(size);
}

SEC("uretprobe")
int malloc_exit(struct pt_regs *ctx)
{
    return gen_alloc_exit(ctx);
}

SEC("uprobe")
int free_enter(struct pt_regs *ctx)
{
    void *address = (void *)PT_REGS_PARM1(ctx);
    return gen_free_enter(address);
}
