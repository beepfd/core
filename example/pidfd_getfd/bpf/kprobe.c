// go:build ignore

#include "vmlinux.h"
#include "vmlinux-x86.h"
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_core_read.h"
#include "bpf/bpf_tracing.h"
#include "bpf/bpf_endian.h"
#include "bpf/bpf_ipv6.h"

struct event
{
    u32 hack_tgid;
    u32 hack_pid;
    u32 target_tgid;
    u64 timestamp;
    int hack_fd;
    int target_pidfd;
    int target_fd;
    char hack_comm[16];
};
struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
    __uint(max_entries, 1024);
} events SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, struct event);
} pidfd_map SEC(".maps");

struct event *unused_event_t __attribute__((unused));

SEC("tracepoint/skb/kfree_skb")
int TP_PROBE(struct trace_event_raw_kfree_skb *args)
{
    bpf_printk("addr=0x%llx reason=%d", (long long)args->skbaddr, args->reason);
    return 0;
}

// 使用 bpfsnoop -k __x64_sys_pidfd_* --output-stack --output-arg="regs->di" --output-arg="regs->si" 命令进行验证
SEC("tracepoint/syscalls/sys_enter_pidfd_getfd")
int trace_pidfd_getfd(struct trace_event_raw_sys_enter *ctx)
{
    u32 hack_pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    u32 hack_tgid = bpf_get_current_pid_tgid() >> 32;
    u64 timestamp = bpf_ktime_get_ns();

    struct event *e = bpf_map_lookup_elem(&pidfd_map, &hack_pid);
    if (!e)
    {
        return 0;
    }

    e->target_fd = (int)ctx->args[1];
    bpf_map_update_elem(&pidfd_map, &hack_pid, e, BPF_ANY);

    bpf_printk("pidfd_getfd: pid=%d, tgid=%d, timestamp=%lld, pidfd=%d, fd=%d, comm=%s\n",
               e->hack_pid, e->hack_tgid, e->timestamp, e->hack_fd, e->target_fd, e->hack_comm);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_pidfd_getfd")
int trace_pidfd_getfd_ret(struct trace_event_raw_sys_exit *ctx)
{
    u32 hack_pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    struct event *e = bpf_map_lookup_elem(&pidfd_map, &hack_pid);
    if (!e)
    {
        return 0;
    }

    int fd = (int)ctx->ret;
    e->hack_fd = fd;
    bpf_map_update_elem(&pidfd_map, &hack_pid, e, BPF_ANY);
    bpf_printk("pidfd_getfd: pid=%d, fd=%d\n", hack_pid, fd);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mmap")
int trace_mmap(struct trace_event_raw_sys_enter *ctx)
{
    u32 pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    struct event *e = bpf_map_lookup_elem(&pidfd_map, &pid);
    if (!e)
    {
        return 0;
    }

    // asmlinkage long sys_mmap(unsigned long addr, unsigned long len,
    //   unsigned long prot, unsigned long flags,
    //   unsigned long fd, unsigned long off);
    int fd = (int)ctx->args[4];
    bpf_printk("mmap: pid=%d, fd=%d\n", pid, fd);
    if (fd != e->hack_fd)
    {
        return 0;
    }

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, e, sizeof(*e));
    bpf_printk("memset: hack_pid=%d, hack_tgid=%d, hack_fd=%d, hack_comm=%s, target_tgid=%d, target_pidfd=%d, target_fd=%d\n",
               e->hack_pid, e->hack_tgid, e->hack_fd, e->hack_comm, e->target_tgid, e->target_pidfd, e->target_fd);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_pidfd_open")
int trace_pidfd_open(struct trace_event_raw_sys_enter *ctx)
{
    u32 target_tgid = (u32)ctx->args[0];
    u64 pid = bpf_get_current_pid_tgid();
    u32 hack_tgid = pid >> 32;

    struct event e = {0};
    e.hack_pid = pid;
    e.hack_tgid = hack_tgid;
    e.target_tgid = target_tgid;
    e.timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&e.hack_comm, sizeof(e.hack_comm));

    bpf_map_update_elem(&pidfd_map, &pid, &e, BPF_ANY);
    bpf_printk("pidfd_open: hack_tgid=%d, target_tgid=%d\n", hack_tgid, target_tgid);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_pidfd_open")
int trace_pidfd_open_ret(struct trace_event_raw_sys_exit *ctx)
{
    int pidfd = (int)ctx->ret;
    if (pidfd < 0)
        return 0;

    u64 pid = bpf_get_current_pid_tgid();
    struct event *e = bpf_map_lookup_elem(&pidfd_map, &pid);
    if (!e)
    {
        return 0;
    }

    e->target_pidfd = pidfd;
    bpf_map_update_elem(&pidfd_map, &pid, e, BPF_ANY);

    bpf_printk("pidfd_open: pid=%d, pidfd=%d\n", pid, pidfd);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
