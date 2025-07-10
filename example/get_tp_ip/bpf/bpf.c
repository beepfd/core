// go:build ignore

#include "vmlinux.h"
#include "vmlinux-x86.h"
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_core_read.h"

#ifndef PERF_MAX_STACK_DEPTH
#define PERF_MAX_STACK_DEPTH 127
#endif

char __license[] SEC("license") = "Dual MIT/GPL";
struct
{
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(key_size, sizeof(u32));
    __uint(value_size, PERF_MAX_STACK_DEPTH * sizeof(u64));
    __uint(max_entries, 10000);
} stack_traces SEC(".maps");

static __always_inline u64 get_user_stack_ip(void *ctx)
{
    u64 user_stack[1];
    int ret = bpf_get_stack(ctx, user_stack, sizeof(user_stack), BPF_F_USER_STACK);

    if (ret > 0)
    {
        return user_stack[0];
    }

    return 0;
}

static __always_inline u64 get_kernel_stack_ip(void *ctx)
{
    u64 kernel_stack[1];
    int ret = bpf_get_stack(ctx, kernel_stack, sizeof(kernel_stack), 0);

    // 详细诊断信息
    bpf_printk("bpf_get_stack() returned: %d\n", ret);

    if (ret > 0)
    {
        bpf_printk("Successfully got kernel stack, first frame: 0x%lx\n", kernel_stack[0]);
        return kernel_stack[0];
    }
    else if (ret == 0)
    {
        bpf_printk("bpf_get_stack() returned 0 - no stack frames available\n");
    }
    else
    {
        bpf_printk("bpf_get_stack() failed with error: %d\n", ret);
    }

    return 0;
}

static __always_inline int process_kernel_stack(void *ctx, const char *event_name)
{
    u64 kernel_stack[10];
    int kernel_ret = bpf_get_stack(ctx, kernel_stack, sizeof(kernel_stack), 0);

    if (kernel_ret <= 0)
    {
        bpf_printk("Failed to get kernel stack for %s: %d\n", event_name, kernel_ret);
        return -1;
    }

    int frames = kernel_ret / sizeof(u64);
    bpf_printk("=== %s Kernel Stack Analysis ===\n", event_name);
    bpf_printk("Kernel stack frames: %d\n", frames);

    // kernel_stack[0] 是 tracepoint 触发时的内核指令地址
    bpf_printk("Tracepoint Kernel IP: 0x%lx\n", kernel_stack[0]);

    // 显示内核调用栈
    for (int i = 0; i < frames && i < 5; i++)
    {
        bpf_printk("  Kernel Frame %d: 0x%lx\n", i, kernel_stack[i]);
    }

    // 尝试获取内核栈 ID 用于后续分析
    u32 stack_id = bpf_get_stackid(ctx, &stack_traces, 0);
    if (stack_id >= 0)
    {
        bpf_printk("Kernel stack ID: %u\n", stack_id);
    }
    else
    {
        bpf_printk("Failed to get kernel stack ID: %d\n", stack_id);
    }

    return 0;
}

static __always_inline int process_user_stack(void *ctx, const char *event_name)
{
    u64 user_stack[10];
    int user_ret = bpf_get_stack(ctx, user_stack, sizeof(user_stack), BPF_F_USER_STACK);

    if (user_ret <= 0)
    {
        bpf_printk("Failed to get user stack for %s: %d\n", event_name, user_ret);
        return -1;
    }

    int frames = user_ret / sizeof(u64);
    bpf_printk("=== %s User Stack Analysis ===\n", event_name);
    bpf_printk("User stack frames: %d\n", frames);

    // user_stack[0] 是触发系统调用的用户空间指令地址
    bpf_printk("User IP (caller): 0x%lx\n", user_stack[0]);

    // 显示调用栈
    for (int i = 0; i < frames && i < 5; i++)
    {
        bpf_printk("  Frame %d: 0x%lx\n", i, user_stack[i]);
    }

    // 尝试获取栈 ID 用于后续分析
    u32 stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_USER_STACK);
    if (stack_id >= 0)
    {
        bpf_printk("User stack ID: %u\n", stack_id);
    }
    else
    {
        bpf_printk("Failed to get stack ID: %d\n", stack_id);
    }

    return 0;
}

static __always_inline void print_process_info(void)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid & 0xffffffff;

    bpf_printk("PID: %u, TID: %u\n", pid, tid);
}

// sys_enter_write tracepoint 的正确结构体定义
// 基于您提供的格式信息
struct sys_enter_write_ctx
{
    // 通用字段
    unsigned short common_type;         // offset:0,  size:2
    unsigned char common_flags;         // offset:2,  size:1
    unsigned char common_preempt_count; // offset:3,  size:1
    int common_pid;                     // offset:4,  size:4

    // 系统调用特定字段
    int __syscall_nr;    // offset:8,  size:4
    char _pad[4];        // padding to offset:16
    unsigned long fd;    // offset:16, size:8
    unsigned long buf;   // offset:24, size:8
    unsigned long count; // offset:32, size:8
} __attribute__((packed));

// 辅助函数：安全地读取 tracepoint 字段
static __always_inline unsigned long read_tp_field(void *ctx, int offset)
{
    unsigned long value = 0;
    // 使用 bpf_probe_read 而不是 bpf_core_read，因为我们是从内核内存读取
    bpf_probe_read_kernel(&value, sizeof(value), (char *)ctx + offset);
    return value;
}

SEC("tracepoint/syscalls/sys_enter_write")
int trace_write_stack(struct trace_event_raw_sys_enter *ctx)
{
    bpf_printk("========== Tracepoint IP Analysis ==========\n");

    // 基本信息
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid & 0xffffffff;
    bpf_printk("PID: %u, TID: %u\n", pid, tid);

    // 专注于内核堆栈分析
    bpf_printk("=== Kernel Stack Detailed Analysis ===\n");

    // 方法1: 直接使用 bpf_get_stack 获取内核堆栈
    u64 kernel_stack[8];
    int kernel_ret = bpf_get_stack(ctx, kernel_stack, sizeof(kernel_stack), 0);
    bpf_printk("bpf_get_stack(kernel, size=%d) returned: %d\n", sizeof(kernel_stack), kernel_ret);

    if (kernel_ret > 0)
    {
        int frames = kernel_ret / sizeof(u64);
        bpf_printk("SUCCESS: Got %d kernel stack frames\n", frames);
        for (int i = 0; i < frames && i < 8; i++)
        {
            bpf_printk("  Kernel frame %d: 0x%lx\n", i, kernel_stack[i]);
        }
    }
    else if (kernel_ret == 0)
    {
        bpf_printk("WARNING: bpf_get_stack returned 0 - no kernel frames\n");
    }
    else
    {
        bpf_printk("ERROR: bpf_get_stack failed with: %d\n", kernel_ret);
    }

    // 方法2: 使用 bpf_get_stackid 获取内核堆栈ID
    u32 kernel_stack_id = bpf_get_stackid(ctx, &stack_traces, 0);
    bpf_printk("bpf_get_stackid(kernel) returned: %d\n", kernel_stack_id);
    if (kernel_stack_id >= 0)
    {
        bpf_printk("SUCCESS: Kernel stack ID: %u\n", kernel_stack_id);
    }
    else
    {
        bpf_printk("ERROR: Failed to get kernel stack ID: %d\n", kernel_stack_id);
    }

    // 方法3: 尝试不同的 bpf_get_stackid 标志
    u32 kernel_stack_id_reuse = bpf_get_stackid(ctx, &stack_traces, BPF_F_REUSE_STACKID);
    bpf_printk("bpf_get_stackid(BPF_F_REUSE_STACKID) returned: %d\n", kernel_stack_id_reuse);

    u32 kernel_stack_id_fast = bpf_get_stackid(ctx, &stack_traces, BPF_F_FAST_STACK_CMP);
    bpf_printk("bpf_get_stackid(BPF_F_FAST_STACK_CMP) returned: %d\n", kernel_stack_id_fast);

    // 方法4: 尝试更小的缓冲区
    u64 small_kernel_stack[2];
    int small_kernel_ret = bpf_get_stack(ctx, small_kernel_stack, sizeof(small_kernel_stack), 0);
    bpf_printk("bpf_get_stack(small buffer, size=%d) returned: %d\n", sizeof(small_kernel_stack), small_kernel_ret);

    if (small_kernel_ret > 0)
    {
        int small_frames = small_kernel_ret / sizeof(u64);
        bpf_printk("SUCCESS: Got %d frames with small buffer\n", small_frames);
        for (int i = 0; i < small_frames && i < 2; i++)
        {
            bpf_printk("  Small frame %d: 0x%lx\n", i, small_kernel_stack[i]);
        }
    }

    // 方法5: 测试 get_kernel_stack_ip 函数的诊断信息
    bpf_printk("=== Testing get_kernel_stack_ip function ===\n");
    u64 kernel_ip = get_kernel_stack_ip(ctx);
    if (kernel_ip)
    {
        bpf_printk("SUCCESS: get_kernel_stack_ip returned: 0x%lx\n", kernel_ip);
    }
    else
    {
        bpf_printk("ERROR: get_kernel_stack_ip failed\n");
    }

    // 方法6: 检查 tracepoint 特性
    bpf_printk("=== Tracepoint Characteristics ===\n");

    // tracepoint 的上下文不是 pt_regs，所以不能直接访问寄存器
    // 但是我们可以检查上下文的地址
    bpf_printk("tracepoint ctx address: %p\n", ctx);

    // 尝试使用 bpf_get_current_task
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (task)
    {
        bpf_printk("Current task: %p\n", task);
    }

    // 方法7: 尝试显式的堆栈走查
    bpf_printk("=== Manual Stack Walk Attempt ===\n");

    // 尝试使用 bpf_get_stack 但指定不同的选项
    u64 raw_stack[4];
    int raw_ret = bpf_get_stack(ctx, raw_stack, sizeof(raw_stack), BPF_F_SKIP_FIELD_MASK);
    bpf_printk("bpf_get_stack(BPF_F_SKIP_FIELD_MASK) returned: %d\n", raw_ret);

    if (raw_ret > 0)
    {
        int raw_frames = raw_ret / sizeof(u64);
        bpf_printk("Got %d raw frames\n", raw_frames);
        for (int i = 0; i < raw_frames && i < 4; i++)
        {
            bpf_printk("  Raw frame %d: 0x%lx\n", i, raw_stack[i]);
        }
    }

    // 正确访问 sys_enter_write 的字段
    unsigned long fd = read_tp_field(ctx, 16);    // offset:16
    unsigned long buf = read_tp_field(ctx, 24);   // offset:24
    unsigned long count = read_tp_field(ctx, 32); // offset:32

    bpf_printk("write() args: fd=%lu, buf=0x%lx, count=%lu\n", fd, buf, count);

    // 验证系统调用号
    int syscall_nr = 0;
    bpf_probe_read_kernel(&syscall_nr, sizeof(syscall_nr), (char *)ctx + 8);
    bpf_printk("syscall_nr: %d\n", syscall_nr);

    return 0;
}

// 对比测试：使用 kprobe 检查是否能获取内核堆栈
SEC("kprobe/ksys_write")
int kprobe_ksys_write(struct pt_regs *ctx)
{
    bpf_printk("=== KPROBE Kernel Stack Test ===\n");

    // 尝试从 kprobe 上下文获取内核堆栈
    u64 kprobe_stack[5];
    int kprobe_ret = bpf_get_stack(ctx, kprobe_stack, sizeof(kprobe_stack), 0);
    bpf_printk("KPROBE bpf_get_stack() returned: %d\n", kprobe_ret);

    if (kprobe_ret > 0)
    {
        int frames = kprobe_ret / sizeof(u64);
        bpf_printk("KPROBE SUCCESS: Got %d kernel frames\n", frames);
        for (int i = 0; i < frames && i < 5; i++)
        {
            bpf_printk("  KPROBE frame %d: 0x%lx\n", i, kprobe_stack[i]);
        }
    }
    else
    {
        bpf_printk("KPROBE FAILED: %d\n", kprobe_ret);
    }

    // 尝试 kprobe 的 stackid
    u32 kprobe_stack_id = bpf_get_stackid(ctx, &stack_traces, 0);
    bpf_printk("KPROBE bpf_get_stackid() returned: %d\n", kprobe_stack_id);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_write")
int trace_write_exit(struct trace_event_raw_sys_exit *ctx)
{
    bpf_printk("========== sys_exit_write IP Analysis ==========\n");

    // 获取 tracepoint 本身的内核 IP
    u64 kernel_ip = get_kernel_stack_ip(ctx);
    if (kernel_ip)
    {
        bpf_printk("Exit Tracepoint Kernel IP: 0x%lx\n", kernel_ip);
    }

    // 复用用户栈处理函数
    process_user_stack(ctx, "sys_exit_write");

    // 获取进程信息
    print_process_info();

    // 获取系统调用返回值
    bpf_printk("write() return: %ld\n", ctx->ret);

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_read")
int trace_read_stack(struct trace_event_raw_sys_enter *ctx)
{
    bpf_printk("========== sys_enter_read IP Analysis ==========\n");

    // 快速获取内核和用户IP
    u64 kernel_ip = get_kernel_stack_ip(ctx);
    u64 user_ip = get_user_stack_ip(ctx);

    if (kernel_ip)
    {
        bpf_printk("read() tracepoint kernel IP: 0x%lx\n", kernel_ip);
    }
    if (user_ip)
    {
        bpf_printk("read() caller IP: 0x%lx\n", user_ip);
    }

    // 获取系统调用参数
    bpf_printk("read() args: fd=%ld, buf=%p, count=%ld\n",
               ctx->args[0], (void *)ctx->args[1], ctx->args[2]);

    return 0;
}
