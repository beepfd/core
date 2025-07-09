// go:build ignore

#include "vmlinux.h"
#include "vmlinux-x86.h"
#include "bpf/bpf_helpers.h"

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

SEC("tracepoint/syscalls/sys_enter_write")
int trace_write_stack(struct trace_event_raw_sys_enter *ctx)
{
    // 或者直接获取栈帧
    u64 stack[10];
    int ret = bpf_get_stack(ctx, stack, sizeof(stack), 0);
    bpf_printk("stack: %d\n", ret);
    if (ret > 0)
    {
        // stack[0] 是当前执行的指令地址
        bpf_printk("Current IP: 0x%lx\n", stack[0]);
    }

    return 0;
}
