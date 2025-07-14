// go:build ignore

#include "vmlinux.h"
#include "vmlinux-x86.h"
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_tracing.h"
#include "bpf/bpf_core_read.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define ETH_P_IP 0x800
#define ETH_P_IPV6 0x86dd
#define MAX_BUF_LEN 10
#define TASK_COMM_LEN 16

struct sys_enter_read_args
{
    unsigned short common_type;         // offset:0,  size:2
    unsigned char common_flags;         // offset:2,  size:1
    unsigned char common_preempt_count; // offset:3,  size:1
    int common_pid;                     // offset:4,  size:4

    int __syscall_nr;    // offset:8,  size:4
    unsigned int __pad1; // padding to align to offset:16
    unsigned long fd;    // offset:16, size:8, 作为 unsigned long 处理
    char *buf;           // offset:24, size:8
    size_t count;        // offset:32, size:8
};

SEC("kprobe/tcp_v4_rcv")
int kprobe__tcp_v4_rcv(struct pt_regs *ctx)
{
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    void *skb_head = {0};
    bpf_probe_read_kernel(&skb_head, sizeof(skb_head), (void *)skb + offsetof(struct sk_buff, head)); // <- 导致异常
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int trace_sys_enter_write(struct sys_enter_read_args *ctx)
{
    char buf_preview[16]; // 只显示前15个字符

    if (ctx->buf && ctx->count > 0)
    {
        bpf_probe_read_user_str(buf_preview, sizeof(buf_preview), ctx->buf);
    }
    else
    {
        buf_preview[0] = '\0';
    }

    bpf_printk("fd=%lu count=%lu buf=0x%lx", ctx->fd, ctx->count, (unsigned long)ctx->buf);
    bpf_printk("buf_str=\"%s\"", buf_preview); // 分成两个printk调用

    return 0;
}


// 该 prog 用于拦截 do_unlinkat 系统调用，当删除文件时，打印文件名和进程名
SEC("kprobe/do_unlinkat")
int BPF_KPROBE(do_unlinkat, int dfd, struct filename *name)
{
    const char *filename;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (pid_tgid << 32) >> 32;
    __u32 tgid = pid_tgid >> 32;
    char comm[TASK_COMM_LEN];
    long ret;

    filename = BPF_CORE_READ(name, name);

    ret = bpf_get_current_comm(&comm, TASK_COMM_LEN);
    if(ret)
    {
        bpf_printk("Failed to get current task name, pid = %d\n", pid);
        return 1;
    }
    bpf_printk("KPROBE ENTRY pid = %d, filename = %s\n", pid, filename);
    return 8;
}  