#include "vmlinux.h"
#include "vmlinux-x86.h"
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_core_read.h"
#include "bpf/bpf_tracing.h"
#include "bpf/bpf_endian.h"
#include "bpf/bpf_ipv6.h"

#define AF_INET 2
#define LOCALHOST 0x0100007F // 127.0.0.1 in little endian

struct ipv4_key_t
{
    u32 pid;
    u32 saddr;
    u32 daddr;
    u16 lport;
    u16 dport;
    u64 bytes;
};

struct ipv4_key_t *unused_ipv4_key_t __attribute__((unused));

struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} tcp_events SEC(".maps");

// struct
// {
//     __uint(type, BPF_MAP_TYPE_HASH);
//     __uint(max_entries, 1024);
//     __type(key, struct ipv4_key_t);
//     __type(value, u64);
// } ipv4_recv_bytes SEC(".maps");

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(tcp_sendmsg)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (!sk)
        return 0;

    u16 family;
    if (bpf_probe_read_kernel(&family, sizeof(family), &sk->__sk_common.skc_family) < 0)
        return 0;

    size_t copied = PT_REGS_PARM3(ctx);
    if (copied <= 0)
        return 0;

    if (family == AF_INET)
    {
        struct ipv4_key_t ipv4_key = {.pid = pid};

        bpf_probe_read_kernel(&ipv4_key.saddr, sizeof(ipv4_key.saddr), &sk->__sk_common.skc_rcv_saddr);
        bpf_probe_read_kernel(&ipv4_key.daddr, sizeof(ipv4_key.daddr), &sk->__sk_common.skc_daddr);

        // 检查是否为本地回环地址 (127.0.0.1)
        if (ipv4_key.saddr == LOCALHOST && ipv4_key.daddr == LOCALHOST)
        {
            return 0; // 如果不是本地回环地址，直接返回
        }

        if (ipv4_key.saddr == ipv4_key.daddr)
        {
            return 0; // 如果是本地回环地址，直接返回
        }

        bpf_probe_read_kernel(&ipv4_key.lport, sizeof(ipv4_key.lport), &sk->__sk_common.skc_num);
        bpf_probe_read_kernel(&ipv4_key.dport, sizeof(ipv4_key.dport), &sk->__sk_common.skc_dport);

        bpf_probe_read_kernel(&ipv4_key.bytes, sizeof(ipv4_key.bytes), &copied);

        bpf_perf_event_output(ctx, &tcp_events, BPF_F_CURRENT_CPU, &ipv4_key, sizeof(ipv4_key));
    }
    return 0;
}

SEC("kprobe/tcp_v4_rcv")
int kprobe__tcp_v4_rcv(struct pt_regs *ctx)
{
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    void *skb_head = {0};
    bpf_probe_read_kernel(&skb_head, sizeof(skb_head), (void *)skb + offsetof(struct sk_buff, head)); // <- 导致异常
    return 0;
}

// SEC("kprobe/tcp_cleanup_rbuf")
// int BPF_KPROBE(tcp_cleanup_rbuf)
// {
//     u32 pid = bpf_get_current_pid_tgid() >> 32;

//     struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
//     if (!sk)
//         return 0;

//     size_t copied = PT_REGS_PARM3(ctx);
//     if (copied <= 0)
//         return 0;

//     u16 family;
//     if (bpf_probe_read_kernel(&family, sizeof(family), &sk->__sk_common.skc_family) < 0)
//         return 0;

//     if (family == AF_INET)
//     {
//         struct ipv4_key_t ipv4_key = {.pid = pid};

//         bpf_probe_read_kernel(&ipv4_key.saddr, sizeof(ipv4_key.saddr), &sk->__sk_common.skc_rcv_saddr);
//         bpf_probe_read_kernel(&ipv4_key.daddr, sizeof(ipv4_key.daddr), &sk->__sk_common.skc_daddr);

//         // 检查是否为本地回环地址 (127.0.0.1)
//         if (ipv4_key.saddr != LOCALHOST && ipv4_key.daddr != LOCALHOST)
//         {
//             return 0; // 如果不是本地回环地址，直接返回
//         }

//         bpf_probe_read_kernel(&ipv4_key.lport, sizeof(ipv4_key.lport), &sk->__sk_common.skc_num);
//         bpf_probe_read_kernel(&ipv4_key.dport, sizeof(ipv4_key.dport), &sk->__sk_common.skc_dport);

//         u64 *val = bpf_map_lookup_elem(&ipv4_recv_bytes, &ipv4_key);
//         u64 new_val = copied;
//         if (val)
//             new_val += *val;
//         bpf_map_update_elem(&ipv4_recv_bytes, &ipv4_key, &new_val, BPF_ANY);
//     }
//     return 0;
// }

char _license[] SEC("license") = "GPL";
