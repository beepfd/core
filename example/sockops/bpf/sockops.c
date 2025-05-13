#include "vmlinux.h"
#include "vmlinux-x86.h"
#include <bpf/bpf_helpers.h>
#include "bpf/bpf_core_read.h"
#include "bpf/bpf_tracing.h"
#include "bpf/bpf_endian.h"
#include "bpf/bpf_ipv6.h"

#define CUSTOM_TCP_OPT_KIND 0xDA
#define CUSTOM_TCP_OPT_LEN 2
struct tcp_opt_source_info
{
    __u8 kind;
    __u8 len;
    struct address_info
    {
        __be32 ip4;
        __be16 port;
    } __attribute__((packed)) address;
} __attribute__((packed));
#define TCP_OPT_SOURCE_INFO_KIND 0x55

SEC("sockops")
int handle_tcp_options(struct bpf_sock_ops *skops)
{
    // 使用 bpf_htonl 函数时，需要将 skops 中的端口转换为 __u32
    __u32 dport = ((skops->remote_port) >> 16);
    __u32 sport = (__builtin_bswap32(skops->local_port) >> 16);

    // // 检查端口
    // if (33315 != dport && 33315 != sport)
    // {
    //     return 0;
    // }

    // bpf_printk("local port is %d, remote port is %d\n", sport, dport);
    bpf_printk("Triggered socket op: %d\n", skops->op);

    switch (skops->op)
    {
    case BPF_SOCK_OPS_TCP_LISTEN_CB:
    case BPF_SOCK_OPS_TCP_CONNECT_CB:
    case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
    {
        bpf_printk("set flag triggered");
        int err1 = bpf_sock_ops_cb_flags_set(skops,
                                             skops->bpf_sock_ops_cb_flags |
                                                 (BPF_SOCK_OPS_PARSE_UNKNOWN_HDR_OPT_CB_FLAG |
                                                  BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG));
        if (err1 < 0)
        {
            bpf_printk("ops_cb_flags_set failed: %d", err1);
        }
        return 0;
    }
    case BPF_SOCK_OPS_HDR_OPT_LEN_CB: // 处理选项长度预留
        bpf_printk("HDR_OPT_LEN_CB triggered");
        const int bytes_to_reserve = sizeof(struct tcp_opt_source_info);
        int err = bpf_reserve_hdr_opt(skops, bytes_to_reserve, 0);
        if (err != 0)
        {
            bpf_printk("Reserve failed: %d", err);
        }
        return 0;
    case BPF_SOCK_OPS_WRITE_HDR_OPT_CB: // 处理选项写入
        bpf_printk("WRITE_HDR_OPT_CB triggered");
        struct tcp_opt_source_info opt = {0};
        opt.kind = TCP_OPT_SOURCE_INFO_KIND;
        opt.len = sizeof(struct tcp_opt_source_info);
        opt.address.ip4 = skops->local_ip4; /* stored in network byte order (bpf.h) */
        opt.address.port = sport;           /* stored in host byte order (bpf.h) */

        int ret = bpf_store_hdr_opt(skops, &opt, sizeof(opt), 0);
        //            char opt_data[CUSTOM_TCP_OPT_LEN] = { CUSTOM_TCP_OPT_KIND, CUSTOM_TCP_OPT_LEN };
        //          int ret = bpf_store_hdr_opt(skops, opt_data, sizeof(opt_data), 0);
        if (ret < 0)
        {
            bpf_printk("Store failed: %d", ret);
        }
        return 0;

    default:
        return 0;
    }
}

char _license[] SEC("license") = "GPL";