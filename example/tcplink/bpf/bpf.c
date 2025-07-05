#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#define TCPCB_SACKED_RETRANS    0x02    /* SKB retransmitted            */
#define TCPCB_LOST              0x04    /* SKB is lost                  */


struct flow_tuple_4 {
    unsigned char proto;
    u32 src;
    u32 dst;
    u16 sport;
    u16 dport;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, struct flow_tuple_4);
  __type(value, u32);
  __uint(max_entries, 8192);
} insp_flow4_metrics SEC(".maps");

SEC("kprobe/tcp_conn_request")
int handle_tcp_mark_skb_lost(struct pt_regs *ctx) {
    bpf_printk("TCP Lost Retransmitin");
    struct sock *sk = (struct sock *)PT_REGS_PARM2(ctx);
    __u32 saddr, daddr;
    __u16 sport, dport;
    struct sk_buff *skb =(struct sk_buff *)PT_REGS_PARM3(ctx);
    if (!sk || !skb) {
        bpf_printk("sock pointer is null\n");
        return 0;
    }
//__u8 sacked=((struct tcp_skb_cb *)&((skb)->cb[0]))->sacked;
    struct tcp_skb_cb *tcp_cb = (struct tcp_skb_cb *)BPF_CORE_READ(skb, cb);
    __u32 sacked = BPF_CORE_READ(tcp_cb, tcp_tw_isn);
    __u32 sk_ack_backlog  = BPF_CORE_READ(sk, sk_ack_backlog);
    __u32 sk_max_backlog = BPF_CORE_READ(sk, sk_max_ack_backlog);
//      if (sacked & TCPCB_LOST) {
//              if (sacked & TCPCB_SACKED_RETRANS){
    // 从 sock 结构读取信息
    saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr); // 接收方地址
    daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);     // 目的地址
    sport = BPF_CORE_READ(sk, __sk_common.skc_num);        // 源端口
    dport = BPF_CORE_READ(sk, __sk_common.skc_dport);      // 目的端口


// 将网络字节序转换为主机字节序
    saddr = bpf_ntohl(saddr);
    daddr = bpf_ntohl(daddr);
    sport = bpf_ntohs(sport);
    dport = bpf_ntohs(dport);

    bpf_printk("TCP conn Retransmit: %u,%u,%u", sacked, sk_ack_backlog, sk_max_backlog);
    // 打印调试信息
    // bpf_printk("TCP Lost Retransmit: %pI4:%d -> %pI4:%d", &saddr, sport, &daddr, dport);
//}}

    struct flow_tuple_4 link = {0};
    link.src=saddr;
    link.dst=daddr;
    link.sport=sport;
    link.dport=dport;
    link.proto=111;
    struct tcp_sock *tcp_sock = (struct tcp_sock *)sk;
    u32 syn_rtt=BPF_CORE_READ(tcp_sock,srtt_us);
    bpf_map_update_elem(&insp_flow4_metrics,&link,&syn_rtt, BPF_ANY);
    return 0;
}


char _license[] SEC("license") = "GPL";