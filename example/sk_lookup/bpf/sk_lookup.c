// go:build ignore

#include "vmlinux.h"
#include "vmlinux-x86.h"
#include "bpf/bpf_helpers.h"

char __license[] SEC("license") = "Dual MIT/GPL";

// 定义网络常量
#define AF_INET 2
#define SK_PASS 1
#define SK_DROP 0
#define IP4(a, b, c, d) ((__u32)((d) << 24 | (c) << 16 | (b) << 8 | (a)))

// Copyright (c) 2020 Cloudflare
struct
{
    __uint(type, BPF_MAP_TYPE_SOCKMAP);
    __uint(max_entries, 32);
    __type(key, __u32);
    __type(value, __u64);
} redir_map SEC(".maps");

static const __u16 DST_PORT = 10000; /* Host byte order */
static const __u32 DST_IP4 = IP4(127, 0, 0, 1);
static const __u32 KEY_SERVER_A = 0;

/* Redirect packets destined for DST_IP4 address to socket at redir_map[0]. */
SEC("sk_lookup")
int redir_ip4(struct bpf_sk_lookup *ctx)
{
    struct bpf_sock *sk;
    int err;

    if (ctx->family != AF_INET)
    {
        bpf_printk("redir_ip4, family: %d\n", ctx->family);
        return SK_PASS;
    }
    if (ctx->local_port != DST_PORT)
    {
        return SK_PASS;
    }
    bpf_printk("redir_ip4, local_port: %d\n", ctx->local_port);
    if (ctx->local_ip4 != DST_IP4)
    {
        return SK_PASS;
    }

    bpf_printk("redir_ip4, family: %d, local_port: %d, local_ip4: %d.%d.%d.%d\n",
               ctx->family, ctx->local_port,
               (ctx->local_ip4 >> 0) & 0xFF,
               (ctx->local_ip4 >> 8) & 0xFF,
               (ctx->local_ip4 >> 16) & 0xFF,
               (ctx->local_ip4 >> 24) & 0xFF);

    sk = bpf_map_lookup_elem(&redir_map, &KEY_SERVER_A);

    err = bpf_sk_assign(ctx, sk, 0);
    bpf_sk_release(sk);

    return err ? SK_DROP : SK_PASS;
}
