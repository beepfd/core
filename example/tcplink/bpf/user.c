#include "kprobe.skel.h"
#include <signal.h>
#include <unistd.h>
#include <inttypes.h> // 包含 PRIu64
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <errno.h>

// 全局变量
volatile int running = 1;

// 信号处理函数
void handle_sigint(int sig)
{
    running = 0; // 设置标志以退出循环
}

// 日志宏定义
#define __debug_printf printf
#define warn_logs printf
#define info_logs printf
#define error_logs printf

// 网络流四元组结构体
struct flow_tuple_4
{
    unsigned char proto;
    __u32 src;
    __u32 dst;
    __u16 sport;
    __u16 dport;
};

int main()
{
    error_logs("main in\n");

    // 设置信号处理
    signal(SIGINT, handle_sigint);

    // 声明 BPF 选项和骨架
    LIBBPF_OPTS(bpf_kprobe_opts, kprobe_opts);
    struct kprobe_bpf *skel;

    // 打开 BPF 对象
    struct bpf_object_open_opts tcp_link_open_opts = (
        {
            memset(&tcp_link_open_opts, 0, sizeof(struct bpf_object_open_opts));
            (struct bpf_object_open_opts){.sz = sizeof(struct bpf_object_open_opts)};
        });
    skel = kprobe_bpf__open_opts(&tcp_link_open_opts);

    if (!skel)
    {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    error_logs("begin to map\n");

    // 获取 map 并设置 pin 路径
    struct bpf_map *mymap = skel->maps.insp_flow4_metrics;
    int ret = bpf_map__set_pin_path(mymap, "/sys/fs/bpf/testBatch/tcplink_args");
    if (ret)
    {
        fprintf(stderr, "Failed to pin map: %s\n", strerror(-ret));
    }

    // 加载 BPF 程序
    if (kprobe_bpf__load(skel))
    {
        error_logs("Failed to load BPF tcp_link skeleton\n");
        return 2;
    }

    // 附加 BPF 程序
    int err1 = kprobe_bpf__attach(skel);
    if (err1)
    {
        error_logs("Failed to attach BPF tcp_link skeleton\n");
        kprobe_bpf__destroy(skel);
        skel = NULL;
        return 3;
    }

    // 设置批量操作参数
    int key_size = sizeof(struct flow_tuple_4);
    int value_size = sizeof(__u32);

    while (running)
    {
        sleep(1);
        error_logs("in running\n");

        // 使用 get_next_key 方法作为对比
        struct flow_tuple_4 key;
        struct flow_tuple_4 next_key;
        __u32 value;
        memset(&key, 0, sizeof(key));
        printf("=== Using get_next_key method ===\n");
        int found_entries = 0;
        while (bpf_map__get_next_key(mymap, &key, &next_key, sizeof(struct flow_tuple_4)) == 0)
        {
            int ret = bpf_map__lookup_elem(mymap, &next_key, sizeof(struct flow_tuple_4),
                                           &value, sizeof(__u32), 0);
            if (!ret)
            {
                printf("Entry %d: proto=%d, src=%u, dst=%u, sport=%u, dport=%u, value=%u\n",
                       found_entries + 1, next_key.proto, next_key.src, next_key.dst, next_key.sport, next_key.dport, value);
                found_entries++;
            }
            key = next_key;
        }
        printf("Total entries found with get_next_key: %d\n\n", found_entries);

        // 设置批量大小和缓冲区
        // __u32 batch_size = 1; // 每次批量读取的数量
        // void *keys = malloc(batch_size * key_size);
        // void *values = malloc(batch_size * value_size);
        // if (!keys || !values) {
        //     fprintf(stderr, "Failed to allocate memory\n");
        //     goto error;
        // }

        // 使用批量操作
        printf("=== Using bpf_map_lookup_batch method ===\n");
        error_logs("Map fd: %d\n", bpf_map__fd(mymap));
        error_logs("Map type: %d\n", bpf_map__type(mymap));
        error_logs("Key size: %d, Value size: %d\n", bpf_map__key_size(mymap), bpf_map__value_size(mymap));
        error_logs("struct flow_tuple_4 size: %zu\n", sizeof(struct flow_tuple_4));
        error_logs("__u32 size: %zu\n", sizeof(__u32));

        // 批量查找操作 - 先尝试批量大小为 1
        const __u32 batch_size = 1;
        struct flow_tuple_4 keys[batch_size];
        __u32 values[batch_size];
        void *in_batch = NULL, *out_batch = NULL;
        DECLARE_LIBBPF_OPTS(bpf_map_batch_opts, opts,
                            .elem_flags = 0,
                            .flags = 0, );

        int batch_entry_count = 0;
        while (true)
        {
            __u32 count = batch_size;

            error_logs("Calling bpf_map_lookup_batch with:\n");
            error_logs("  map_fd=%d, in_batch=%p, out_batch=%p, count=%d\n",
                       bpf_map__fd(mymap), in_batch, out_batch, count);

            int err = bpf_map_lookup_batch(bpf_map__fd(mymap), in_batch, &out_batch,
                                           keys, values, &count, &opts);

            error_logs("bpf_map_lookup_batch returned: err=%d, errno=%d (%s)\n",
                       err, errno, strerror(errno));
            error_logs("  after call: in_batch=%p, out_batch=%p, count=%d\n",
                       in_batch, out_batch, count);

            // 如果没有获取到任何数据，则退出
            if (count == 0)
            {
                error_logs("No entries returned, exiting\n");
                break;
            }

            // 打印获取到的数据
            error_logs("Processing %d entries:\n", count);
            for (__u32 i = 0; i < count; i++)
            {
                struct flow_tuple_4 *key_ptr = &keys[i];
                __u32 *value_ptr = &values[i];
                printf("Entry %d: proto=%d, src=%u, dst=%u, sport=%u, dport=%u, value=%u\n",
                       batch_entry_count + 1, key_ptr->proto, key_ptr->src, key_ptr->dst,
                       key_ptr->sport, key_ptr->dport, *value_ptr);
                batch_entry_count++;
            }

            // 更新 in_batch 以继续下一批次
            in_batch = out_batch;

            // 如果返回了错误（通常是 ENOENT 表示已到末尾），在处理完当前批次后退出
            if (err != 0)
            {
                error_logs("Error returned (%d), this was the last batch\n", err);
                break;
            }
        }
        printf("Total entries found with batch lookup: %d\n\n", batch_entry_count);
    }

error:
    if (skel != NULL)
    {
        kprobe_bpf__destroy(skel);
        info_logs("Succeed to unload and deattach BPF tcp_link skeleton\n");
    }

    return 0;
}