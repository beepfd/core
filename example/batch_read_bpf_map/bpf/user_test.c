#include "kprobe.skel.h"
#include <signal.h>
#include <unistd.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <time.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <errno.h>

__u32 batch_size = 10;
volatile int running = 1;

void handle_sigint(int sig)
{
    running = 0;
}

#define printf(...) fprintf(stderr, __VA_ARGS__)

struct flow_tuple_4
{
    unsigned char proto;
    __u32 src;
    __u32 dst;
    __u16 sport;
    __u16 dport;
};

void bump_memlock_rlimit(void)
{
    struct rlimit rlim_new = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };
    if (setrlimit(RLIMIT_MEMLOCK, &rlim_new))
    {
        printf("Failed to increase RLIMIT_MEMLOCK limit!");
        exit(1);
    }
}

int main()
{
    bump_memlock_rlimit();
    printf("main in\n");
    signal(SIGINT, handle_sigint);

    LIBBPF_OPTS(bpf_kprobe_opts, kprobe_opts);
    struct kprobe_bpf *skel;
    struct bpf_object_open_opts tcp_link_open_opts = {
        .sz = sizeof(struct bpf_object_open_opts),
    };
    skel = kprobe_bpf__open_opts(&tcp_link_open_opts);
    if (!skel)
    {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    printf("begin to map\n");
    struct bpf_map *mymap = skel->maps.insp_flow4_metrics;
    int ret = bpf_map__set_pin_path(mymap, "/sys/fs/bpf/testBatch/tcplink_args");
    if (ret)
    {
        fprintf(stderr, "Failed to pin map: %s\n", strerror(-ret));
    }

    if (kprobe_bpf__load(skel))
    {
        printf("Failed to load BPF tcp_link skeleton\n");
        return 2;
    }

    int err1 = kprobe_bpf__attach(skel);
    if (err1)
    {
        printf("Failed to attach BPF tcp_link skeleton\n");
        kprobe_bpf__destroy(skel);
        return 3;
    }

    int mymapFd = bpf_map__fd(mymap);
    if (mymapFd < 0)
    {
        fprintf(stderr, "Failed to get map fd: %s\n", strerror(-mymapFd));
        return -1;
    }

    __u32 key_ins = 0;
    __u32 value_ins = 1;
    struct flow_tuple_4 flow_tuple_4_ins = (struct flow_tuple_4){.proto = 6};

    for (int i = 0; i < 80; i++)
    {
        key_ins++;
        value_ins++;
        flow_tuple_4_ins.src = key_ins;
        flow_tuple_4_ins.dst = key_ins;
        flow_tuple_4_ins.sport = key_ins;
        flow_tuple_4_ins.dport = key_ins;
        if (bpf_map_update_elem(mymapFd, &flow_tuple_4_ins, &value_ins, BPF_ANY) < 0)
        {
            perror("Failed to update map");
            return -1;
        }
    }

    int key_size = sizeof(struct flow_tuple_4);
    int value_size = sizeof(__u32);

    struct flow_tuple_4 *keys = malloc(batch_size * key_size);
    __u32 *values = malloc(batch_size * value_size);
    if (!keys || !values)
    {
        fprintf(stderr, "Failed to allocate memory\n");
        goto error;
    }

    DECLARE_LIBBPF_OPTS(bpf_map_batch_opts, opts,
                        .elem_flags = 0,
                        .flags = 0, );

    while (running)
    {
        printf("in running\n");

        clock_t start_time = clock();
        __u32 count = batch_size;
        __u32 in_batch = 0;
        __u32 out_batch = 0;
        int allcount = 0;
        errno = 0;

        while (true)
        {
            count = batch_size;
            int err = bpf_map_lookup_batch(mymapFd, &in_batch, &out_batch, keys, values, &count, &opts);
            if (err != 0 && errno != ENOENT)
            {
                fprintf(stderr, "Failed to lookup batch: %s\n", strerror(errno));
                break;
            }

            allcount += count;

            for (__u32 i = 0; i < count; i++)
            {
                struct flow_tuple_4 *key_ptr = (struct flow_tuple_4 *)(keys + i);
                __u32 *value_ptr = (__u32 *)(values + i);
                printf("Key: %d, Value: %u\n", key_ptr->src, *value_ptr);
            }

            printf("allcount=%d,count=%d\n\n", allcount, count);

            if (errno == ENOENT)
            {
                printf("ENOENT---\n");
                printf("allcount=%d\n", allcount);
                break;
            }

            in_batch = out_batch;

            if (!out_batch)
            {
                break;
            }
        }

        clock_t end_time = clock();
        double time_taken = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;
        printf("Time taken: %f seconds\n", time_taken);

        sleep(5);
    }

error:
    if (skel)
    {
        kprobe_bpf__destroy(skel);
        printf("Succeed to unload and deattach BPF tcp_link skeleton\n");
    }
    free(keys);
    free(values);
    return 0;
}