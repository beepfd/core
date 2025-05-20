package main

import (
	"log"
	"net"
	"os"
	"time"

	"github.com/cen-ngc5139/BeePF/example/tcpnat/src"
	"github.com/cen-ngc5139/BeePF/loader/lib/src/meta"
	"github.com/cilium/ebpf/rlimit"

	_ "embed"
	"flag"

	loader "github.com/cen-ngc5139/BeePF/loader/lib/src/cli"
	"go.uber.org/zap"
)

//go:generate sh -c "echo Generating for $TARGET_GOARCH"
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type ipv4_key_t  -target $TARGET_GOARCH -go-package main -output-dir ./ -cc clang -no-strip TcpNat ./bpf/tcpnat.c -- -I../headers -Wno-address-of-packed-member

//go:embed min_core_btfs.tar.gz
var minCoreBtfs []byte

var SkipNet = flag.String("skip", "", "跳过指定网络，格式为逗号分隔的CIDR列表，如 10.0.0.0/24,192.168.100.0/24")

func main() {
	flag.Parse()

	var skipNets []*net.IPNet
	var err error
	if *SkipNet != "" {
		skipNets, err = src.ParseCIDRList(*SkipNet)
		if err != nil {
			log.Fatalf("解析跳过网段失败: %v\n", err)
			os.Exit(1)
		}
	}
	// 移除 eBPF 程序的内存限制
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock limit: %v\n", err)
		os.Exit(1)
	}

	// 初始化日志
	logger, err := zap.NewDevelopment()
	if err != nil {
		logger.Fatal("初始化日志失败", zap.Error(err))
		return
	}
	defer logger.Sync()

	config := &loader.Config{
		ObjectBytes: _TcpNatBytes,
		BTFBytes:    minCoreBtfs,
		Logger:      logger,
		PollTimeout: 100 * time.Millisecond,
		Properties: meta.Properties{
			Maps: map[string]*meta.Map{
				"tcp_events": {
					ExportHandler: &src.SendHandler{
						Logger:   logger,
						SkipNets: skipNets,
					},
				},
			},
		},
	}

	bpfLoader := loader.NewBPFLoader(config)

	err = bpfLoader.Init()
	if err != nil {
		logger.Fatal("初始化 BPF 加载器失败", zap.Error(err))
		return
	}

	err = bpfLoader.Load()
	if err != nil {
		logger.Fatal("加载 BPF 程序失败", zap.Error(err))
		return
	}

	if err := bpfLoader.Start(); err != nil {
		logger.Fatal("start failed", zap.Error(err))
	}

	if err := bpfLoader.Stats(); err != nil {
		logger.Fatal("start stats collector failed", zap.Error(err))
	}

	if err := bpfLoader.Metrics(); err != nil {
		logger.Fatal("start metrics failed", zap.Error(err))
	}

	// 等待退出信号
	<-bpfLoader.Done()
	logger.Info("clean shutdown")
}
