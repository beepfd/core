package main

import (
	"log"
	"os"
	"time"

	"github.com/cen-ngc5139/BeePF/example/bad_btf/binary"
	"github.com/cen-ngc5139/BeePF/loader/lib/src/meta"
	"github.com/cilium/ebpf/rlimit"

	_ "embed"

	loader "github.com/cen-ngc5139/BeePF/loader/lib/src/cli"
	"go.uber.org/zap"
)

//go:generate sh -c "echo Generating for $TARGET_GOARCH"
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $TARGET_GOARCH -go-package binary -output-dir ./binary -cc clang -no-strip BadBTF ./bpf/bpf.c -- -I../headers -Wno-address-of-packed-member

//go:embed min_core_btfs.tar.gz
var minCoreBtfs []byte

func main() {
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
		ObjectBytes: binary.ExportRaw(),
		BTFBytes:    minCoreBtfs,
		Logger:      logger,
		PollTimeout: 100 * time.Millisecond,
		Properties:  meta.Properties{},
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
