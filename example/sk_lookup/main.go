package main

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cen-ngc5139/BeePF/example/sk_lookup/binary"
	meta "github.com/cen-ngc5139/BeePF/loader/lib/src/meta"
	"github.com/cilium/ebpf"

	loader "github.com/cen-ngc5139/BeePF/loader/lib/src/cli"
	"go.uber.org/zap"
)

//go:generate sh -c "echo Generating for $TARGET_GOARCH"
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $TARGET_GOARCH -go-package binary -output-dir ./binary -cc clang -no-strip sk_lookup ./bpf/sk_lookup.c -- -I../headers -Wno-address-of-packed-member

func main() {
	// 初始化日志
	logger, err := zap.NewDevelopment()
	if err != nil {
		panic("初始化日志失败: " + err.Error())
	}
	defer logger.Sync()

	config := &loader.Config{
		ObjectBytes: binary.ExportRaw(),
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

	if err := initializeSockMap(bpfLoader.Collection, logger); err != nil {
		logger.Fatal("初始化 sock map 失败", zap.Error(err))
		return
	}

	if err := bpfLoader.Start(); err != nil {
		logger.Fatal("启动失败", zap.Error(err))
	}

	if err := bpfLoader.Stats(); err != nil {
		logger.Fatal("启动统计收集器失败", zap.Error(err))
	}

	if err := bpfLoader.Metrics(); err != nil {
		logger.Fatal("启动指标失败", zap.Error(err))
	}

	logger.Info("========================================")
	logger.Info("sk_lookup POC 已启动")
	logger.Info("========================================")
	logger.Info("配置信息:")
	logger.Info("  - 拦截目标: 127.0.0.1:10000")
	logger.Info("  - 重定向到: 127.0.0.1:10001")
	logger.Info("  - Echo 服务已启动")
	logger.Info("========================================")
	logger.Info("测试命令:")
	logger.Info("  1. 重定向测试: telnet 127.0.0.1 10000")
	logger.Info("  2. 直连测试:   telnet 127.0.0.1 10001")
	logger.Info("  3. 查看日志:   sudo cat /sys/kernel/debug/tracing/trace_pipe | grep redir_ip4")
	logger.Info("========================================")

	// 等待退出信号
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	logger.Info("正常关闭")
}

func initializeSockMap(collection *ebpf.Collection, logger *zap.Logger) error {
	sockMap := collection.Maps["redir_map"]
	if sockMap == nil {
		return fmt.Errorf("redir_map not found")
	}

	// 创建监听socket（重定向目标端口）
	listener, err := net.Listen("tcp", "127.0.0.1:5201")
	if err != nil {
		return fmt.Errorf("无法创建监听socket: %w", err)
	}

	// 获取socket fd并存储到map
	if tcpListener, ok := listener.(*net.TCPListener); ok {
		file, err := tcpListener.File()
		if err != nil {
			return err
		}
		defer file.Close()

		key := uint32(0) // KEY_SERVER_A
		sockFd := uint64(file.Fd())

		logger.Info("将监听socket存储到SOCKMAP",
			zap.Uint32("key", key),
			zap.Uint64("sockFd", sockFd),
			zap.String("listen_addr", "127.0.0.1:5201"))

		err = sockMap.Update(key, sockFd, ebpf.UpdateAny)
		if err != nil {
			return fmt.Errorf("更新 sockmap 失败: %w", err)
		}

		// 启动goroutine处理连接
		go handleConnections(listener, logger)
		logger.Info("SOCKMAP 初始化成功，Echo 服务器已启动")

		return nil

	}

	return fmt.Errorf("failed to get TCP listener")
}

// 处理重定向到这里的连接
func handleConnections(listener net.Listener, logger *zap.Logger) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			logger.Error("Accept connection failed", zap.Error(err))
			continue
		}

		logger.Info("Received redirected connection",
			zap.String("remote", conn.RemoteAddr().String()))

		// 简单的echo服务器作为演示
		go func(c net.Conn) {
			defer c.Close()

			// 发送欢迎消息
			welcome := "Hello! This connection was redirected by sk_lookup BPF program!\n"
			c.Write([]byte(welcome))

			// Echo服务
			buffer := make([]byte, 1024)
			for {
				n, err := c.Read(buffer)
				if err != nil {
					break
				}
				c.Write(buffer[:n])
			}

			logger.Info("Connection closed",
				zap.String("remote", c.RemoteAddr().String()))
		}(conn)
	}
}
