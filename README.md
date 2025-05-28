# BeePF

<table>
<tr>
<td width="150">
<img src="./doc/image/logo.png" alt="BeePF Logo" width="150" height="auto">
</td>
<td>
BeePF core 是一个用 Go 语言编写的 eBPF 程序加载器和运行时框架。它提供了一套完整的工具链，用于加载、管理和监控 eBPF 程序。
</td>
</tr>
</table>

## 特性

- 支持自动加载和管理 BTF (BPF Type Format) 信息
- 提供多种数据导出格式 (JSON、纯文本、原始数据、直方图等)
- 灵活的事件处理机制
- 支持 Map 数据采样和导出
- 内置性能监控和调试功能

## 安装

确保你的系统满足以下要求：

- Go 1.23.0 或更高版本
- Linux 内核 5.4 或更高版本（支持 BTF）
- `clang` 和 `llvm` 用于编译 eBPF 程序

通过 Go 工具链安装：

```bash
go get github.com/cen-ngc5139/BeePF
```

## 快速开始

1. 获取 pidfd_getfd 示例项目：

```bash
git clone https://github.com/cen-ngc5139/BeePF.git
cd BeePF/example/pidfd_getfd
```

2. 使用 BeePF 加载和运行程序：

```go
package main

import (
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cen-ngc5139/BeePF/example/pidfd_getfd/binary"
	"github.com/cen-ngc5139/BeePF/example/tcpnat/src"
	"github.com/cen-ngc5139/BeePF/loader/lib/src/meta"

	loader "github.com/cen-ngc5139/BeePF/loader/lib/src/cli"
	"go.uber.org/zap"
)

//go:generate sh -c "echo Generating for $TARGET_GOARCH"
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $TARGET_GOARCH -go-package binary -output-dir ./binary -cc clang -no-strip kprobe ./bpf/kprobe.c -- -I../headers -Wno-address-of-packed-member

func main() {
	// 初始化日志
	logger, err := zap.NewDevelopment()
	if err != nil {
		panic("初始化日志失败: " + err.Error())
	}
	defer logger.Sync()

	config := &loader.Config{
		// 使用预编译的二进制数据
		ObjectBytes: binary.ExportRaw(),
		// 设置日志记录器
		Logger:      logger,
		// 设置轮询超时时间
		PollTimeout: 100 * time.Millisecond,
		// 配置 Map 属性
		Properties: meta.Properties{
			Maps: map[string]*meta.Map{
				"pidfd_map": {
					ExportHandler: &src.SkipHandler{},
				},
			},
		},
	}

	// 创建 BPF 加载器
	bpfLoader := loader.NewBPFLoader(config)

	// 初始化 BPF 加载器
	err = bpfLoader.Init()
	if err != nil {
		logger.Fatal("初始化 BPF 加载器失败", zap.Error(err))
		return
	}

	// 加载 eBPF 程序
	err = bpfLoader.Load()
	if err != nil {
		logger.Fatal("加载 BPF 程序失败", zap.Error(err))
		return
	}

	// 启动 eBPF 程序
	if err := bpfLoader.Start(); err != nil {
		logger.Fatal("启动失败", zap.Error(err))
	}

	// 启动 stats 收集
	if err := bpfLoader.Stats(); err != nil {
		logger.Fatal("启动统计收集器失败", zap.Error(err))
	}

	// 启动 metrics 收集
	if err := bpfLoader.Metrics(); err != nil {
		logger.Fatal("启动指标失败", zap.Error(err))
	}

	// 等待退出信号
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	logger.Info("正常关闭")
}
```

**生成指令部分**：

```go
//go:generate sh -c "echo Generating for $TARGET_GOARCH"
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $TARGET_GOARCH -go-package binary -output-dir ./binary -cc clang -no-strip kprobe ./bpf/kprobe.c -- -I../headers -Wno-address-of-packed-member
```

需要自定义的参数：
- `kprobe`：生成的 Go 代码前缀
- `./bpf/kprobe.c`：eBPF 程序源文件路径
- `-I../headers`：头文件包含路径

**配置部分**：

```go
config := &loader.Config{
    ObjectBytes: binary.ExportRaw(),    // 使用预编译的二进制数据
    Logger:      logger,                // 日志实例
    PollTimeout: 100 * time.Millisecond, // 轮询超时时间
    Properties: meta.Properties{        // Map 配置
        Maps: map[string]*meta.Map{
            "pidfd_map": {
                ExportHandler: &src.SkipHandler{},
            },
        },
    },
}
```

**目录结构**：

```
pidfd_getfd/
├── main.go                 # 主程序
├── Makefile               # 构建配置
├── bpf/
│   └── kprobe.c          # eBPF 程序源码
└── binary/               # 生成的文件存放目录
    ├── kprobe_bpfel.o
    └── kprobe_bpfel.go
```

**eBPF 程序功能** (kprobe.c)：

这个示例监控 `pidfd_getfd` 系统调用，用于检测进程间文件描述符获取行为：

```c
struct event {
    u32 hack_tgid;      // 发起调用的进程组ID
    u32 hack_pid;       // 发起调用的进程ID
    u32 target_tgid;    // 目标进程组ID
    u64 timestamp;      // 时间戳
    int hack_fd;        // 获取到的文件描述符
    int target_pidfd;   // 目标进程的pidfd
    int target_fd;      // 目标进程的文件描述符
    char hack_comm[16]; // 进程名称
};

// 监控 pidfd_getfd 系统调用入口
SEC("tracepoint/syscalls/sys_enter_pidfd_getfd")
int trace_pidfd_getfd(struct trace_event_raw_sys_enter *ctx)

// 监控 pidfd_getfd 系统调用出口
SEC("tracepoint/syscalls/sys_exit_pidfd_getfd")
int trace_pidfd_getfd_ret(struct trace_event_raw_sys_exit *ctx)

// 监控相关的 mmap 调用
SEC("tracepoint/syscalls/sys_enter_mmap")
int trace_mmap(struct trace_event_raw_sys_enter *ctx)
```

**编译和运行**：

```bash
# 设置架构
export TARGET_GOARCH=amd64

# 生成 eBPF 对象和 Go 代码
make build

# 运行程序（需要 root 权限）
sudo ./getfd
```

**测试程序功能**：

在另一个终端中，可以使用以下命令测试 pidfd_getfd 功能：

```bash
# 创建一个测试进程
sleep 1000 &
TARGET_PID=$!

# 使用 pidfd_getfd 获取文件描述符（需要支持该系统调用的内核）
# 这将触发 eBPF 程序记录相关事件
```

**注意事项**：

- 确保系统内核版本支持 `pidfd_getfd` 系统调用（Linux 5.6+）
- 程序需要 root 权限运行
- 该示例展示了如何监控系统调用和进程间文件描述符操作
- 可以通过 `/sys/kernel/debug/tracing/trace_pipe` 查看 BPF 程序输出

## 架构

BeePF 主要由以下组件组成：

- **Loader**: eBPF 程序加载器
- **Skeleton**: 程序骨架生成器和管理器
- **BTF**: BTF 信息处理器
- **Export**: 数据导出和处理模块
- **Container**: ELF 和 BTF 容器管理

## 配置

BeePF 支持通过环境变量和配置文件进行配置：

- `BTF_FILE_PATH`: 指定 BTF 文件路径
- `VMLINUX_BTF_PATH`: 系统 BTF 文件路径（默认：/sys/kernel/btf/vmlinux）

## 贡献

欢迎提交 Pull Request 和 Issue！在提交代码前，请确保：

1. 代码通过所有测试
2. 新功能包含相应的测试用例
3. 更新相关文档

## 许可证

本项目采用 MIT 许可证。详见 [LICENSE](LICENSE) 文件。