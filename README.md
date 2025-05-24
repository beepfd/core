# BeePF

![BeePF Logo](./doc/image/logo.png)

BeePF 是一个用 Go 语言编写的 eBPF 程序加载器和运行时框架。它提供了一套完整的工具链，用于加载、管理和监控 eBPF 程序。

## 特性

- 支持自动加载和管理 BTF (BPF Type Format) 信息
- 提供多种数据导出格式 (JSON、纯文本、原始数据、直方图等)
- 灵活的事件处理机制
- 支持 Map 数据采样和导出
- 内置性能监控和调试功能
- 可视化界面支持程序详情和指令查看，便于调试和分析

## 安装

确保你的系统满足以下要求：

- Go 1.16 或更高版本
- Linux 内核 5.4 或更高版本（支持 BTF）
- `clang` 和 `llvm` 用于编译 eBPF 程序

通过 Go 工具链安装：

```bash
go get github.com/cen-ngc5139/BeePF
```

## 快速开始

1. 创建一个简单的 eBPF 程序：

```bash
go get github.com/cen-ngc5139/BeePF/example/sched_wakeup
```

2. 使用 BeePF 加载和运行程序：

```go
package main

import (
	"time"

	loader "github.com/cen-ngc5139/BeePF/loader/lib/src/cli"
	"go.uber.org/zap"
)

//go:generate sh -c "echo Generating for $TARGET_GOARCH"
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type sched_latency_t -target $TARGET_GOARCH -go-package binary -output-dir ./binary -cc clang -no-strip Shepherd ./bpf/trace.c -- -I../headers -Wno-address-of-packed-member

func main() {
	// 初始化日志
	logger, err := zap.NewDevelopment()
	if err != nil {
		logger.Fatal("初始化日志失败", zap.Error(err))
		return
	}
	defer logger.Sync()

	config := &loader.Config{
		// 设置 eBPF 程序对象文件路径
		ObjectPath:  "./binary/shepherd_x86_bpfel.o",
		// 设置日志记录器
		Logger:      logger,
		// 设置要处理的结构体名称
		StructName:  "sched_latency_t",
		// 设置轮询超时时间
		PollTimeout: 100 * time.Millisecond,
		// 设置是否启用 stats 收集
		IsEnableStats: true,
		// 设置 stats 收集间隔
		StatsInterval: 1 * time.Second,
			// 设置用户自定义的 map 数据导出处理器
		UserExporterHandler: &export.MyCustomHandler{
			Logger: logger,
		},
		// 设置用户自定义的 metrics 数据导出处理器
		UserMetricsHandler: &metrics.DefaultHandler{
			Logger: logger,
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
		logger.Fatal("start failed", zap.Error(err))
	}

	// 启动 stats 收集
	if err := bpfLoader.Stats(); err != nil {
		logger.Fatal("start stats collector failed", zap.Error(err))
	}

	// 启动 metrics 收集
	if err := bpfLoader.Metrics(); err != nil {
		logger.Fatal("start metrics failed", zap.Error(err))
	}

	// 等待退出信号
	<-bpfLoader.Done()
	logger.Info("clean shutdown")
}
```
**生成指令部分**：

````go
//go:generate sh -c "echo Generating for $TARGET_GOARCH"
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type sched_latency_t -target $TARGET_GOARCH -go-package binary -output-dir ./binary -cc clang -no-strip Shepherd ./bpf/trace.c -- -I../headers -Wno-address-of-packed-member
````
需要自定义的参数：
- `sched_latency_t`：您的 eBPF 程序中定义的结构体名称
- `./bpf/trace.c`：您的 eBPF 程序源文件路径
- `-I../headers`：头文件包含路径
- `Shepherd`：生成的 Go 代码前缀

**配置部分**：

````go
config := &loader.Config{
    ObjectPath:  "./binary/shepherd_x86_bpfel.o",  // eBPF 对象文件路径
    Logger:      logger,                           // 日志实例
    StructName:  "sched_latency_t",               // 要处理的结构体名称
    PollTimeout: 100 * time.Millisecond,          // 轮询超时时间
}
````
需要自定义的配置：
- `ObjectPath`：编译后的 eBPF 对象文件路径，需要与生成指令中的名称对应
- `StructName`：与您的 eBPF 程序中定义的结构体名称对应
- `PollTimeout`：根据您的需求调整轮询间隔

**目录结构**：

```
your_project/
├── main.go                 # 主程序
├── bpf/
│   └── trace.c            # eBPF 程序源码
├── headers/               # eBPF 程序需要的头文件
└── binary/               # 生成的文件存放目录
    ├── shepherd_x86_bpfel.o
    └── shepherd_bpfel.go
```

**eBPF 程序示例** (trace.c)：

````c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct sched_latency_t {
    u32 pid;
    u64 timestamp;
    // 自定义字段...
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, 1024);
} events SEC(".maps");

SEC("tracepoint/sched/sched_wakeup")
int trace_wakeup(struct trace_event_raw_sched_wakeup *ctx)
{
    struct sched_latency_t data = {};
    // 填充数据...
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
````

需要自定义的部分：
1. 定义您自己的数据结构 (`struct sched_latency_t`)
2. 选择合适的 eBPF 程序类型（tracepoint/kprobe/等）
3. 实现数据收集逻辑
4. 选择合适的 map 类型（PERF_EVENT_ARRAY/RING_BUF/等）

**编译和运行**：

```bash
# 设置架构
export TARGET_GOARCH=amd64

# 生成 eBPF 对象和 Go 代码
go generate

# 编译和运行
go build
sudo ./your_program
```

**注意事项**：

- 确保系统内核版本支持 eBPF（5.4+推荐）
- 安装必要的依赖（clang、llvm、libbpf-dev等）
- 程序通常需要 root 权限运行
- 根据实际需求调整 map 大小和轮询间隔
- 考虑添加错误处理和数据处理逻辑

这个示例提供了基本框架，您可以根据具体需求：
1. 修改数据结构
2. 选择不同的 eBPF 程序类型
3. 实现自己的数据处理逻辑
4. 调整性能参数
5. 添加监控和报警功能

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