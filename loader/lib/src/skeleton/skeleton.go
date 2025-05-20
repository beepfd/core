package skeleton

import (
	"sync/atomic"

	"github.com/cen-ngc5139/BeePF/loader/lib/src/container"
	"github.com/cen-ngc5139/BeePF/loader/lib/src/meta"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
)

// PreLoadBpfSkeleton 表示一个已初始化但尚未加载的 BPF 程序
type PreLoadBpfSkeleton struct {
	// Meta 数据控制 ebpf 程序的行为
	// 例如: maps 和 programs 的类型,导出数据类型等
	Meta *meta.EunomiaObjectMeta

	// 程序的配置数据
	ConfigData *meta.RunnerConfig

	// BTF 信息
	Btf *container.BTFContainer

	// BTFSpec 表示 BTF 的规范
	BTFSpec *btf.Spec

	// CollectionSpec 替代原来的 bpf_object
	// 包含了未加载的程序和 maps 的规格说明
	Spec *ebpf.CollectionSpec

	// map 值大小的缓存
	MapValueSizes map[string]uint32

	// 原始 ELF 数据
	RawElf *container.ElfContainer
}

// BpfSkeleton 表示一个已加载并运行的 BPF 程序
type BpfSkeleton struct {
	// 用于控制轮询过程的句柄
	Handle *PollingHandle

	// 程序元数据
	Meta *meta.EunomiaObjectMeta

	// 配置数据
	ConfigData *meta.RunnerConfig

	// BTF 信息
	Btf *container.BTFContainer

	// 程序的链接信息
	Links []link.Link

	// Collection 替代原来的 prog
	// 包含已加载的程序和 maps
	Collection *ebpf.Collection
}

// PollingHandle 用于控制轮询过程
type PollingHandle struct {
	State atomic.Uint32
}

const (
	pauseBit uint32 = 1 << iota
	terminatingBit
)

// AttachLink 表示程序的附加点
type AttachLink interface {
	Close() error
}
