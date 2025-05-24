package meta

import (
	"encoding/json"
	"sync"

	"github.com/cilium/ebpf/btf"
)

// EunomiaObjectMeta 全局元数据配置
// 用于描述 eBPF 程序的全局配置和元数据信息
type EunomiaObjectMeta struct {
	// ExportTypes 描述程序导出到用户空间的数据类型
	// 这些类型将通过 BTF 进行验证，并用于格式化输出
	ExportTypes []ExportedTypesStructMeta `json:"export_types"`

	// BpfSkel eBPF 程序的骨架元数据
	BpfSkel BpfSkeletonMeta `json:"bpf_skel"`

	// PerfBufferPages perf 缓冲区的页数，默认为 64
	PerfBufferPages uint `json:"perf_buffer_pages,omitempty"`

	// PerfBufferTimeMs perf 缓冲区的超时时间（毫秒），默认为 10
	PerfBufferTimeMs uint `json:"perf_buffer_time_ms,omitempty"`

	// PollTimeoutMs 轮询超时时间（毫秒），默认为 100
	PollTimeoutMs int `json:"poll_timeout_ms,omitempty"`

	// DebugVerbose 是否启用 libbpf 调试信息输出
	DebugVerbose bool `json:"debug_verbose,omitempty"`

	// PrintHeader 是否打印导出类型的类型和名称信息
	PrintHeader bool `json:"print_header,omitempty"`

	// EnableMultiExportTypes 是否启用多导出类型支持
	// 如果为 true，将使用每个 map 的 export_config 字段
	// 如果为 false，将保持与旧版本的兼容性
	EnableMultiExportTypes bool `json:"enable_multiple_export_types,omitempty"`
}

// ExportedTypesStructMeta 导出类型结构定义
// 描述导出到用户空间的数据结构类型
type ExportedTypesStructMeta struct {
	// Name 结构体名称
	Name string `json:"name"`

	// Members 结构体成员列表
	Members []ExportedTypesStructMemberMeta `json:"members"`

	// Size 结构体大小（字节）
	Size uint32 `json:"size"`

	// TypeID BTF 类型 ID
	Type btf.Type `json:"type"`
}

// ExportedTypesStructMemberMeta 导出类型结构成员定义
// 描述结构体中的成员字段
type ExportedTypesStructMemberMeta struct {
	// Name 成员名称
	Name string `json:"name"`

	// Type 成员类型
	Type string `json:"type"`

	// BTFType BTF 类型
	BTFType btf.Type `json:"btf_type"`
}

// BpfSkeletonMeta BPF 骨架元数据
// 描述 eBPF 对象的骨架结构
type BpfSkeletonMeta struct {
	// DataSections 描述 .rodata 和 .bss 段及其中的变量
	DataSections []DataSectionMeta `json:"data_sections"`

	// Maps 描述 eBPF 对象中使用的 map 声明
	Maps map[string]*MapMeta `json:"maps"`

	// Progs 描述 eBPF 对象中的程序（函数）
	Progs map[string]*ProgMeta `json:"progs"`

	// ObjName eBPF 对象名称
	ObjName string `json:"obj_name"`

	// Doc 文档信息，用于生成命令行解析器
	Doc *BpfSkelDoc `json:"doc,omitempty"`
}

// DataSectionMeta 数据段元数据
// 描述数据段及其中声明的变量
type DataSectionMeta struct {
	// Name 段名称
	Name string `json:"name"`

	// Variables 段中的变量列表
	Variables []DataSectionVariableMeta `json:"variables"`
}

// DataSectionVariableMeta 数据段变量元数据
// 描述数据段中的变量
type DataSectionVariableMeta struct {
	// Name 变量名称
	Name string `json:"name"`

	// Type 变量的 C 类型
	Type string `json:"type"`

	// Value 变量的默认值
	// 如果未提供且未通过命令行解析器填充，将使用零值
	Value *json.RawMessage `json:"value,omitempty"`

	// Description 变量描述，用于生成命令行参数说明
	Description string `json:"description,omitempty"`

	// CmdArg 命令行参数配置
	CmdArg VariableCommandArgument `json:"cmdarg"`

	// Others 其他字段
	Others map[string]interface{} `json:"others,omitempty"`
}

// VariableCommandArgument 变量命令行参数
// 描述变量的命令行参数配置
type VariableCommandArgument struct {
	// Default 参数默认值
	Default *json.RawMessage `json:"default,omitempty"`

	// Long 长参数名
	Long string `json:"long,omitempty"`

	// Short 短参数名（单个字符）
	Short string `json:"short,omitempty"`

	// Help 帮助信息
	Help string `json:"help,omitempty"`
}

// MapMeta Map 元数据
// 描述 eBPF map
type MapMeta struct {
	// Name map 名称
	Name string `json:"name"`

	// Ident map 标识符
	Ident string `json:"ident"`

	// Mmaped 该 map 的值是否用于描述数据段
	Mmaped bool `json:"mmaped"`

	// Sample map 采样配置
	Sample *MapSampleMeta `json:"sample,omitempty"`

	// ExportConfig map 导出配置
	ExportConfig MapExportConfig `json:"export_config"`

	// Interpreter 缓冲区值解释器配置
	Interpreter BufferValueInterpreter `json:"interpreter"`

	// Properties map 配置
	Properties *MapProperties `json:"properties,omitempty"`

	// ExportHandler 导出处理器
	ExportHandler EventHandler `json:"export_handler"`
}

// MapSampleMeta Map 采样元数据
// 用于 map 采样的额外配置
type MapSampleMeta struct {
	// Interval 采样间隔（毫秒）
	Interval uint `json:"interval"`

	// Type map 类型
	Type SampleMapType `json:"type"`

	// Unit 打印直方图时的单位
	Unit string `json:"unit"`

	// ClearMap 采样完成后是否清理 map
	ClearMap bool `json:"clear_map"`
}

// SampleMapType 采样 Map 类型
type SampleMapType string

const (
	// SampleMapTypeLog2Hist 以 log2 直方图形式打印事件数据
	SampleMapTypeLog2Hist SampleMapType = "log2_hist"

	// SampleMapTypeLinearHist 以线性直方图形式打印事件数据
	SampleMapTypeLinearHist SampleMapType = "linear_hist"

	// SampleMapTypeDefaultKV 以键值对形式打印事件数据
	SampleMapTypeDefaultKV SampleMapType = "default_kv"
)

// MapExportConfig Map 导出配置
type MapExportConfig string

const (
	// MapExportConfigNoExport 不导出
	MapExportConfigNoExport MapExportConfig = "no_export"

	// MapExportConfigExportUseBtf 使用 BTF 类型指定导出值
	MapExportConfigExportUseBtf MapExportConfig = "btf_type_id"

	// MapExportConfigExportUseCustom 使用自定义成员指定导出值
	MapExportConfigExportUseCustom MapExportConfig = "custom_members"

	// MapExportConfigDefault 使用 BTF 的默认配置
	MapExportConfigDefault MapExportConfig = "default"
)

// BufferValueInterpreter 缓冲区值解释器
// 指示如何解释用户空间程序轮询的缓冲区值
type BufferValueInterpreter struct {
	// Type 解释器类型：default_struct 或 stack_trace
	Type string `json:"type"`

	// StackTrace 堆栈跟踪配置
	// 仅当 Type 为 stack_trace 时使用
	StackTrace *StackTraceConfig `json:"stack_trace,omitempty"`
}

// StackTraceConfig 堆栈跟踪配置
// 配置堆栈跟踪数据的解释方式
type StackTraceConfig struct {
	// FieldMap 字段映射配置
	FieldMap StackTraceFieldMapping `json:"field_map"`

	// WithSymbols 是否包含符号信息
	WithSymbols bool `json:"with_symbols"`
}

// StackTraceFieldMapping 堆栈跟踪字段映射
// 指定输入结构中的哪些字段映射到相应的堆栈跟踪字段
type StackTraceFieldMapping struct {
	// PID 进程 ID 字段名
	PID string `json:"pid,omitempty"`

	// CPUID CPU ID 字段名
	CPUID string `json:"cpu_id,omitempty"`

	// Comm 进程名字段名
	Comm string `json:"comm,omitempty"`

	// KstackSz 内核栈大小字段名
	KstackSz string `json:"kstack_sz,omitempty"`

	// UstackSz 用户栈大小字段名
	UstackSz string `json:"ustack_sz,omitempty"`

	// Kstack 内核栈字段名
	Kstack string `json:"kstack,omitempty"`

	// Ustack 用户栈字段名
	Ustack string `json:"ustack,omitempty"`
}

// ProgMeta 程序元数据
// 描述 eBPF 程序
type ProgMeta struct {
	// Name 程序名称
	Name string `json:"name"`

	// Attach 程序附加点
	Attach string `json:"attach"`

	// Link 程序附加是否生成 bpf_link
	Link bool `json:"link"`

	// Properties 程序特定配置
	Properties *ProgramProperties `json:"properties,omitempty"`
}

// BpfSkelDoc BPF 骨架文档
// 用于生成命令行解析器的文档信息
type BpfSkelDoc struct {
	// Version 版本信息
	Version string `json:"version,omitempty"`

	// Brief 简短描述
	Brief string `json:"brief,omitempty"`

	// Details 详细信息
	Details string `json:"details,omitempty"`

	// Description 描述信息
	Description string `json:"description,omitempty"`
}

// OverridedStructMember 重写结构成员
// 描述重写结构中的成员
type OverridedStructMember struct {
	// Name 字段名称
	Name string `json:"name"`

	// Offset 字段偏移量（字节）
	Offset uint `json:"offset"`

	// BtfTypeID BTF 类型 ID
	BtfTypeID uint32 `json:"btf_type_id"`
}

// TCHook TC 钩子
// 流量控制钩子配置
type TCHook struct {
	// Ifindex 接口索引
	Ifindex int32 `json:"ifindex"`

	// AttachPoint 附加点类型
	AttachPoint TCAttachPoint `json:"attach_point"`
}

// TCAttachPoint TC 附加点类型
type TCAttachPoint string

const (
	// TCAttachPointIngress 入口流量
	TCAttachPointIngress TCAttachPoint = "BPF_TC_INGRESS"

	// TCAttachPointEgress 出口流量
	TCAttachPointEgress TCAttachPoint = "BPF_TC_EGRESS"

	// TCAttachPointCustom 自定义附加点
	TCAttachPointCustom TCAttachPoint = "BPF_TC_CUSTOM"
)

// TCOpts TC 选项
// 流量控制选项配置
type TCOpts struct {
	// Handle TC handle 值
	Handle uint32 `json:"handle"`

	// Priority TC 优先级
	Priority uint32 `json:"priority"`
}

// XDPOpts XDP 选项
// XDP 程序选项配置
type XDPOpts struct {
	// OldProgFD 旧程序的文件描述符
	OldProgFD int32 `json:"old_prog_fd"`
}

// RunnerConfig 运行时配置
// 控制 eunomia-bpf 的行为
type RunnerConfig struct {
	// PrintKernelDebug 是否从 /sys/kernel/debug/tracing/trace_pipe 打印 bpf_printk 输出
	PrintKernelDebug bool `json:"print_kernel_debug"`

	// ProgProperties 程序特定配置
	ProgProperties ProgramProperties `json:"prog_properties,omitempty"`
}

type TaskStatus int

const (
	TaskStatusPending TaskStatus = iota
	TaskStatusRunning
	TaskStatusSuccess
	TaskStatusFailed
)

// prog attach status
type ProgAttachStatus struct {
	ProgName      string        `json:"prog_name"`
	AttachID      uint32        `json:"attach_id"`
	Status        TaskStatus    `json:"status"`
	Error         string        `json:"error"`
	VerifierStats VerifierStats `json:"verifier_stats"`
}

// FindMapByIdent 通过标识符查找 Map
func (s *BpfSkeletonMeta) FindMapByIdent(ident string) *MapMeta {
	for _, m := range s.Maps {
		if m.Ident == ident {
			return m
		}
	}
	return nil
}

// DataType 定义数据类型枚举
type DataType int

const (
	TypeBuffer DataType = iota
	TypeKeyValueBuffer
	TypePlainText
	TypeJsonText
)

// ReceivedEventData 表示从 eBPF 程序接收到的数据
type ReceivedEventData struct {
	Type     DataType
	Buffer   []byte
	KeyBuf   []byte
	ValueBuf []byte
	Text     string
	JsonText string
}

// UserContext 用于存储用户上下文
type UserContext struct {
	Value interface{}
	mu    sync.RWMutex
}

// NewUserContext 创建新的用户上下文
func NewUserContext(value interface{}) *UserContext {
	return &UserContext{
		Value: value,
	}
}

// GetValue 获取上下文值
func (c *UserContext) GetValue() interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.Value
}

// SetValue 设置上下文值
func (c *UserContext) SetValue(value interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Value = value
}
