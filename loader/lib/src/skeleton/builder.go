package skeleton

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	btfutils "github.com/cen-ngc5139/BeePF/loader/lib/src/btf"
	"github.com/cilium/ebpf/btf"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	"github.com/cen-ngc5139/BeePF/loader/lib/src/container"
	"github.com/cen-ngc5139/BeePF/loader/lib/src/meta"
	"github.com/cilium/ebpf"
)

// BpfSkeletonBuilder eBPF 骨架构建器
type BpfSkeletonBuilder struct {
	// btfArchivePath 内核 BTF 文件存档路径
	btfArchivePath string

	// objectMeta 对象元数据
	objectMeta *meta.EunomiaObjectMeta

	// bpfObject eBPF 对象的二进制数据
	bpfObject []byte

	// runnerConfig 运行时配置
	runnerConfig *meta.RunnerConfig

	// logger 日志记录器
	logger *zap.Logger
}

// NewBpfSkeletonBuilder 从对象元数据和对象缓冲区创建构建器
// btfArchivePath - 内核 BTF 文件存档的根路径，如果不提供，将尝试使用环境变量 BTF_FILE_PATH 和 /sys/kernel/btf/vmlinux
func NewBpfSkeletonBuilder(meta *meta.EunomiaObjectMeta, bpfObject []byte, btfArchivePath string, logger *zap.Logger) *BpfSkeletonBuilder {
	return &BpfSkeletonBuilder{
		btfArchivePath: btfArchivePath,
		objectMeta:     meta,
		bpfObject:      bpfObject,
		logger:         logger,
	}
}

// FromJsonPackage 从 JSON 包创建构建器
func FromJsonPackage(pkg *meta.ComposedObject, btfArchivePath string, logger *zap.Logger) *BpfSkeletonBuilder {
	return NewBpfSkeletonBuilder(&pkg.Meta, pkg.BpfObject, btfArchivePath, logger)
}

// SetRunnerConfig 设置运行时配置
func (b *BpfSkeletonBuilder) SetRunnerConfig(cfg *meta.RunnerConfig) *BpfSkeletonBuilder {
	b.runnerConfig = cfg
	return b
}

// Build 构建并打开骨架
func (b *BpfSkeletonBuilder) Build() (*PreLoadBpfSkeleton, error) {
	// 加载 BTF
	vmlinux, err := b.loadBTF()
	if err != nil {
		return nil, fmt.Errorf("load BTF error: %w", err)
	}

	if vmlinux == nil {
		return nil, errors.New("fail to get kernel vmlinux")
	}

	// 创建 BTF 容器
	btf, err := container.NewBTFContainerFromBinary(b.bpfObject)
	if err != nil {
		return nil, fmt.Errorf("create BTF container error: %w", err)
	}

	// 创建 CollectionSpec
	spec, err := b.createCollectionSpec()
	if err != nil {
		return nil, fmt.Errorf("create collection spec error: %w", err)
	}

	// 创建 ELF 容器
	rawElf, err := container.NewElfContainerFromBinary(b.bpfObject)
	if err != nil {
		return nil, fmt.Errorf("create ELF container error: %w", err)
	}

	// 获取 map 值大小
	mapValueSizes, err := b.getMapValueSizes(spec)
	if err != nil {
		return nil, fmt.Errorf("get map value sizes error: %w", err)
	}

	return &PreLoadBpfSkeleton{
		Meta:          b.objectMeta,
		ConfigData:    b.runnerConfig,
		Btf:           btf,
		Spec:          spec,
		MapValueSizes: mapValueSizes,
		RawElf:        rawElf,
	}, nil
}

// createCollectionSpec 创建 CollectionSpec
func (b *BpfSkeletonBuilder) createCollectionSpec() (*ebpf.CollectionSpec, error) {
	// 从对象文件创建 CollectionSpec
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(b.bpfObject))
	if err != nil {
		return nil, fmt.Errorf("load collection spec error: %w", err)
	}

	return spec, nil
}

// loadBTF 加载 BTF 信息
func (b *BpfSkeletonBuilder) loadBTF() (*btf.Spec, error) {
	// 尝试从不同位置加载 BTF 文件
	btfPath, err := b.findBTFFile()
	if err != nil {
		return nil, err
	}

	// 创建 BTF 容器
	return btfutils.LoadSystemBTF(btfPath)
}

// findBTFFile 查找 BTF 文件
func (b *BpfSkeletonBuilder) findBTFFile() (string, error) {
	// 1. 检查自定义路径
	if b.btfArchivePath != "" {
		path := filepath.Join(b.btfArchivePath, "vmlinux")
		if fileExists(path) {
			b.logger.Info("found BTF file in custom path", zap.String("path", path))
			return path, nil
		}
	}

	// 2. 检查环境变量
	if envPath := os.Getenv(BTF_PATH_ENV_NAME); envPath != "" {
		if fileExists(envPath) {
			b.logger.Info("found BTF file in environment variable", zap.String("path", envPath))
			return envPath, nil
		}
	}

	// 3. 检查默认系统路径
	if fileExists(VMLINUX_BTF_PATH) {
		b.logger.Info("found BTF file in default system path", zap.String("path", VMLINUX_BTF_PATH))
		return VMLINUX_BTF_PATH, nil
	}

	return "", fmt.Errorf("BTF file not found. Tried: custom path, %s, and %s",
		BTF_PATH_ENV_NAME, VMLINUX_BTF_PATH)
}

// getMapValueSizes 获取所有 map 的值大小
func (b *BpfSkeletonBuilder) getMapValueSizes(spec *ebpf.CollectionSpec) (map[string]uint32, error) {
	sizes := make(map[string]uint32)

	for name, mapSpec := range spec.Maps {
		sizes[name] = mapSpec.ValueSize
	}

	return sizes, nil
}

// 常量定义
const (
	BTF_PATH_ENV_NAME = "BTF_FILE_PATH"
	VMLINUX_BTF_PATH  = "/sys/kernel/btf/vmlinux"
)

// 辅助函数

// fileExists 检查文件是否存在且可读
func fileExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !info.IsDir() && info.Mode().Perm()&0400 != 0
}
