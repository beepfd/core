package loader

import (
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cen-ngc5139/BeePF/loader/lib/src/container"
	"github.com/cen-ngc5139/BeePF/loader/lib/src/meta"
	"github.com/cen-ngc5139/BeePF/loader/lib/src/metrics"
	"github.com/cen-ngc5139/BeePF/loader/lib/src/skeleton"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"go.uber.org/zap"
)

// Loader 定义加载器接口
type Loader interface {
	Init() error
	Load() error
	Start() error
	Stop() error
	Stats() error
	Metrics() error
}

// BPFLoader 实现 eBPF 程序加载器
type BPFLoader struct {
	Logger           *zap.Logger
	Config           *Config
	Collection       *ebpf.Collection
	Skeleton         *skeleton.BpfSkeleton
	PreLoadSkeleton  *skeleton.PreLoadBpfSkeleton
	Pollers          []*skeleton.ProgramPoller
	MapHandlers      []MapHandler
	BTFContainer     *container.BTFContainer
	Links            []link.Link
	done             chan struct{}
	StatsCollector   metrics.Collector
	ProgAttachStatus map[string]meta.ProgAttachStatus
}

// Config 配置结构
type Config struct {
	ObjectPath  string
	ObjectBytes []byte
	BTFPath     string
	Logger      *zap.Logger
	PollTimeout time.Duration
	Properties  meta.Properties
}

func NewBPFLoader(cfg *Config) *BPFLoader {
	if err := ValidateAndMutateConfig(cfg); err != nil {
		cfg.Logger.Error("failed to validate and mutate config", zap.Error(err))
		os.Exit(1)
	}

	loader := &BPFLoader{
		Logger:      cfg.Logger,
		Config:      cfg,
		MapHandlers: make([]MapHandler, 0),
	}

	if cfg.Properties.Stats != nil {
		stats := cfg.Properties.Stats
		collector, err := metrics.NewStatsCollector(stats.Interval, stats.Handler, cfg.Logger)
		if err != nil {
			cfg.Logger.Error("failed to create stats collector", zap.Error(err))
		}
		loader.StatsCollector = collector
	}

	// 注册默认的 map 处理器
	loader.RegisterMapHandler(&PerfEventMapHandler{
		BaseMapHandler: BaseMapHandler{
			Logger: cfg.Logger,
			Config: cfg,
		},
	})

	loader.RegisterMapHandler(&RingBufMapHandler{
		BaseMapHandler: BaseMapHandler{
			Logger: cfg.Logger,
			Config: cfg,
		},
	})

	loader.RegisterMapHandler(&SampleMapHandler{
		BaseMapHandler: BaseMapHandler{
			Logger: cfg.Logger,
			Config: cfg,
		},
	})

	return loader
}

// Init 初始化阶段
func (l *BPFLoader) Init() (err error) {
	l.Logger.Info("initializing BPF loader...")

	var pkg *meta.ComposedObject
	if l.Config.ObjectBytes != nil {
		pkg, err = meta.GenerateComposedObjectWithBytes(l.Config.ObjectBytes, l.Config.Properties)
		if err != nil {
			return fmt.Errorf("generate composed object failed: %w", err)
		}
	} else {
		pkg, err = meta.GenerateComposedObject(l.Config.ObjectPath, l.Config.Properties)
		if err != nil {
			return fmt.Errorf("generate composed object failed: %w", err)
		}
	}

	// 构建预加载骨架
	preLoadSkeleton, err := skeleton.FromJsonPackage(pkg, l.Config.BTFPath, l.Logger).Build()
	if err != nil {
		return fmt.Errorf("build preload skeleton failed: %w", err)
	}

	l.PreLoadSkeleton = preLoadSkeleton
	return nil
}

// Load 加载阶段
func (l *BPFLoader) Load() error {
	l.Logger.Info("loading BPF programs...")

	// 加载并附加 eBPF 程序
	skel, attachStatus, err := l.PreLoadSkeleton.LoadAndAttach()
	if err != nil {
		return fmt.Errorf("load and attach BPF programs failed: %w", err)
	}

	l.Collection = skel.Collection
	l.BTFContainer = skel.Btf
	l.Links = skel.Links
	l.ProgAttachStatus = attachStatus
	for _, handler := range l.MapHandlers {
		handler.SetCollection(l.Collection)
		handler.SetBTFContainer(l.BTFContainer)
	}
	return nil
}

// RegisterMapHandler 注册 Map 处理器
func (l *BPFLoader) RegisterMapHandler(handler MapHandler) {
	l.MapHandlers = append(l.MapHandlers, handler)
}

// GetMapHandlerByType 根据 map 类型返回对应的 MapHandler
func (l *BPFLoader) GetMapHandlerByType(mapType ebpf.MapType) MapHandler {
	// 根据特定类型返回对应的处理器
	switch mapType {
	case ebpf.PerfEventArray:
		for _, handler := range l.MapHandlers {
			if _, ok := handler.(*PerfEventMapHandler); ok {
				handler.SetExportTypes(l.PreLoadSkeleton.Meta.ExportTypes)
				return handler
			}
		}
	case ebpf.RingBuf:
		for _, handler := range l.MapHandlers {
			if _, ok := handler.(*RingBufMapHandler); ok {
				handler.SetExportTypes(l.PreLoadSkeleton.Meta.ExportTypes)
				return handler
			}
		}
	default:
		// 对于其他类型，查找 SampleMapHandler
		for _, handler := range l.MapHandlers {
			if _, ok := handler.(*SampleMapHandler); ok {
				handler.SetExportTypes(l.PreLoadSkeleton.Meta.ExportTypes)
				return handler
			}
		}
	}

	// 如果没有任何处理器，返回 nil
	return nil
}

func (l *BPFLoader) GetMapSpecByType(name string) *ebpf.MapSpec {
	mapSpec, ok := l.PreLoadSkeleton.Spec.Maps[name]
	if !ok {
		return nil
	}
	return mapSpec
}

func (l *BPFLoader) GetMapCollectionByType(name string) *ebpf.Map {
	mapSpec, ok := l.Collection.Maps[name]
	if !ok {
		return nil
	}
	return mapSpec
}

// isSkipMap 判断是否需要跳过某些特殊的 map
func isSkipMap(name string) bool {
	// 需要跳过的特殊 map 名称列表
	skipMaps := []string{
		".bss",
		".rodata",
		".data",
		".kconfig",
		"license",
		".maps",
		".BTF",
	}

	for _, skipName := range skipMaps {
		if strings.Contains(name, skipName) {
			return true
		}
	}

	return false
}

// Start 启动阶段
func (l *BPFLoader) Start() error {
	l.Logger.Info("starting BPF programs...")

	for mapName, mapMeta := range l.PreLoadSkeleton.Meta.BpfSkel.Maps {
		m := l.GetMapCollectionByType(mapName)
		if m == nil {
			l.Logger.Error("map spec not found", zap.String("map name", mapName))
			continue
		}

		info, err := m.Info()
		if err != nil {
			l.Logger.Error("failed to get map info", zap.String("map name", m.String()), zap.Error(err))
			continue
		}

		if isSkipMap(info.Name) {
			l.Logger.Info("skip map", zap.String("map name", m.String()))
			continue
		}

		// 查找对应的处理器
		handler := l.GetMapHandlerByType(m.Type())
		if handler == nil {
			l.Logger.Error("map handler not found", zap.String("map name", m.String()))
			continue
		}

		spec := l.GetMapSpecByType(info.Name)
		if spec == nil {
			l.Logger.Error("map spec not found", zap.String("map name", m.String()))
			continue
		}

		handler.SetEventHandler(mapMeta.ExportHandler)

		poller, err := handler.Setup(spec, m)
		if err != nil {
			return fmt.Errorf("setup map handler failed: %w", err)
		}
		if poller != nil {
			l.Pollers = append(l.Pollers, poller)
		}
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// 创建 done channel
	l.done = make(chan struct{})

	go func() {
		sig := <-sigChan
		l.Logger.Info("received signal", zap.String("signal", sig.String()))

		if err := l.Stop(); err != nil {
			l.Logger.Error("stop failed", zap.Error(err))
		}

		// 通知主程序可以退出
		close(l.done)

		// 停止接收更多信号
		signal.Stop(sigChan)
	}()

	return nil
}

// Stop 停止阶段
func (l *BPFLoader) Stop() error {
	l.Logger.Info("starting cleanup process...")

	l.Logger.Info("stopping stats collector")
	if l.StatsCollector != nil {
		err := l.StatsCollector.Stop()
		if err != nil {
			l.Logger.Error("failed to stop stats collector", zap.Error(err))
		}
	}

	// 1. 先停止所有 poller，因为它们在使用 maps
	l.Logger.Info("stopping pollers")
	for _, p := range l.Pollers {
		p.Stop()
	}

	// 2. 关闭所有 map handlers，它们持有 map readers
	l.Logger.Info("closing map handlers")
	for _, handler := range l.MapHandlers {
		handler.Close()
	}

	// 3. 关闭所有 links，因为它们引用了 programs
	l.Logger.Info("closing links")
	for _, link := range l.Links {
		if err := link.Unpin(); err != nil {
			l.Logger.Error("failed to unpin link", zap.Error(err))
		}

		if err := link.Close(); err != nil {
			l.Logger.Error("failed to close link", zap.Error(err))
		}
	}

	// 4. 最后关闭 collection，它会关闭所有 maps 和 programs
	l.Logger.Info("closing collection")
	if l.Collection != nil {
		l.Collection.Close()
	}

	if l.Config.Logger != nil {
		l.Config.Logger.Info("closing logger")
		l.Config.Logger.Sync()
	}

	// 5. 清空所有引用
	l.Pollers = nil
	l.MapHandlers = nil
	l.Links = nil
	l.Collection = nil

	return nil
}

func (l *BPFLoader) Stats() error {
	l.Logger.Info("collecting stats")

	if l.StatsCollector == nil {
		l.Logger.Info("stats collector is not enabled")
		return nil
	}

	attachedPros := make(map[uint32]*ebpf.Program)
	for _, prog := range l.Collection.Programs {
		info, err := prog.Info()
		if err != nil {
			return fmt.Errorf("failed to get program info: %w", err)
		}

		id, ok := info.ID()
		if !ok {
			return fmt.Errorf("failed to get program id: %w", err)
		}
		attachedPros[uint32(id)] = prog
	}

	if err := l.StatsCollector.SetAttachedPros(attachedPros); err != nil {
		return err
	}

	return l.StatsCollector.Start()
}

func (l *BPFLoader) Metrics() error {
	if l.StatsCollector == nil {
		l.Logger.Info("stats collector is not enabled")
		return nil
	}

	return l.StatsCollector.Export()
}

// handlePollingError 处理轮询错误
func (h *BaseMapHandler) handlePollingError(err error) {
	h.Logger.Error("polling error", zap.Error(err))
}

// Done 返回完成信号通道
func (l *BPFLoader) Done() <-chan struct{} {
	return l.done
}
