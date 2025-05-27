package meta

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// AttachProgram 根据程序类型选择合适的 attach 方式
func (p *ProgMeta) AttachProgram(spec *ebpf.ProgramSpec, program *ebpf.Program) (link link.Link, err error) {

	switch spec.Type {
	case ebpf.UnspecifiedProgram:
		err = fmt.Errorf("error:%v, %s", ErrSectionFormat, "invalid program type, make sure to use the right section prefix")
		return
	case ebpf.Kprobe:
		link, err = p.attachKprobe(program)
	case ebpf.TracePoint:
		link, err = p.attachTracepoint(program)
	case ebpf.CGroupDevice, ebpf.CGroupSKB, ebpf.CGroupSock, ebpf.SockOps, ebpf.CGroupSockAddr, ebpf.CGroupSockopt, ebpf.CGroupSysctl:
		link, err = p.attachCGroup(program, spec.AttachType, p.Properties.CGroupPath)
	case ebpf.SocketFilter:
		link, err = p.attachSocket()
	case ebpf.SkLookup:
		link, err = p.attachSkLookup(program)
	case ebpf.SchedCLS:
		link, err = p.attachTCCLS(program)
	case ebpf.XDP:
		link, err = p.attachXDP()
	case ebpf.RawTracepoint:
		link, err = p.attachRawTracepoint(program)
	case ebpf.Tracing:
		link, err = p.attachTracing(program)
	case ebpf.LSM:
		link, err = p.attachLsm()
	default:
		err = fmt.Errorf("program type %s not implemented yet", spec.Type)
	}

	if err != nil {
		return nil, err
	}

	// 如果设置了 PinPath，则将程序固定到文件系统
	if p.Properties.PinPath != "" {
		err = p.PinProgram(program)
		if err != nil {
			return nil, err
		}
	}

	return link, nil
}

func (p *ProgMeta) attachTracing(program *ebpf.Program) (link.Link, error) {
	tracing, err := link.AttachTracing(link.TracingOptions{Program: program})
	if err != nil {
		return nil, fmt.Errorf("error:%v, couldn's activate tracing %s, matchFuncName:%s", err, p.Attach, p.Name)
	}
	return tracing, nil
}

func (p *ProgMeta) attachKprobe(program *ebpf.Program) (link.Link, error) {
	// Prepare kprobe_events line parameters
	var err error
	attachPoint := strings.SplitN(p.Attach, "/", 2)
	if len(attachPoint) != 2 {
		return nil, fmt.Errorf("invalid attach point: %s", p.Attach)
	}
	funcName := attachPoint[1]

	isRet := false
	if strings.HasPrefix(p.Attach, "kretprobe/") {
		isRet = true
	} else if strings.HasPrefix(p.Attach, "kprobe/") {
		isRet = false
	} else {
		// this might actually be a Uprobe
		return p.attachUprobe(program)
	}

	var kp link.Link
	if isRet {
		kp, err = link.Kretprobe(funcName, program, nil)
	} else {
		kp, err = link.Kprobe(funcName, program, nil)
	}

	if err != nil {
		return nil, fmt.Errorf("opening Kprobe: %s, funcName:%s, isRet:%t, section:%s", err, funcName, isRet, p.Attach)
	}

	return kp, nil
}

func (p *ProgMeta) attachUprobe(program *ebpf.Program) (link.Link, error) {
	// 解析附加点信息，格式应该是 "uprobe/path:symbol" 或 "uretprobe/path:symbol"
	attachPoint := strings.SplitN(p.Attach, "/", 2)
	if len(attachPoint) != 2 {
		return nil, fmt.Errorf("invalid uprobe attach point: %s, expected format uprobe/path:symbol", p.Attach)
	}

	// 确定是 uprobe 还是 uretprobe
	isRet := false
	if strings.HasPrefix(p.Attach, "uretprobe/") {
		isRet = true
	} else if !strings.HasPrefix(p.Attach, "uprobe/") {
		return nil, fmt.Errorf("invalid uprobe prefix: %s, expected uprobe/ or uretprobe/", p.Attach)
	}

	ex, err := link.OpenExecutable(p.Properties.Uprobe.BinPath)
	if err != nil {
		return nil, fmt.Errorf("error:%v , couldn't enable uprobe %s", err, p.Properties.Uprobe.BinPath)
	}
	opts := &link.UprobeOptions{
		Offset:  p.Properties.Uprobe.Offset,
		Address: p.Properties.Uprobe.Address,
		PID:     p.Properties.Uprobe.PID,
	}

	// 创建 uprobe 或 uretprobe
	var up link.Link
	if isRet {
		up, err = ex.Uretprobe(p.Properties.Uprobe.Symbol, program, opts)
		if err != nil {
			return nil, fmt.Errorf("opening Uretprobe failed: %v, binary:%s, symbol:%s",
				err, p.Properties.Uprobe.BinPath, p.Properties.Uprobe.Symbol)
		}
	} else {
		up, err = ex.Uprobe(p.Properties.Uprobe.Symbol, program, opts)
		if err != nil {
			return nil, fmt.Errorf("opening Uprobe failed: %v, binary:%s, symbol:%s",
				err, p.Properties.Uprobe.BinPath, p.Properties.Uprobe.Symbol)
		}
	}

	return up, nil
}

func (p *ProgMeta) attachTracepoint(program *ebpf.Program) (link.Link, error) {
	// Parse section
	traceGroup := strings.SplitN(p.Attach, "/", 3)
	if len(traceGroup) != 3 {
		return nil, fmt.Errorf("error:%v, expected SEC(\"tracepoint/[category]/[name]\") got %s", ErrSectionFormat, p.Attach)
	}
	category := traceGroup[1]
	name := traceGroup[2]

	kp, err := link.Tracepoint(category, name, program, nil)
	if err != nil {
		return nil, fmt.Errorf("error:%v , couldn's activate tracepoint %s, matchFuncName:%s", err, p.Attach, p.Name)
	}

	return kp, nil
}

func (p *ProgMeta) attachCGroup(program *ebpf.Program, typ ebpf.AttachType, cgroupPath string) (link.Link, error) {
	if cgroupPath == "" {
		return nil, fmt.Errorf("prog %s invalid cgroupPath", p.Name)
	}

	opts := link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  typ,
		Program: program,
	}
	kp, err := link.AttachCgroup(opts)
	if err != nil {
		return nil, fmt.Errorf("error:%v ,failed to attach program %s to cgroup %s, attach type:%s", err, p.Name, p.Attach, typ.String())
	}

	return kp, nil
}

func (p *ProgMeta) attachSocket() (link.Link, error) {
	// todo: 需要实现
	return nil, nil
}

func (p *ProgMeta) attachTCCLS(program *ebpf.Program) (link.Link, error) {
	if p.Properties.Tc == nil {
		return nil, fmt.Errorf("prog %s invalid tc properties", p.Name)
	}

	if p.Properties.Tc.Ifindex == 0 && p.Properties.Tc.Ifname == "" {
		return nil, fmt.Errorf("prog %s invalid tc properties", p.Name)
	}

	ntl, err := net.InterfaceByName(p.Properties.Tc.Ifname)
	if err != nil {
		return nil, fmt.Errorf("prog %s invalid tc properties", p.Name)
	}

	// Attach the program to Ingress TC.
	link, err := link.AttachTCX(link.TCXOptions{
		Interface: ntl.Index,
		Program:   program,
		Attach:    p.Properties.Tc.AttachType,
	})
	if err != nil {
		return nil, fmt.Errorf("error:%v , couldn's activate tc ingress %s, matchFuncName:%s", err, p.Attach, p.Name)
	}

	return link, nil
}

func (p *ProgMeta) attachXDP() (link.Link, error) {
	// todo: 需要实现
	return nil, nil
}

func (p *ProgMeta) attachRawTracepoint(program *ebpf.Program) (link.Link, error) {
	name := strings.TrimLeft(p.Attach, "raw_tracepoint/")
	link, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    name,
		Program: program,
	})
	if err != nil {
		return nil, fmt.Errorf("error:%v , couldn's activate raw_tracepoint %s, matchFuncName:%s", err, p.Attach, p.Name)
	}

	return link, nil
}

func (p *ProgMeta) attachLsm() (link.Link, error) {
	return nil, nil
}

// PinProgram 将程序固定到文件系统
func (p *ProgMeta) PinProgram(program *ebpf.Program) error {
	if p.Properties == nil || p.Properties.PinPath == "" {
		return nil
	}

	pinPath := p.Properties.PinPath

	// 确保目录存在
	if err := os.MkdirAll(filepath.Dir(pinPath), 0755); err != nil {
		return fmt.Errorf("create pin directory error: %w", err)
	}

	// 检查是否已存在 pinned program
	existingProg, err := ebpf.LoadPinnedProgram(pinPath, nil)
	if err == nil {
		defer existingProg.Close() // 只关闭我们加载的引用，不影响已 pin 的程序

		// 获取现有程序和新程序的信息
		existingInfo, err := existingProg.Info()
		if err != nil {
			return fmt.Errorf("get existing program info error: %w", err)
		}

		progInfo, err := program.Info()
		if err != nil {
			return fmt.Errorf("get program info error: %w", err)
		}

		// 检查程序类型和名称是否匹配
		if existingInfo.Type != progInfo.Type || existingInfo.Name != progInfo.Name {
			return fmt.Errorf("pin path %s already exists with different program (existing: type=%s, name=%s; new: type=%s, name=%s)",
				pinPath,
				existingInfo.Type,
				existingInfo.Name,
				progInfo.Type,
				progInfo.Name)
		}

		// 类型和名称匹配，直接返回
		if err := os.Remove(pinPath); err != nil {
			return fmt.Errorf("remove mismatched pinned program error: %w", err)
		}
		return nil
	}

	// Pin 新程序
	if err := program.Pin(pinPath); err != nil {
		return fmt.Errorf("pin program %s error: %w", p.Name, err)
	}

	return nil
}

func (p *ProgMeta) attachSkLookup(program *ebpf.Program) (link.Link, error) {
	netns, err := os.Open("/proc/self/ns/net")
	if err != nil {
		return nil, fmt.Errorf("error:%v , couldn't open netns", err)
	}
	defer netns.Close()

	link, err := link.AttachNetNs(int(netns.Fd()), program)
	if err != nil {
		return nil, fmt.Errorf("error:%v , couldn's activate sk_lookup %s, matchFuncName:%s", err, p.Attach, p.Name)
	}

	return link, nil
}
