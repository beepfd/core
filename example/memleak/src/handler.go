package src

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/cen-ngc5139/BeePF/loader/lib/src/meta"
	"go.uber.org/zap"
)

type SoftLockHandler struct {
	Logger *zap.Logger
}

// BPF程序中的soft_lockup_event结构体对应的Go结构
type SoftLockupEvent struct {
	CPU       uint32 `json:"cpu"`
	Timestamp uint64 `json:"timestamp"`
	Interval  uint64 `json:"interval"`
	PID       uint32 `json:"pid"`
	Comm      string `json:"comm"`
}

// 格式化间隔时间为可读格式
func (e *SoftLockupEvent) FormatInterval() string {
	duration := time.Duration(e.Interval)
	if duration >= time.Second {
		return fmt.Sprintf("%.3fs", duration.Seconds())
	} else if duration >= time.Millisecond {
		return fmt.Sprintf("%.3fms", float64(duration.Nanoseconds())/1e6)
	} else if duration >= time.Microsecond {
		return fmt.Sprintf("%.3fµs", float64(duration.Nanoseconds())/1e3)
	} else {
		return fmt.Sprintf("%dns", duration.Nanoseconds())
	}
}

// 判断是否为严重的软锁定事件
func (e *SoftLockupEvent) IsSevere() bool {
	return e.Interval > 5*1000*1000*1000 // 超过5秒认为是严重事件
}

// 实现 EventHandler 接口
func (h *SoftLockHandler) HandleEvent(ctx *meta.UserContext, data *meta.ReceivedEventData) error {
	switch data.Type {
	case meta.TypeJsonText:
		var event SoftLockupEvent
		err := json.Unmarshal([]byte(data.JsonText), &event)
		if err != nil {
			h.Logger.Error("解析软锁定事件JSON失败", zap.Error(err))
			return err
		}

		// 根据严重程度使用不同的日志级别
		if event.IsSevere() {
			h.Logger.Error("检测到严重软锁定事件",
				zap.Uint32("CPU", event.CPU),
				zap.String("间隔", event.FormatInterval()),
				zap.Uint32("进程ID", event.PID),
				zap.String("进程名", event.Comm),
				zap.Uint64("间隔纳秒", event.Interval))
		} else {
			h.Logger.Info("检测到软锁定事件",
				zap.Uint32("CPU", event.CPU),
				zap.String("间隔", event.FormatInterval()),
				zap.Uint32("进程ID", event.PID),
				zap.String("进程名", event.Comm),
				zap.Uint64("间隔纳秒", event.Interval))
		}

	case meta.TypePlainText:
		h.Logger.Info("接收到纯文本事件",
			zap.String("data", data.Text))
	}
	return nil
}

// 简单的跳过处理器，可用于测试
type SkipHandler struct {
}

func (h *SkipHandler) HandleEvent(ctx *meta.UserContext, data *meta.ReceivedEventData) error {
	return nil
}
