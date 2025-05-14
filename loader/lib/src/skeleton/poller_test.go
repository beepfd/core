package skeleton

import (
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/cen-ngc5139/BeePF/loader/lib/src/meta"
	"github.com/cen-ngc5139/BeePF/loader/lib/src/skeleton/export"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
	"go.uber.org/zap/zaptest"
)

func TestRingBufferPoller_Poll(t *testing.T) {
	type fields struct {
		BinaryPath, BtfArchivePath string
		reader                     *perf.Reader
		processor                  EventProcessor
		errorFlag                  *atomic.Bool
		timeout                    time.Duration
		Properties                 meta.Properties
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "normol",
			fields: fields{
				BinaryPath:     "../../../testdata/shepherd_x86_bpfel.o",
				BtfArchivePath: "../../../testdata/",
				Properties:     meta.Properties{},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkg, err := meta.GenerateComposedObject(tt.fields.BinaryPath, tt.fields.Properties)
			if err != nil {
				t.Errorf("GenerateComposedObject() error = %v", err)
				return
			}

			preLoadBpfSkeleton, err := FromJsonPackage(pkg, tt.fields.BtfArchivePath, zaptest.NewLogger(t)).Build()
			if err != nil {
				t.Errorf("Build() error = %v", err)
				return
			}

			skeleton, _, err := preLoadBpfSkeleton.LoadAndAttach()
			if (err != nil) != tt.wantErr {
				t.Errorf("LoadAndAttach() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			for _, m := range skeleton.Collection.Maps {
				if m.Type() != ebpf.RingBuf {
					continue
				}

				perfReader, err := ringbuf.NewReader(m)
				if err != nil {
					t.Errorf("fail to new perf event array map  reader, err = %v", err)
				}

				for _, v := range skeleton.Collection.Variables {

					ee := export.NewEventExporterBuilder().
						SetExportFormat(export.FormatJson).
						SetUserContext(meta.NewUserContext(0)).
						SetEventHandler(&export.MyCustomHandler{Logger: zaptest.NewLogger(t)})

					structType, err := FindStructType(v.Type())
					if err != nil {
						t.Fatalf("failed to find struct type: %v", err)
					}

					if structType.Name != "sched_latency_t" {
						continue
					}

					exporter, err := ee.BuildForSingleValueWithTypeDescriptor(
						&export.BTFTypeDescriptor{
							Type: structType,
							Name: structType.TypeName(),
						},
						skeleton.Btf,
					)
					if err != nil {
						t.Errorf("BuildForSingleValueWithTypeDescriptor() error = %v", err)
						return
					}

					jsonHandler := export.NewJsonExportEventHandler(exporter)

					p := &RingBufPoller{
						Reader:    perfReader,
						Processor: jsonHandler,
						Timeout:   tt.fields.timeout,
					}

					pp := NewProgramPoller(100 * time.Millisecond)
					pp.StartPolling("test", p.GetPollFunc(), func(err error) {
						t.Errorf("Poll() error = %v", err)
					})

					// 等待信号
					sigChan := make(chan os.Signal, 1)
					signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

					<-sigChan

					// 停止轮询
					pp.Stop()
				}

			}

		})
	}
}
