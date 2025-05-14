package skeleton

import (
	"testing"

	"github.com/cen-ngc5139/BeePF/loader/lib/src/container"
	"github.com/cen-ngc5139/BeePF/loader/lib/src/meta"
	"github.com/cilium/ebpf"
	"go.uber.org/zap/zaptest"
)

func TestPreLoadBpfSkeleton_LoadAndAttach(t *testing.T) {
	type fields struct {
		BinaryPath, BtfArchivePath string
		Meta                       *meta.EunomiaObjectMeta
		ConfigData                 *meta.RunnerConfig
		Btf                        *container.BTFContainer
		Spec                       *ebpf.CollectionSpec
		MapValueSizes              map[string]uint32
		RawElf                     *container.ElfContainer

		Properties meta.Properties
	}
	tests := []struct {
		name    string
		fields  fields
		want    *BpfSkeleton
		wantErr bool
	}{
		{
			name: "shepherd",
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

			got, _, err := preLoadBpfSkeleton.LoadAndAttach()
			if (err != nil) != tt.wantErr {
				t.Errorf("LoadAndAttach() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if len(got.Links) == 0 {
				t.Errorf("LoadAndAttach() got = %v, want %v", got, tt.want)
			}
		})
	}
}
