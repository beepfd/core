package skeleton

import (
	"os"
	"reflect"
	"testing"

	"github.com/cen-ngc5139/BeePF/loader/lib/src/meta"
	"go.uber.org/zap"
)

func TestBpfSkeletonBuilder_Build(t *testing.T) {
	type fields struct {
		btfArchivePath string
		objectMeta     *meta.EunomiaObjectMeta
		objectFile     string
		bpfObject      []byte
		runnerConfig   *meta.RunnerConfig
	}
	tests := []struct {
		name    string
		fields  fields
		want    *PreLoadBpfSkeleton
		wantErr bool
	}{
		{
			name: "shepherd",
			fields: fields{
				btfArchivePath: "../../../testdata/",
				objectFile:     "../../../testdata/shepherd_x86_bpfel.o",
				objectMeta:     nil,
				bpfObject:      nil,
				runnerConfig:   nil,
			},
			want:    nil,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			objectFile, err := os.ReadFile(tt.fields.objectFile)
			if err != nil {
				t.Errorf("ReadFile() error = %v", err)
				return
			}

			b := &BpfSkeletonBuilder{
				btfArchivePath: tt.fields.btfArchivePath,
				objectMeta:     tt.fields.objectMeta,
				bpfObject:      objectFile,
				runnerConfig:   tt.fields.runnerConfig,
			}
			got, err := b.Build()
			if (err != nil) != tt.wantErr {
				t.Errorf("Build() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Build() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFromJsonPackage(t *testing.T) {

	pkg, err := meta.GenerateComposedObject("../../../testdata/shepherd_x86_bpfel.o", meta.Properties{})
	if err != nil {
		t.Errorf("GenerateComposedObject() error = %v", err)
		return
	}

	type args struct {
		pkg            *meta.ComposedObject
		btfArchivePath string
		logger         *zap.Logger
	}
	tests := []struct {
		name string
		args args
		want *BpfSkeletonBuilder
	}{
		{
			name: "shepherd",
			args: args{
				pkg:            pkg,
				btfArchivePath: "../../../testdata/",
				logger:         zap.NewExample(),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FromJsonPackage(tt.args.pkg, tt.args.btfArchivePath, tt.args.logger)

			preLoadBpfSkeleton, err := got.Build()
			if err != nil {
				t.Errorf("Build() error = %v", err)
				return
			}

			if preLoadBpfSkeleton == nil {
				t.Errorf("Build() got = %v, want %v", preLoadBpfSkeleton, tt.want)
			}

		})
	}
}
