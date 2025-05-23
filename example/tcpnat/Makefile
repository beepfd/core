GO := go
GO_BUILD = CGO_ENABLED=1 $(GO) build
GO_GENERATE = $(GO) generate
GO_TAGS ?=
TARGET_GOARCH ?= amd64,arm64
GOARCH ?= amd64
BPF_ARCH = $(shell echo $(GOARCH) | sed 's/amd64/x86/' \
                                  | sed 's/arm64/arm64/' \
                                  | sed 's/ppc64le/powerpc/' \
                                  | sed 's/mips.*/mips/' \
                                  | sed 's/riscv64/riscv/' \
                                  | sed 's/loongarch64/loongarch/')
GOOS ?= linux
VERSION=$(shell git describe --tags --always)
# For compiling libpcap and CGO
CC ?= gcc
OUTPUT := .output
APPS = tcpnat example


elf:
	TARGET_GOARCH=$(TARGET_GOARCH) $(GO_GENERATE)
    	CC=$(CC) GOARCH=$(TARGET_GOARCH) $(GO_BUILD) $(if $(GO_TAGS),-tags $(GO_TAGS)) \
    		-ldflags "-w -s "

build: elf
	CGO_ENABLED=1 GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_LDFLAGS='-g -lcapstone -static'   go build -tags=netgo,osusergo -gcflags "all=-N -l" -v  -o tcpnat

dlv: build
	dlv --headless --listen=:2345 --api-version=2 exec ./tcpnat

run:  build
	./tcpnat

.PHONY: clean
clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(OUTPUT) $(APPS)
	$(Q)rm -rf min_core_btfs.tar.gz


# Build application binary
$(APPS): %: $(OUTPUT)/%-btf.tar.gz  | $(OUTPUT)
	cp $(word 1,$^) $(OUTPUT)/min_core_btfs.tar.gz
	$(call msg,CP,$(OUTPUT)/min_core_btfs.tar.gz,./min_core_btfs.tar.gz)
	cp $(OUTPUT)/min_core_btfs.tar.gz ./min_core_btfs.tar.gz
	CGO_ENABLED=1 GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_LDFLAGS='-g -lcapstone -static'   go build -tags=netgo,osusergo -gcflags "all=-N -l" -v  -o tcpnat

# Build BPF code
$(OUTPUT)/%.bpf.o: elf
	cp tcpnat_$(BPF_ARCH)_bpfel.o $(OUTPUT)/tcpnat.bpf.o

$(OUTPUT)/btfhub-cache:
	BTFHUB_REPO=https://github.com/beepfd/btfhub-archive \
	BTFHUB_CACHE=$(OUTPUT)/btfhub-cache \
	../../compatible/script/btfgen fetch

$(OUTPUT)/%-btf.tar.gz: $(OUTPUT)/%.bpf.o $(OUTPUT)/btfhub-cache 
	BTFHUB_CACHE=$(OUTPUT)/btfhub-cache \
	../../compatible/script/btfgen btfgen $< -o $@