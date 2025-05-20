package skeleton

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"go.uber.org/zap"
)

func (b *BpfSkeletonBuilder) FindBTFFromTar(btfBytes []byte) (string, error) {
	tmpDir := "./tmp"

	// 解压 BTF 文件
	if err := b.UnpackBTF(btfBytes, tmpDir); err != nil {
		return "", fmt.Errorf("unpack btf: %w", err)
	}

	// 查找对应的 BTF 文件
	btfFile, err := b.findBTFFileFromTar(tmpDir)
	if err != nil {
		return "", fmt.Errorf("find btf file: %w", err)
	}

	return btfFile, nil
}

func (b *BpfSkeletonBuilder) UnpackBTF(btfBytes []byte, tmpDir string) error {
	if err := os.MkdirAll(tmpDir, 0755); err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}

	// 创建 gzip reader
	r, err := gzip.NewReader(bytes.NewReader(btfBytes))
	if err != nil {
		return fmt.Errorf("create gzip reader: %w", err)
	}
	defer r.Close()

	tr := tar.NewReader(r)

	// 遍历并解压文件
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read tar header: %w", err)
		}

		// 构建目标文件路径
		target := filepath.Join(tmpDir, header.Name)

		// 确保父目录存在
		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			return fmt.Errorf("create directory %s: %w", filepath.Dir(target), err)
		}

		// 根据文件类型处理
		switch header.Typeflag {
		case tar.TypeDir:
			// 创建目录
			if err := os.MkdirAll(target, 0755); err != nil {
				return fmt.Errorf("create directory %s: %w", target, err)
			}
		case tar.TypeReg:
			// 创建文件
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(header.Mode))
			if err != nil {
				return fmt.Errorf("create file %s: %w", target, err)
			}
			// 复制文件内容
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return fmt.Errorf("write file %s: %w", target, err)
			}
			f.Close()
		}

		b.logger.Info("Extracted: %s", zap.String("target", target))
	}

	return nil
}

func (b *BpfSkeletonBuilder) findBTFFileFromTar(tmpDir string) (string, error) {
	// 获取系统信息
	var uname syscall.Utsname
	if err := syscall.Uname(&uname); err != nil {
		return "", fmt.Errorf("get uname: %w", err)
	}

	// 转换 uname 信息为字符串
	machine := charsToString(uname.Machine[:])
	release := charsToString(uname.Release[:])

	// 读取 os-release 文件
	osRelease, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return "", fmt.Errorf("read os-release: %w", err)
	}

	// 解析 os-release
	var osID, osVersion string
	for _, line := range strings.Split(string(osRelease), "\n") {
		if strings.HasPrefix(line, "ID=") {
			osID = strings.Trim(strings.TrimPrefix(line, "ID="), "\"")
		} else if strings.HasPrefix(line, "VERSION_ID=") {
			osVersion = strings.Trim(strings.TrimPrefix(line, "VERSION_ID="), "\"")
		}
	}

	// 构建预期的 BTF 文件路径
	btfPath := filepath.Join(tmpDir, "btfhub-archive", osID, osVersion, machine, release+".btf")
	b.logger.Info("Start to find btf file", zap.String("btfPath", btfPath))

	// 检查文件是否存在
	if _, err := os.Stat(btfPath); err != nil {
		return "", fmt.Errorf("No btf file found for %s/%s/%s/%s", osID, osVersion, machine, release)
	}

	b.logger.Info("Found BTF file", zap.String("btfPath", btfPath))
	return btfPath, nil
}

func charsToString(ca []int8) string {
	s := make([]byte, 0, len(ca))
	for i := 0; i < len(ca); i++ {
		if ca[i] == 0 {
			break
		}
		s = append(s, byte(ca[i]))
	}
	return string(s)
}
