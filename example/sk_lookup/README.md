# sk_lookup BPF 程序 POC

## 概述

这个 POC 演示了如何使用 BPF `sk_lookup` 程序来拦截和重定向 TCP 连接。当客户端尝试连接到特定的 IP:端口时，BPF 程序会将连接重定向到预先配置的目标 socket。

## 工作原理

### sk_lookup Hook 点
- **触发时机**: 当内核为新的 TCP 连接查找目标 socket 时
- **作用**: 可以重写连接的目标，实现透明的连接重定向
- **应用场景**: 负载均衡、服务发现、流量劫持等

### 重定向流程
1. 客户端发起连接到 `127.0.0.1:10000`
2. 内核触发 `sk_lookup` BPF 程序
3. BPF 程序检查连接参数（IP、端口、协议族）
4. 如果匹配条件，从 `SOCKMAP` 中查找目标 socket
5. 使用 `bpf_sk_assign()` 将连接重定向到目标 socket
6. 客户端的连接被透明地重定向到实际的服务端口

## 代码结构

### BPF 程序 (`bpf/sk_lookup.c`)
- **过滤条件**: 只处理发往 `127.0.0.1:10000` 的 IPv4 TCP 连接
- **重定向逻辑**: 将匹配的连接重定向到 `redir_map[0]` 中存储的 socket
- **调试输出**: 使用 `bpf_printk` 输出调试信息

### 用户态程序 (`main.go`)
- **BPF 程序加载**: 加载并附加 sk_lookup 程序
- **SOCKMAP 初始化**: 创建监听 socket 并存储到 BPF map
- **连接处理**: 实现简单的 echo 服务器来验证重定向

## 使用方法

### 1. 构建程序
```bash
cd example/sk_lookup
make build
```

### 2. 启动 POC 程序（需要 root 权限）
```bash
sudo ./sk_lookup
```

程序启动后会：
- 加载 sk_lookup BPF 程序到内核
- 创建监听 socket 在端口 10001
- 将监听 socket 的文件描述符存储到 SOCKMAP
- 开始处理重定向的连接

### 3. 测试重定向功能

在另一个终端运行测试命令：

#### 测试 1: 直接连接（对比测试）
```bash
# 连接到实际的服务端口 - 应该成功
telnet 127.0.0.1 10001
```

#### 测试 2: 重定向连接（主要测试）
```bash
# 连接到虚拟端口 - 会被重定向到 10001
telnet 127.0.0.1 10000
```

#### 测试 3: 非匹配连接
```bash
# 连接到其他端口 - 应该失败（没有服务监听）
telnet 127.0.0.1 8080
```

### 4. 查看 BPF 调试日志
```bash
# 实时查看 BPF 程序的调试输出
sudo cat /sys/kernel/debug/tracing/trace_pipe | grep redir_ip4
```

## 预期结果

### 成功的重定向连接
当连接到 `127.0.0.1:10000` 时：

1. **连接成功建立**
2. **收到欢迎消息**: "Hello! This connection was redirected by sk_lookup BPF program!"
3. **Echo 功能**: 输入的文本会被服务器回显
4. **BPF 日志输出**:
   ```
   redir_ip4, local_port: 10000
   redir_ip4, family: 2, local_port: 10000, local_ip4: 127.0.0.1
   ```

### 失败的连接
当连接到其他端口时：
- 连接被拒绝或超时
- 没有 BPF 日志输出（因为不匹配过滤条件）

## 测试脚本

创建自动化测试脚本：

```bash
#!/bin/bash
echo "=== sk_lookup POC 测试 ==="

# 启动程序（后台运行）
sudo ./sk_lookup &
SK_LOOKUP_PID=$!

# 等待程序启动
sleep 3

echo "测试 1: 重定向连接到 10000 端口"
echo "hello world" | nc 127.0.0.1 10000

echo "测试 2: 直接连接到 10001 端口"
echo "direct connection" | nc 127.0.0.1 10001

echo "测试 3: 连接到未监听端口（应该失败）"
timeout 3 nc 127.0.0.1 8080 || echo "连接失败（预期行为）"

# 清理
kill $SK_LOOKUP_PID
echo "测试完成"
```

## 故障排查

### 常见问题

1. **连接被拒绝**
   - 检查程序是否以 root 权限运行
   - 确认 BPF 程序正确加载
   - 验证 SOCKMAP 初始化成功

2. **重定向不工作**
   - 检查 IP 地址字节序是否正确
   - 确认端口号匹配
   - 查看 BPF 日志输出

3. **无调试日志**
   - 确认 `/sys/kernel/debug/tracing/trace_pipe` 可访问
   - 检查 BPF 程序是否正确附加

### 调试命令

```bash
# 查看已加载的 BPF 程序
sudo bpftool prog list

# 查看 BPF maps
sudo bpftool map list

# 查看 sk_lookup 程序详情
sudo bpftool prog show type sk_lookup

# 实时监控内核日志
sudo dmesg -w
```

## 技术细节

### 字节序处理
- IP 地址在内核中以网络字节序存储
- `IP4(127, 0, 0, 1)` 宏正确处理了字节序转换
- 端口号在 `bpf_sk_lookup` 上下文中以主机字节序提供

### SOCKMAP 类型
- 存储 socket 文件描述符的特殊 BPF map 类型
- 支持 `bpf_sk_assign()` 等 socket 操作
- 需要存储**监听 socket**而不是已连接的 socket

### 性能考虑
- sk_lookup 在连接建立阶段执行，对已建立连接无性能影响
- BPF 程序应尽量简单高效，避免复杂计算
- 使用 `bpf_printk` 仅用于调试，生产环境应移除

## 扩展应用

这个 POC 可以扩展为：
- **负载均衡器**: 将连接分发到多个后端服务器
- **服务网格**: 实现透明的服务间通信
- **安全网关**: 在连接层面实现访问控制
- **流量分析**: 记录和分析连接模式

## 参考资料

- [Linux BPF sk_lookup 文档](https://docs.kernel.org/bpf/prog_sk_lookup.html)
- [Cilium eBPF 库文档](https://pkg.go.dev/github.com/cilium/ebpf)
- [BPF 系统调用手册](https://man7.org/linux/man-pages/man2/bpf.2.html)
