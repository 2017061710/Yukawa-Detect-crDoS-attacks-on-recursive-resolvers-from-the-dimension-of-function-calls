# dns-ebpf

基于 eBPF 的 BIND DNS 观测工具，提供：

- **normal 模式**：无需自定义 BPF 程序，自动按 ELF 符号批量附着 uprobe/uretprobe，输出粗颗粒事件；
- **detail 模式**：载入 `hook/detail` 中生成的专用 eBPF，按需解码结构体并输出 JSON 事件。

运行过程产生的日志、事件、映射信息都会写入 `record/<timestamp>/` 目录，方便离线分析与复现实验。normal 模式的输出会同时包含原始符号名与（若为 C++）解码后的符号名。

## 快速上手

```
# 在tool_Yukawa/dns-ebpf目录下
make all
./build/dns-ebpf -mode detail -c config/bind/9_16_2/detail.yaml -e -event-targets file
```

## 目录结构

| 路径 | 说明 |
| ---- | ---- |
| `hook/normal` | normal 模式的配置解析、执行计划以及 runtime |
| `hook/detail` | detail 模式的 Session、事件解码器以及 bpf2go 产物 |
| `hook/output` | 事件输出（文件、Redis）实现 |
| `hook/model`  | cgo 生成的 eBPF event 结构，与 detail 解码器共享 |
| `hook/tools/cmd/hookidgen` | 扫描 `.def` 文件并生成 `hook_ids.h` 的工具 |
| `config/` | 预置的 normal/detail YAML 配置及模板 |
| `utils/` | 辅助脚本（例如自动生成配置） |
| `record/` | 运行时生成的日志、事件和 map 信息 |

## 环境准备

```bash
sudo apt update
sudo apt install -y clang llvm libbpf-dev gcc-multilib make golang redis-tools
```

> 需要 Linux 5.8+（推荐 5.10+）并启用 `CONFIG_BPF`/`CONFIG_BPF_JIT`。

## 构建

```bash
# 1. 生成 hook_ids.h、bpf 对象以及 Go 绑定
make hook

# 2. 编译主程序（会自动执行 make hook）
make

# 等价手动构建
go build -o build/dns-ebpf ./...
```

`make hook` 会读取 `hook/ebpf/headers/*/*.def`，在 `hook/detail` 目录生成 `hook_x86_bpf*.go`、`hook_x86_bpf*.o` 以及 `hook_ids.h`，供 detail 模式引用。

## 运行

```bash
./build/dns-ebpf -h
  -mode string                 Hook 模式：normal/detail（默认 detail）
  -c string                    配置文件路径，若留空将按模式选择默认文件
  -event-targets string        事件输出（file,redis，可组合，默认 file）
  -log-output string           运行日志输出：file 或 console（默认 console）
  -e                           是否写入事件（默认 false，可用 -e 启用）
  -redis-addr string           Redis 地址（默认 localhost:6379）
  -redis-db int                Redis DB（默认 0）
  -redis-key string            Redis 列表 key（默认 dns_events）
  -redis-password string       Redis 密码
  -v                           是否输出实时 Hook 进度（默认 true）
```

### normal 模式

```bash
./build/dns-ebpf -mode normal \
  -c config/bind/9_16_2/normal.yaml \
  -event-targets file

tail -f record/<timestamp>/events.log
```

执行流程：
1. 读取 YAML 配置，按 include/exclude 规则挑选符号；
2. 自动生成 hook 计划并附着 uprobe/uretprobe；
3. 事件通过 ring buffer 输出，写入 `events.log` 或推送 Redis。

运行结束可在 `record/<timestamp>/hook_items.json` 中查看具体符号与 Hook ID 对应关系。

### detail 模式

```bash
./build/dns-ebpf -mode detail \
  -c config/bind/9_16_2/detail.yaml \
  -event-targets file,redis \
  -redis-addr localhost:6379
```

执行流程：
1. 根据配置选择需要装载的 eBPF program/map；
2. 仅附着配置列出的符号；
3. 按 `event_decoder` 指定的解码器解析 `hook_event_map` 中的 ring buffer 样本；
4. 将解码后的 JSON 事件写入文件或 Redis。

## 配置说明

### normal 模式配置（`config/*/normal.yaml`）

```yaml
targets:
  - path: /usr/local/sbin/named
    language: c++                 # 可选：c（默认）/ c++，c++ 时会自动对符号做 demangle
    default_entry: true          # 默认附着 entry
    default_return: true         # 默认附着 return
    include:
      - pattern: "dns_.*"        # pattern 必填，match 可选：raw/demangled/both（默认 both）
        match: raw
      - pattern: "std::.*"
        match: demangled         # 仅对解码后的 C++ 名称匹配
    exclude: ["^_start$"]        # 可选，正则匹配需要排除的符号
    explicit:                    # 可选，逐个符号覆盖 Entry/Return
      - symbol: _start
        entry: false
        return: false
      - demangled_symbol: "std::basic_string<char, std::char_traits<char>, std::allocator<char> >::_M_construct(char*, char*, std::forward_iterator_tag)"
        entry: true
        return: false
```

`InitHookFuncs` 会读取 ELF 符号表、在需要时解码 C++ 符号，并套用 include/exclude/explicit 规则（每条 include/exclude 可单独声明匹配 raw/demangled/both），最终生成附着计划。默认配置针对 BIND 9.16.2 的主要二进制/动态库，可按需修改路径或过滤规则。normal 模式生成的 `hook_items.json` 与事件 JSON 中会额外包含 `demangled_func_name` 字段。

### detail 模式配置（`config/*/detail.yaml`）

```yaml
programs:
  - name: uprobe_bind_fctx_query_entry    # 对应 bpf2go 生成的 program 名称
    bin_path: /usr/local/lib/libdns.so
    symbol: fctx_query
    position: entry                       # entry/return
maps:
  - name: hook_event_map                  # 必须与 eBPF 程序中的 map 名一致
infos:
  - hook_id: hook/ebpf/headers/bind/9_16_2/hook_ids.h
event_decoder: bind_9_16_2                # detail/EventDecoder 注册名
```

- `infos` 允许为事件编码器提供额外上下文，目前用于加载 hook ID -> 名称的映射；
- `event_decoder` 默认为 `bind_9_16_2`，可通过实现新的解码器（参考 `hook/detail/decoder_bind_9_16_2.go`）扩展。

### detail 配置自动生成

`utils/generate_detail_config.py` 可以根据 `hook_ids.h` 与 normal 模式产出的 `hook_items.json` 生成 detail 模式 YAML，省去手工维护：

```bash
python utils/generate_detail_config.py \
  --hook-header hook/ebpf/headers/bind/9_16_2/hook_ids.h \
  --hook-items record/<timestamp>/hook_items.json \
  --output config/bind/9_16_2/detail.generated.yaml \
  --symbol-prefix uprobe_bind_ \
  --map hook_event_map \
  --event_decoder bind_9_16_2
```

- `--map` 可多次指定以保留多个 map，默认只写入 `hook_event_map`；
- `--symbol-prefix` 指定 `HOOK_` 宏中 program 名的前缀（默认为 `uprobe_bind_`），确保匹配正确的函数；
- `--strict` 会在任意符号无法匹配时失败，方便在 CI 中使用；
- 脚本会自动去除 `HOOK_`、前缀、`_entry/_return` 后缀后再比对 `func_name`。

## 事件输出

- `-event-targets file` 会将每条事件写入 `record/<timestamp>/events.log`；
- `-event-targets redis` 通过 `RPUSH <redis-key>` 投递 JSON；
- 可组合 `file,redis` 以同时生效；
- `-e=false` 可完全关闭事件消费，仅用于调试 Hook 状态。
- normal 模式事件以 JSON 输出（文件与 Redis 同格式），字段：`timestamp_boot_ns`、`tgid`、`pid`、`hook_id`、`bin_path`、`func_name`、`demangled_func_name`、`position`。

`record/<timestamp>/run.log` 保存主程序日志，`map_info.json` 记录 normal 模式生成的 map ID，方便其他工具复用。

## Hook 模板 & hookidgen

- `hook/ebpf/headers/common/hook_macros.h` 定义了 `HOOK_PARAM` / `HOOK_PARAM_PTR` 等辅助宏，可在 `.def` 文件中快速声明 Hook；
- 模板示例：

```c
#define DNS_MSG_PARAM(idx) HOOK_PARAM_PTR(dns_message_t, idx)
#define DNS_MSG_HOOK(target, expr) \
  HOOK_TYPED_UPROBE(target, dns_message_t, expr, report_dns_message_event)
```

按照上述方式新增 `FOO_HOOK` 宏后，在对应 `.def` 文件内写入 `FOO_HOOK(uprobe_xxx, args...)` 即可纳入 `make hook` 的自动生成流程。

`hook/tools/cmd/hookidgen` 会：

1. 解析 `.def` 中所有 `XXX_HOOK`；
2. 生成自增的 `HOOK_uprobe_xxx` 宏常量；
3. 合并 `manual_hooks.txt` 中的额外符号（用于特殊场景）。

独立运行示例：

```bash
go run ./hook/tools/cmd/hookidgen \
  -def hook/ebpf/headers/bind/9_16_2/hooks.def \
  -extra hook/ebpf/headers/bind/9_16_2/manual_hooks.txt \
  -o hook/ebpf/headers/bind/9_16_2/hook_ids.h
```

## 调试与常用命令

- 查看 bpf_printk：
  ```bash
  sudo mount -t debugfs none /sys/kernel/debug
  sudo cat /sys/kernel/debug/tracing/trace_pipe
  ```
- 检查进程加载的 so：`cat /proc/<pid>/maps`
- 查询符号：`readelf -s /usr/local/lib/libdns.so | grep fctx_query`
- 启动 named：
  ```bash
  sudo named -c /etc/bind/named.conf          # 后台
  sudo named -g -c /etc/bind/named.conf       # 前台调试
  ```
- Redis：
  ```bash
  sudo apt install -y redis-server
  redis-server --daemonize yes
  redis-cli ping
  ```
- 触发 DNS 流量：`dig @127.0.0.1 www.example.com`

- 安装BPFtool（可选）
    ```bash
    git clone --recurse-submodules https://github.com/libbpf/bpftool.git
    # 必须要安装，不然缺少库
    sudo apt install libelf-dev
    # 进入项目目录
    cd bpftool/
    # 进入源码目录
    cd src
    # 安装bpftool
    sudo make install

    # 基本使用：
    # 列举所有map
    sudo bpftool map
    # 查看ip为1944的map
    sudo bpftool map dump id 1944
    ```

## 工具
### 内存布局查看
```bash
apt-get install dwarves
pahole -C auth_xfer /usr/sbin/unbound
---输出---
struct auth_xfer {
        rbnode_type                node;                 /*     0    40 */
        lock_basic_type            lock;                 /*    40    40 */
        /* --- cacheline 1 boundary (64 bytes) was 16 bytes ago --- */
        uint8_t *                  name;                 /*    80     8 */
        size_t                     namelen;              /*    88     8 */
        int                        namelabs;             /*    96     4 */
        uint16_t                   dclass;               /*   100     2 */

        /* XXX 2 bytes hole, try to pack */

        struct auth_nextprobe *    task_nextprobe;       /*   104     8 */
        struct auth_probe *        task_probe;           /*   112     8 */
        struct auth_transfer *     task_transfer;        /*   120     8 */
        /* --- cacheline 2 boundary (128 bytes) --- */
        int                        notify_received;      /*   128     4 */
        int                        notify_has_serial;    /*   132     4 */
        uint32_t                   notify_serial;        /*   136     4 */

        /* XXX 4 bytes hole, try to pack */

        struct auth_master *       allow_notify_list;    /*   144     8 */
        int                        zone_expired;         /*   152     4 */
        int                        have_zone;            /*   156     4 */
        uint32_t                   serial;               /*   160     4 */

        /* XXX 4 bytes hole, try to pack */

        time_t                     retry;                /*   168     8 */
        time_t                     refresh;              /*   176     8 */
        time_t                     expiry;               /*   184     8 */
        /* --- cacheline 3 boundary (192 bytes) --- */
        time_t                     lease_time;           /*   192     8 */

        /* size: 200, cachelines: 4, members: 20 */
        /* sum members: 190, holes: 3, sum holes: 10 */
        /* last cacheline: 8 bytes */
};
```

## 已知问题

- 容器环境的 PID namespace 会导致事件中的 PID/TGID 与 `ps` 结果不一致，可结合 `bpf_get_current_task` 补充上下文。
- 遇到 eBPF verifier 报错时，使用 `-v` 查看完整日志，并确认 `clang/llvm` 版本满足要求。
