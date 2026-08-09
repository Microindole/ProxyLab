# 项目架构

## 为什么是 `src/proxy_traffic_lab`

这不是重复目录，也不是历史兼容层：

- `src/` 是 Python 的源码布局，防止从仓库根目录意外导入未安装源码。
- `proxy_traffic_lab/` 是发布和安装后的唯一包命名空间。

`pyproject.toml` 将 `src/proxy_traffic_lab` 打包，并把 `lab` 命令指向
`proxy_traffic_lab.cli.app:main`。如果删除包名这一层，`capture`、`cli`、`protocols`
等都会成为容易冲突的顶层包，所有绝对导入和安装入口也要改成散包。因此保留这一层。

## 单向职责边界

```text
src/proxy_traffic_lab/
├── configuration/   YAML 模型、加载和组合兼容性校验
├── kernels/         上游内核来源、固定版本、镜像拉取/构建和锁文件
├── protocols/       协议原生配置的纯生成与结构验证
├── lifecycle/       渲染落盘、校验、server/client 启停、状态和日志
├── capture/         抓包后端、过滤器、流统计和采集状态
├── cli/             参数解析、命令注册、错误反馈和结果输出
├── common/          统一异常和外部进程执行
├── diagnostics/     主机环境诊断
├── dataset/         样本元数据 schema
├── encryptions/     TLS 材料及安全层目录
└── traffic/         受控流量生成
```

`traffic/registry.py` 按内层网络注册工作负载；网页工作负载只允许用于声明了 TCP 的
case，SOCKS5 UDP echo 工作负载只允许用于声明了 UDP 的 case。`dataset/audit.py`
独立检查采集结果，不参与代理内核配置或容器生命周期。

代理隧道抓包不再集中在单个 `capture/experiment.py` 中，职责拆分为：

| 模块 | 单一职责 |
| --- | --- |
| `capture/segmented.py` | 校验并轮转一组正式采集分段 |
| `capture/segment.py` | 运行一个分段的计数、排空和停止状态循环 |
| `capture/pilot.py` | 编排一次 web/UDP workload 小规模试采 |
| `capture/tcpdump.py` | tcpdump 启停、sudo 续期、路由接口与代理监听检查 |
| `capture/formatting.py` | 终端字节数格式化 |
| `dataset/records.py` | 写入正式/试采元数据、事件记录与摘要 manifest |

不保留 `capture/experiment.py` 转发层，调用方直接依赖自己使用的职责模块。

单元测试按同样的领域边界放在 `tests/unit/<domain>/`，当前包括 `capture`、`cli`、
`configuration`、`dataset`、`lifecycle`、`protocols`、`security` 和 `traffic`；
`tests/unit/` 根目录不直接堆放测试文件。

依赖方向为：

```text
cli -> lifecycle -> kernels
                -> protocols
                -> encryptions

cli -> capture -> configuration
```

`kernels/` 不实现代理协议，只保存和获取已有内核；`protocols/` 不启动容器；
`lifecycle/` 不定义 dataset class；`capture/` 不负责代理配置；`cli/` 不拼装内核原生
配置，只调用一个明确的生命周期操作并输出结果。

项目不自行实现 Shadowsocks、ShadowsocksR、VMess、VLESS、Trojan、Hysteria 2、
TLS、QUIC 或 REALITY，网络行为始终由固定版本的上游内核执行。

## YAML 目标矩阵

`configs/protocol_matrix.yaml` 是采集目标的唯一来源。当前 12 个特色目标以及
`required_dataset_classes` 都只写在该 YAML 中，Python 代码不包含 class ID 或编号范围。

其他配置分别声明可用组件：

| 文件 | 职责 |
| --- | --- |
| `configs/protocols.yaml` | 代理协议名称 |
| `configs/transports.yaml` | 传输包装和外层 TCP/UDP |
| `configs/encryptions.yaml` | 加密/安全层名称 |
| `configs/compatibility.yaml` | 内核实际支持的合法组合及参数 |

加载目标矩阵时会在采集前拒绝未知组件、不匹配内核和未声明组合。也可以先验证临时组合：

```powershell
lab matrix compose `
  --protocol vmess `
  --transport websocket `
  --encryption tls `
  --outer-transport tcp `
  --client-core xray-core `
  --server-core xray-core
```

## 三个内核采用同一结构

- Xray-core：`kernels/xray.py` + `protocols/xray/` + `lifecycle/xray/`
- Hysteria 2：`kernels/hysteria2.py` + `protocols/hysteria2.py` + `lifecycle/hysteria2.py`
- ShadowsocksR-native：`kernels/shadowsocksr.py` + `protocols/shadowsocksr.py` +
  `lifecycle/shadowsocksr.py`

跨内核选择由 `lifecycle/registry.py` 的注册表完成，不再存在 `providers/runtime.py` 或
各内核自己的大杂糅 `runtime.py`。
