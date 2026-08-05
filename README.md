# 代理流量实验室

一个用于收集加密代理隧道流量的、经过授权且可复现的流水线。

原始冒烟测试里程碑支持
`VLESS + TCP + TLS`。第一个正式数据集试验支持目标类别 5：
`VMess + WebSocket + TLS`，使用固定版本的官方 Xray-core
实现，而不是自定义协议代码。

本仓库不是公共代理部署工具包。仅可在你拥有或明确获得授权测试权限的系统和网络上运行。
代理端口必须限制为采集客户端的源
IP。绝不要提交凭据、私钥、UUID、令牌、公共 IP 地址或数据包捕获文件。

## 当前里程碑

-   类型化 YAML 配置
-   `lab doctor` 主机诊断
-   适用于 2 核 / 4 GiB 服务器的保守资源限制
-   MVP 场景的协议矩阵验证
-   面向提供商、隔离、采集、流量和数据集的扩展接口

## Ubuntu 初始化

``` bash
sudo apt update
sudo apt install -y python3 python3-venv git make iproute2 nftables \
  tcpdump tshark curl jq openssl

cd /root/proxy-traffic-lab
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
cp --update=none .env.example .env
lab doctor
pytest
```

`lab doctor` 会检查 Docker，但本仓库不会使用不可信的一键 Docker
或代理安装程序。

## 配置

仓库中的文件只包含占位符和非敏感默认值。请将密钥放入 `secrets/` 目录，
或通过环境变量注入。整个 `secrets/` 目录已被 Git 忽略。

``` bash
lab config validate
lab matrix list
lab doctor --json
```

## Xray 准备

选定的基线是官方 `ghcr.io/xtls/xray-core` 镜像，稳定版本为 `v26.2.6`
（GHCR 标签
`26.2.6`）。第一个命令会将该标签解析为不可变仓库摘要，并将结果保存到
`configs/locks/xray.json`。

``` bash
lab xray lock-image
lab xray init-secrets --server-name lab.invalid --validity-days 30
lab xray render --server-address YOUR_VPS_PUBLIC_IP --server-port 24443
lab xray validate
lab server start
lab server status
lab server logs --tail 100
lab server stop
```

所有生成的凭据以及客户端/服务器配置均位于 Git 忽略的 `secrets/` 目录中。
短期自签名证书通过证书 SHA-256 固定校验；生成的客户端配置不会设置
`allowInsecure`。

在云安全组限制来源为采集客户端公网 `/32` 之前，不要开放端口 `24443`。
后续数据集分组中，该端口将支持配置化并进行轮换。

`lab server start`
具有幂等性，并会在启动前重新验证生成的客户端和服务器配置。
服务器以只读模式运行，删除所有 Linux capabilities，无权限提升，限制为：
一个 CPU、512 MiB 内存以及 128 个进程。

## 试验

当前有两套采集流程，按目标选择，不要混用：

- 普通网页/视频直连流量（Win11 + Wireshark/Npcap + mixed IPv4/IPv6）：
  [`docs/plain-windows-capture-runbook-zh.md`](docs/plain-windows-capture-runbook-zh.md)
- 代理隧道类别 5/6（WSL 客户端 + VPS 服务端 + 外层 TCP 流分段）：
  [`docs/flow-limited-capture-runbook-zh.md`](docs/flow-limited-capture-runbook-zh.md)

旧的按 1 GiB 分段流程只作为历史参考保留：
[`docs/formal-capture-runbook-zh.md`](docs/formal-capture-runbook-zh.md)。

在服务器端渲染类别 5。此操作只替换被忽略的生成配置，不会替换证书或凭据。

``` bash
lab xray render \
  --case class-05-vmess-websocket-tls \
  --server-address YOUR_VPS_PUBLIC_IP \
  --server-port 24443
lab xray validate
lab server start
lab server status
```

将 `secrets/generated/client.json` 复制到采集主机，然后在采集主机运行：

``` bash
lab client start --config ~/proxy-lab-client/client.json
lab client status
curl --fail --socks5-hostname 127.0.0.1:10808 https://example.com/ -o /dev/null
```

在试验前预热 sudo 凭据，因为采集过程使用非交互式 sudo。 Chromium
运行期间不会弹出提示：

``` bash
sudo -v
export PLAYWRIGHT_BROWSERS_PATH="$HOME/.cache/ms-playwright"

lab experiment web \
  --case class-05-vmess-websocket-tls \
  --server-ip YOUR_VPS_PUBLIC_IP \
  --server-port 24443 \
  --duration 120 \
  --max-pages 12 \
  --url https://example.com/ \
  --url https://www.iana.org/help/example-domains \
  --output-root ~/proxy-lab-data
```

每次试验都会存储在：

`~/proxy-lab-data/pilot/class-05-vmess-websocket-tls/<sample-id>/`

其中包含：

-   `capture.pcap`
-   `metadata.json`
-   `traffic.jsonl`
-   `manifest.sha256`

只能使用允许自动化访问的 URL。Web 试验是正确性验证门槛， 不是最终 5 GiB
类别数据采集。
