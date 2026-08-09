# 代理隧道 PCAP 采集手册

> 本手册适用于代理隧道实验：Windows 浏览器进入本地实验客户端，
> WSL 抓取到授权实验服务器固定端口的外层隧道流量。
>
> 普通网页/新闻/视频直连流量的当前流程已经迁移到 Windows 原生环境，
> 见[普通网站采集](plain-capture.md)。两套流程不要混用。

## 1. 当前范围

协议矩阵中的 12 类均已启用。类别 1/2 和 5--10 由 Xray-core 执行，类别 3/4
由源码提交固定的 ShadowsocksR-native 执行，类别 11/12 由官方 Hysteria 2 内核执行。
本项目只生成上游内核的原生配置并管理容器，不自行实现
Shadowsocks、ShadowsocksR、VMess、VLESS、Trojan、Hysteria 2、QUIC、TLS 或 Salamander。

类别 11 是 Hysteria 2 + QUIC + TLS，类别 12 在同一组合上启用 Salamander。
首次正式采集前仍必须在实际 Linux/WSL 与服务器环境完成小规模连通性和 PCAP 纯度验证。

旧的按 1 GiB 采集结果保存在 `/home/indole/formal_bak`，不混入本轮正式数据。新数据写入 `/home/indole/proxy-lab-data/formal`。

本轮完全使用 Windows 专用 Chrome 手动访问，不使用自动 URL脚本、爬虫或循环 curl。

## 2. 分段口径

每个 PCAP 的目标是3000个完整起始的外层TCP会话：

- 新的 TCP SYN 增加一个流，SYN重传不会重复计数。
- 达到3000后进入 `DRAINING`，此时停止所有手动操作。
- 活动流没有全部结束时绝不关闭或切换 PCAP。
- 关闭专用 Chrome，让活动连接通过 FIN/RST自然结束。
- 活动流归零并持续空闲15秒后，封尾当前 PCAP，再创建下一份。
- `--finish-timeout` 在流模式中只重复告警，不会截断活动流。

类别 11/12 的 `--target-flows` 统计双向归一化后的外层 UDP 五元组。一个 Hysteria 2
QUIC 连接可以复用许多内层 TCP/UDP 流，因此这个数字不等于网页连接数或 QUIC stream
数量。正式采集 Hysteria 2 时优先使用 `--target-gib` 容量口径；只有实验设计明确要求
外层 UDP 会话数，并会在样本间重建客户端连接时，才使用 `--target-flows`。

## 3. 流大小不作为采集停止条件

采集器不设置单流大小上限、不因流大小告警，也不按流大小判定 PCAP 是否合格。流大小在后续离线处理 PCAP 时统计和筛选。

关闭标签页或浏览器是正常用户行为；达到目标流数后，抓包器仍会等待已存在的连接自然关闭，不会在 PCAP 中截断活动 TCP 流。

## 4. 采集前检查

关闭 Windows VPN、TUN、系统代理、日常 Chrome/Edge 和所有后台下载。只保留当前实验客户端。

先在正式抓包前，于 WSL执行：

```bash
cd ~/proxy-traffic-lab
. .venv/bin/activate

lab client status

curl \
  --fail \
  --socks5-hostname 127.0.0.1:10808 \
  --connect-timeout 10 \
  --max-time 30 \
  -o /dev/null \
  -w 'HTTP status: %{http_code}\n' \
  https://example.com/
```

只有客户端 `healthy=true` 且 HTTP返回200才继续。检查完成后停止其他网络操作，再启动正式抓包。

### 类别 1/2：Xray-core 的 Shadowsocks 2022

Shadowsocks 是协议，Xray-core 是本矩阵选择的实现内核，因此配置仍由 `lab xray`
生成，不存在单独的 Shadowsocks 进程：

```bash
lab xray init-secrets
lab xray render \
  --case class-01-shadowsocks-2022-tcp \
  --server-address YOUR_SERVER_IP \
  --server-port 24443
lab xray validate
lab server start --case class-01-shadowsocks-2022-tcp
```

类别 2 将 case 改为 `class-02-shadowsocks-2022-udp`，并确保服务器防火墙放行 UDP。

### 类别 3/4：独立 ShadowsocksR-native 内核

SSR 不属于 Xray 的 Shadowsocks 实现。本项目从固定的上游 Git commit 构建容器，
避免依赖来源不明的第三方 SSR 镜像。SSR 内核较旧，只能在隔离、授权的实验环境使用。

```bash
lab shadowsocksr build-image
lab shadowsocksr init-secrets
lab shadowsocksr render \
  --case class-03-ssr-auth-aes128-md5 \
  --server-address YOUR_SERVER_IP \
  --server-port 24443
lab shadowsocksr validate
lab server start --case class-03-ssr-auth-aes128-md5
lab server status --case class-03-ssr-auth-aes128-md5
```

类别 4 将 case 改为 `class-04-ssr-auth-aes128-sha1`。客户端只同步
`configs/locks/shadowsocksr-native.json` 和
`secrets/generated/shadowsocksr-client.json`，然后执行：

```bash
lab client start --case class-03-ssr-auth-aes128-md5 \
  --config secrets/generated/shadowsocksr-client.json
lab client status --case class-03-ssr-auth-aes128-md5
```

### 从情况5切换到情况6

情况5和情况6共用端口24443，但同一时刻只运行一种配置。不要同时启动两个服务。

先在授权实验服务器终端执行（不是 WSL，也不需要从 WSL 反复 SSH）：

```bash
cd /root/proxy-traffic-lab
. .venv/bin/activate

lab server stop
lab xray render \
  --case class-06-vmess-xhttp-h2-tls \
  --server-address YOUR_SERVER_IP \
  --server-port 24443
lab xray validate
lab server start
lab server status
```

然后只同步一次客户端配置。在 WSL 执行：

```bash
export VPS_IP=YOUR_SERVER_IP

scp root@"$VPS_IP":/root/proxy-traffic-lab/secrets/generated/client.json \
  "$HOME/proxy-lab-client/client.json"
chmod 600 "$HOME/proxy-lab-client/client.json"

cd ~/proxy-traffic-lab
. .venv/bin/activate
lab client stop
lab client start --config "$HOME/proxy-lab-client/client.json"
lab client status

curl --fail --socks5-hostname 127.0.0.1:10808 \
  --connect-timeout 10 --max-time 30 -o /dev/null \
  -w 'HTTP status: %{http_code}\n' https://example.com/
```

必须看到 `healthy: true` 和 `HTTP status: 200`。切回情况5时，在服务器重新执行同一组命令，只把 `--case` 改成 `class-05-vmess-websocket-tls`，再同步一次新生成的 `client.json`。

### 配置并启动类别 11/12

以下命令调用官方 Hysteria 2 容器，不包含自研协议实现。先在服务器项目目录锁定镜像、
生成短期实验凭据并渲染配置：

```bash
lab hysteria2 lock-image
lab hysteria2 init-secrets --server-name lab.invalid --validity-days 30
lab hysteria2 render \
  --case class-11-hysteria2-quic-tls \
  --server-address YOUR_SERVER_IP \
  --server-port 24443
lab hysteria2 validate
lab server start --case class-11-hysteria2-quic-tls
lab server status --case class-11-hysteria2-quic-tls
```

采类别 12 时，把上面所有 `--case` 改为
`class-12-hysteria2-quic-salamander-tls`。两类不能共用正在运行的服务端容器；切换前执行：

```bash
lab server stop --case class-11-hysteria2-quic-tls
```

将以下文件通过受控通道同步到客户端对应项目路径，不要提交到 Git：

- `configs/locks/hysteria2.json`
- `secrets/generated/hysteria2-client.yaml`

客户端不需要服务端私钥。客户端项目目录中执行：

```bash
lab client start --case class-11-hysteria2-quic-tls \
  --config secrets/generated/hysteria2-client.yaml
lab client status --case class-11-hysteria2-quic-tls

curl --fail --socks5-hostname 127.0.0.1:10808 \
  --connect-timeout 10 --max-time 30 -o /dev/null \
  -w 'HTTP status: %{http_code}\n' https://example.com/
```

防火墙和云安全组必须允许实验端口的 **UDP** 入站。只有客户端状态健康、HTTP 返回成功，
且一份短试采 PCAP 中目标端口主要是预期服务器与客户端之间的 UDP，才开始正式采集。

生命周期命令可用 `--case` 按矩阵选择内核，也可直接用
`--core xray-core|hysteria2|shadowsocksr-native`。不传二者时读取 `configs/lab.yaml` 中的
`runtime.default_core`，默认仍是 `xray-core`。

Hysteria 2 推荐先按容量采集一份试样：

```bash
lab capture run \
  --case class-11-hysteria2-quic-tls \
  --server-ip YOUR_SERVER_IP \
  --server-port 24443 \
  --target-gib 0.1 \
  --profile pilot-01
```

## 5. 启动连续五份 PCAP

在 WSL终端 A执行：

```bash
cd ~/proxy-traffic-lab
. .venv/bin/activate
export VPS_IP="YOUR_SERVER_IP"

sudo -v

CASE="class-05-vmess-websocket-tls"  # 采情况6时改为 class-06-vmess-xhttp-h2-tls

lab capture run \
  --case "$CASE" \
  --server-ip "$VPS_IP" \
  --server-port 24443 \
  --target-flows 3000 \
  --profile sample-01 \
  --profile sample-02 \
  --profile sample-03 \
  --profile sample-04 \
  --profile sample-05 \
  --progress-interval 2 \
  --idle-seconds 15 \
  --idle-kib-per-second 32 \
  --finish-timeout 300
```

等待出现：

```text
READY segment 1/5: sample-01
Target: 3000 outer TCP flows
```

## 6. 启动手动访问专用 Chrome

在 Windows PowerShell执行：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File `
  "\\wsl.localhost\Ubuntu\home\indole\proxy-traffic-lab\scripts\browser\chrome.ps1"
```

启动器默认打开 `about:blank`，不会自动访问任何网站。不要在正式抓包期间添加 `-CheckProxy`。

手动输入你准备访问的真实网站，建议：

1. 访问不同站点的首页、文章页、新闻页、论坛或文档页面。
2. 正常滚动、点击站内链接、返回、前进和分页。
3. 每个页面停留数秒到几十秒，不快速重复刷新。
4. 分散访问多个站点，避免单一网站占据绝大多数流。
5. 不登录私人账号，不提交密码、消息或敏感数据。

终端 A会持续显示：

```text
[segment 1/5 CAPTURING ...] flows 1842 / 3000, active 9, completed 1833
```

接近目标时：

- 约2800流：减少新标签页，只完成当前页面。
- 约2950流：不要再打开新站点，使用当前站点少量正常跳转。
- 达到或超过3000流：立即停止操作并关闭整个专用 Chrome窗口。

随后终端 A进入：

```text
[segment 1/5 DRAINING ...] flows 3004 / 3000, active 6, completed 2998
```

不要按 `Ctrl+C`。等待：

```text
Segment 1/5 stopped: target_flows_reached_and_all_flows_closed
READY segment 2/5: sample-02
```

出现新的 `READY` 后，再次运行同一条 PowerShell启动命令，开始下一份手动会话。五份都按这个循环操作。

## 7. 验收

```bash
find "$HOME/proxy-lab-data/formal/class-05-vmess-websocket-tls" \
  -name capture.json -print0 |
xargs -0 jq -r '[.profile, .capture.flow_count, .capture.completed_flow_count, .capture.active_flow_count, .capture.stop_reason] | @tsv'
```

每份必须满足：

- `flow_count >= 3000`
- `completed_flow_count == flow_count`
- `active_flow_count == 0`
- `stop_reason == target_flows_reached_and_all_flows_closed`
- tcpdump日志包含 `0 packets dropped by kernel`

独立复核流数：

```bash
PCAP="替换为 capture.pcap 完整路径"

tshark -r "$PCAP" -Y 'tcp.flags.syn == 1 && tcp.flags.ack == 0' \
  -T fields -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e tcp.seq_raw |
sort -u |
wc -l
```

实时计数和 tshark复核只应有极小差异；差异明显时不要入库。
