# Windows 普通网页/视频 PCAP 采集手册

本手册用于采集 Win11 浏览器直连网站产生的普通流量，不经过 WSL Xray
客户端，也不经过授权实验服务器。适用目标是普通 IPv4/IPv6 网页、
新闻、视频等真实访问流量。

代理隧道实验的采集流程见[代理隧道采集](proxy-capture.md)。
两套流程不要混用。

## 1. 当前推荐环境

项目目录：

```powershell
D:\works\proxy-traffic-lab
```

数据目录：

```powershell
D:\works\proxy-lab-data\plain
```

Windows 依赖：

- Wireshark + Npcap
- `dumpcap.exe`，当前已支持 `D:\Wireshark\dumpcap.exe`
- Python 3.12 虚拟环境：`D:\works\proxy-traffic-lab\.venv`

启动 PowerShell：

```powershell
cd D:\works\proxy-traffic-lab
.\.venv\Scripts\Activate.ps1
```

如果 PowerShell 不允许激活虚拟环境，执行一次：

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

## 2. 和之前代理采集的区别

代理隧道实验数据链路是：

```text
Win11 Chrome -> 127.0.0.1:10808 SOCKS -> WSL/Docker client -> 授权实验服务器
```

WSL 可以抓到本地实验客户端发往授权实验服务器固定端口的外层隧道流量。

本手册的普通网页数据链路是：

```text
Win11 Chrome/Edge -> Windows 网络栈 -> WLAN -> 网站/CDN
```

因此抓包必须使用 Windows `dumpcap` 抓 Win11 网卡。WSL 的 `tcpdump`
通常看不到 Win11 浏览器的真实出站流量。

## 3. 采集前检查

列出网卡：

```powershell
lab capture windows-ipv6 --list-interfaces
```

当前 Wi-Fi 使用：

```text
4. ... (WLAN)
```

中文网卡名如果显示乱码不用管，只看编号和英文名。不要选
`vEthernet (WSL)`。

检查 IPv6 是否可用时必须在 Windows PowerShell 里执行：

```powershell
ping -6 www.bilibili.com
ping -6 news.cctv.com
```

WSL 里 `ping -6` 不通不能代表 Win11 不通，因为 WSL2 可能没有 IPv6
默认路由。

正式采集前关闭：

- VPN、Clash、v2rayN、公司 VPN、TUN 模式和游戏加速器
- 系统代理和浏览器代理插件
- 网盘同步、下载器、BT/PT、Steam、系统更新
- 日常 Chrome/Edge 的无关窗口

采集命令会启动一个独立无代理 Chrome/Edge profile：

```text
C:\Users\<user>\AppData\Local\ProxyLab\ChromePlainNoProxyProfile
```

注意：Windows 抓包是按网卡抓，不是按 Chrome 进程抓。独立浏览器只能减少
污染，不能从内核层保证只抓这个进程。

## 4. 进度字段怎么读

示例：

```text
flows 304 / 3000, active 287, completed 17,
tcp6 166, tcp4 138, ip6 13603, ip4 834, udp443-conv 1,
pcap 9.77 MiB, rate 2.21 KiB/s
```

含义：

- `flows`：当前 profile 使用的目标流数；`video-*` 为 TCP+UDP L4
  conversations，其他 profile 默认为看到 SYN-ACK 的 established TCP 连接；
  达到 `--target-flows` 后进入 DRAINING
- `active`：仍未关闭的 TCP 流，只供观察，不作为普通网页自动停止条件
- `completed`：已关闭的 TCP 流
- `tcp6`：IPv6 TCP 流数
- `tcp4`：IPv4 TCP 流数
- `ip6`：IPv6 包数，不是流数
- `ip4`：IPv4 包数，不是流数
- `udp443-conv`：UDP/443 会话数，常见于 QUIC/HTTP3
- `rate`：PCAP 文件增长速度

普通 Windows 采集默认使用：

```text
--flow-count-mode auto
```

`auto` 会对 `video-*` profile 使用 TCP+UDP L4 会话口径，对其他 profile
使用 established TCP 口径。若需要和早期实验完全一致，可以显式使用
`--flow-count-mode syn`，但普通网页/AI 聊天不建议这样做。

达到目标流数后，停止打开新页面。普通网页模式不会等待 `active == 0`，
而是等待 PCAP 写入速率低于空闲阈值并持续 `--idle-seconds` 后自动封尾。
这是因为浏览器、HTTP/2 和网站 CDN 会长期保留 TCP 连接。

## 5. 重要故障判断

如果浏览器和手机热点都有流量，但进度里 `pcap` 和 `rate` 长时间不变，
说明抓包没有继续写入。当前代码已经避免 `dumpcap` 输出管道阻塞，并把日志写入
每个 session 的：

```text
dumpcap.log
```

如果再次出现，停止当前采集，检查：

```powershell
Get-ChildItem D:\works\proxy-lab-data\plain -Recurse -Filter dumpcap.log |
  Sort-Object LastWriteTime -Descending |
  Select-Object -First 1 |
  Get-Content
```

如果 `flows` 不涨但 `ip6/ip4` 包数还在涨，通常是 HTTP/2/HTTP/3 连接复用。
继续停留同一页面不会明显增加 TCP 流，应该打开新的站内页面或降低单份目标。

如果 `active` 很高但 `rate` 已经很低，这是普通网页采集的常见情况。当前
Windows plain 模式会在达到目标流数后按 `rate` 空闲自动切下一份，不再等待
所有 TCP 流关闭。

如果 PCAP 很小但 `flows` 很多，通常表示页面产生了大量小连接、失败连接或后台连接。
当前默认 established 口径会减少这类噪声；仍然建议结合 SNI/DNS 审计判断样本纯度。

对真实网站，推荐目标是：

```text
1000-1500 TCP flows x 10 PCAP
```

比强行等待一个网站凑满 3000 TCP flows 更现实，也更稳定。

## 6. 文本采集命令

文本建议加 `--disable-quic`，减少 HTTP/3 复用，让 TCP 流数更可控。
每个网站单独跑一次，每次生成 5 个 PCAP。采集期间尽量只访问该站站内链接。

统一输出目录：

```powershell
$outputRoot = "D:\works\proxy-lab-data\plain"
```

央视新闻：

```powershell
lab capture windows-ipv6 `
  --interface 4 `
  --ip-version mixed `
  --target-flows 1500 `
  --output-root $outputRoot `
  --profile text-cctv-01 `
  --profile text-cctv-02 `
  --profile text-cctv-03 `
  --profile text-cctv-04 `
  --profile text-cctv-05 `
  --start-chrome `
  --disable-quic `
  --start-url "https://news.cctv.com/" `
  --progress-interval 2
```

网易新闻：

```powershell
lab capture windows-ipv6 `
  --interface 4 `
  --ip-version mixed `
  --target-flows 1500 `
  --output-root $outputRoot `
  --profile text-163-01 `
  --profile text-163-02 `
  --profile text-163-03 `
  --profile text-163-04 `
  --profile text-163-05 `
  --start-chrome `
  --disable-quic `
  --start-url "https://www.163.com/news/" `
  --progress-interval 2
```

中国政府网：

```powershell
lab capture windows-ipv6 `
  --interface 4 `
  --ip-version mixed `
  --target-flows 1500 `
  --output-root $outputRoot `
  --profile text-govcn-01 `
  --profile text-govcn-02 `
  --profile text-govcn-03 `
  --profile text-govcn-04 `
  --profile text-govcn-05 `
  --start-chrome `
  --disable-quic `
  --start-url "https://www.gov.cn/" `
  --progress-interval 2
```

操作方法：

- 不用搜索引擎作为数据源
- 从首页或频道页进入站内文章
- 每轮打开多个站内文章、滚动几秒、关闭标签，再继续新文章
- 不点广告和外链
- 进入 DRAINING 后停止操作，等待下一份 READY

## 7. 视频采集命令

视频不要加 `--disable-quic`，保留真实 QUIC/HTTP3 行为。`video-*`
profile 在 `--flow-count-mode auto` 下会自动使用 TCP+UDP L4 conversation
口径，接近 Wireshark `Statistics -> Conversations` 中 TCP 与 UDP 页签的合计。

B 站：

```powershell
lab capture windows-ipv6 `
  --interface 4 `
  --ip-version mixed `
  --target-flows 3000 `
  --output-root $outputRoot `
  --profile video-bilibili-01 `
  --profile video-bilibili-02 `
  --profile video-bilibili-03 `
  --profile video-bilibili-04 `
  --profile video-bilibili-05 `
  --start-chrome `
  --start-url "https://www.bilibili.com/" `
  --progress-interval 2
```

腾讯视频：

```powershell
lab capture windows-ipv6 `
  --interface 4 `
  --ip-version mixed `
  --target-flows 3000 `
  --output-root $outputRoot `
  --profile video-vqq-01 `
  --profile video-vqq-02 `
  --profile video-vqq-03 `
  --profile video-vqq-04 `
  --profile video-vqq-05 `
  --start-chrome `
  --start-url "https://v.qq.com/" `
  --progress-interval 2
```

西瓜视频：

```powershell
lab capture windows-ipv6 `
  --interface 4 `
  --ip-version mixed `
  --target-flows 3000 `
  --output-root $outputRoot `
  --profile video-ixigua-01 `
  --profile video-ixigua-02 `
  --profile video-ixigua-03 `
  --profile video-ixigua-04 `
  --profile video-ixigua-05 `
  --start-chrome `
  --start-url "https://www.ixigua.com/" `
  --progress-interval 2
```

## 8. 采完检查

汇总每份 `capture.json`：

```powershell
Get-ChildItem "D:\works\proxy-lab-data\plain" -Recurse -Filter capture.json |
  ForEach-Object {
    $j = Get-Content $_.FullName -Raw | ConvertFrom-Json
    [PSCustomObject]@{
      profile = $j.profile
      mode = $j.capture.flow_count_mode
      flows = $j.capture.flow_count
      l4tcp = $j.capture.tcp_conversation_count
      l4udp = $j.capture.udp_conversation_count
      flow6 = $j.capture.ipv6_flow_count
      flow4 = $j.capture.ipv4_flow_count
      completed = $j.capture.completed_flow_count
      active = $j.capture.active_flow_count
      ip6_packets = $j.capture.ipv6_packets
      ip4_packets = $j.capture.ipv4_packets
      udp443 = $j.capture.udp_443_conversations
      stop = $j.capture.stop_reason
      file = $_.FullName
    }
  } |
  Format-Table -AutoSize
```

可用样本优先满足：

- `flows >= target_flows`
- `stop == target_flows_reached_and_traffic_idle`
- `active` 可以大于 0；普通网页数据不以 active 归零作为合格条件
- `video-*` 样本重点看 `l4tcp + l4udp` 是否达到目标
- `flow6` 或 `flow4` 符合你的后续筛选需求

如果手动 `Ctrl+C`，该 PCAP 可作为试验或补充样本，但不算标准完成样本。

## 9. 后续过滤口径

本采集阶段只负责保存真实 mixed PCAP。后处理时可以按需要过滤：

- IPv4：`ip`
- IPv6：`ipv6`
- TCP：`tcp`
- UDP/QUIC：`udp.port == 443`
- 某站域名：优先用 DNS/SNI/HTTP host 审计，不要假设所有 CDN 域名都等于主站

现代网站会加载 CDN、字体、统计、图片、视频等子域名。分类标注建议按采集
profile 和人工访问站点记录，不要要求 PCAP 中每个域名都严格等于主站域名。
