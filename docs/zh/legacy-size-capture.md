# 历史容量分段流程（WSL 客户端 + 授权实验服务器）

> 已过时：本手册按 1 GiB 分段，不符合当前“每份约 3000 个完整外层流”的要求。新的正式流程见[代理隧道采集](proxy-capture.md)。本文件只保留作历史参考。

## 1. 本手册的适用范围

本手册用于采集本地实验客户端与授权实验服务器之间的隧道流量。当前已经端到端验证、可以正式采集的是：

- 数据类别：5
- Case ID：`class-05-vmess-websocket-tls`
- 协议：VMess
- 外层传输：WebSocket over TCP
- 安全层：TLS
- 服务端端口：`24443`
- 单份目标：至少 `1 GiB`，即 `1,073,741,824` 字节
- 每类最低数量：5 个相互独立的 PCAP

> 重要：采集命令只负责抓取和标记流量，不会实现代理协议。类别 1–4、6–12 必须先用对应的正式开源实现完成服务端、客户端配置并通过连通性验证，才能采集。不能只把 `--case` 改成另一个名称就把 VMess 流量标成其他协议。

本手册中的 PCAP 保存在 WSL：

```text
/home/indole/proxy-lab-data/formal/
```

不是保存在实验服务器。Windows 可以通过下面的位置查看，但正式抓包期间不要移动或修改正在增长的文件：

```text
\\wsl.localhost\Ubuntu\home\indole\proxy-lab-data\formal
```

## 2. 采集期间不能开启的程序和设置

开始正式采集前，关闭以下程序或功能：

1. Windows 上的其他 VPN、公司 VPN、Clash、v2rayN、WireGuard、OpenVPN、TUN 模式和游戏加速器。
2. Windows“设置 → 网络和 Internet → 代理”中的系统代理。
3. 浏览器代理扩展，例如 SwitchyOmega，以及任何会再次改写代理的扩展。
4. OneDrive、百度网盘、阿里云盘、Steam、BT/PT、系统更新和其他后台下载或上传。
5. 其他正在使用 `127.0.0.1:10808` 的浏览器、脚本或应用。
6. 其他实验代理客户端。正式采集时只运行当前类别对应的一个客户端容器。
7. Docker 镜像下载、系统升级和大规模 Git 拉取等会竞争带宽的任务。

不要把 Windows 或 WSL 的全局代理设置为 `127.0.0.1:10808`。本手册只让专用 Chromium 显式使用该 SOCKS5 代理，防止其他应用混入数据。

其他 VPN 即使没有直接出现在 PCAP 中，也可能改变 WSL 路由、出口 IP、MTU、时延和丢包，因此会影响数据质量。无法关闭时，不要进行正式采集。

采集期间还应遵守以下要求：

- 不登录私人账号，不采集密码、Cookie、私人消息或敏感业务。
- 只访问允许正常浏览、下载或播放的站点和内容。
- 不运行爬虫、不绕过验证码、不对第三方站点进行高并发请求。
- 不反复运行测速工具来凑容量，也不要用一个下载连接填满整份 PCAP。
- 不在一份 PCAP 中切换代理协议、服务端端口或客户端配置。
- 不要使用 `kill -9` 杀死抓包进程，不要在抓包过程中关闭 WSL 或重启电脑。

## 3. 采集前的终端安排

准备三个相互独立的终端：

- 终端 S：授权实验服务器终端，只负责服务端。
- 终端 A：WSL 抓包终端，前台运行 `lab capture run`。
- 终端 B：Windows PowerShell，只负责启动强制使用 WSL SOCKS5 的专用 Chrome。

不需要在 WSL 命令里反复套 `ssh`。只有复制新客户端配置时才需要 `scp`。

建议同时关闭普通 Chrome、Edge 等无关浏览器，避免误操作和带宽竞争。专用 Chrome 使用独立用户目录，与日常 Chrome 分开。

## 4. 第一步：检查授权实验服务器

在“终端 S（授权实验服务器）”执行：

```bash
cd /root/proxy-traffic-lab
. .venv/bin/activate

lab server status
```

正常结果应包含：

```json
{
  "state": "running",
  "healthy": true,
  "port": 24443
}
```

如果服务端没有运行，再执行：

```bash
lab server start
lab server status
```

再确认端口：

```bash
ss -lnt | grep ':24443'
```

云防火墙或安全组规则只应允许当前采集客户端的公网 IP/CIDR 访问实验端口，不要为了方便向全网永久开放。家庭和公司的公网出口 IP 可能不同，切换网络后应更新来源地址。

## 5. 第二步：检查 WSL 环境和磁盘

在“终端 A（WSL）”执行：

```bash
cd ~/proxy-traffic-lab
. .venv/bin/activate

df -h "$HOME"
```

一类至少需要 5 GiB，考虑文件超出目标、哈希和后续处理，开始一类采集前建议至少保留 10–15 GiB；采集全部 12 类前需要准备明显更大的余量。

清除当前终端继承的全局代理环境变量：

```bash
unset HTTP_PROXY HTTPS_PROXY ALL_PROXY
unset http_proxy https_proxy all_proxy
```

设置授权实验服务器公网 IP：

```bash
export VPS_IP="YOUR_SERVER_IP"
```

如服务器 IP 以后改变，只修改这里，不要盲目复制旧值。

## 6. 第三步：启动并验证 WSL 代理客户端

仍然在“终端 A（WSL）”执行：

```bash
lab client status
```

如果客户端不存在或没有运行：

```bash
lab client start \
  --config "$HOME/proxy-lab-client/client.json"

lab client status
```

正常结果必须包含：

```json
{
  "state": "running",
  "healthy": true,
  "socks_port": 10808
}
```

检查本地监听：

```bash
ss -lnt | grep '127.0.0.1:10808'
```

检查端到端代理，必须得到 HTTP 200：

```bash
curl \
  --fail \
  --show-error \
  --socks5-hostname 127.0.0.1:10808 \
  --connect-timeout 10 \
  --max-time 30 \
  -o /dev/null \
  -w 'HTTP status: %{http_code}\n' \
  https://example.com/
```

如果不是 200，不要开始正式采集。先检查：

```bash
lab client logs --tail 100
```

同时在授权实验服务器“终端 S”检查：

```bash
lab server logs --tail 100
```

## 7. 第四步：确认 Windows 可以连接 WSL SOCKS5

在“终端 B（Windows PowerShell）”执行，必须得到 `HTTP=200`：

```powershell
curl.exe `
  --fail `
  --silent `
  --show-error `
  --socks5-hostname 127.0.0.1:10808 `
  --connect-timeout 10 `
  --max-time 30 `
  --output NUL `
  --write-out "HTTP=%{http_code}`n" `
  https://example.com/
```

这验证了 Windows 应用可以进入 WSL 中的实验客户端。正式 PCAP 仍由 WSL 在 `eth0` 上抓取到授权实验服务器端口的外层隧道；Windows 到 `127.0.0.1:10808` 的本地转发段不会混入该 PCAP。

不要再使用 WSLg/Playwright Chromium 进行正式采集。WSLg 窗口可能出现不可见、方框字体或任务栏幽灵窗口；Windows 专用 Chrome 更稳定，并且已经通过上述 SOCKS 测试保证走同一条 Xray 隧道。

## 8. 第五步：一次启动，连续采集五份 1 GiB PCAP

回到“终端 A（WSL）”。先刷新 sudo 凭据；抓包命令内部使用非交互 sudo，如果这里没有成功授权，抓包会立即退出：

```bash
cd ~/proxy-traffic-lab
. .venv/bin/activate
export VPS_IP="YOUR_SERVER_IP"

sudo -v
```

当前版本会在连续采集期间每 60 秒自动续期 sudo 凭据，并在启动每个新 segment 前再次检查，因此长时间采集不会再因 sudo 缓存超时而中断。不要另开终端执行 `sudo -k` 或修改 sudo 时间戳。

启动连续抓包。五个 `--profile` 的顺序就是五个 PCAP 的顺序：

```bash
lab capture run \
  --case class-05-vmess-websocket-tls \
  --server-ip "$VPS_IP" \
  --server-port 24443 \
  --target-gib 1 \
  --profile large-download \
  --profile video \
  --profile images-resources \
  --profile web-news \
  --profile other \
  --progress-interval 5 \
  --idle-seconds 15 \
  --idle-kib-per-second 32 \
  --finish-timeout 300
```

只需要执行这一次命令。看到下面信息才开始第一个“大文件下载”阶段：

```text
READY segment 1/5: large-download
Capturing class-05-vmess-websocket-tls on eth0 to .../capture.pcap
Target: 1.00 GiB
```

以及持续更新的进度：

```text
[segment 1/5 CAPTURING 04:30:00Z] 256.20 MiB / 1.00 GiB (25.0%), current rate 2.31 MiB/s
```

达到目标但当前动作尚未结束时，同一份 PCAP 会继续增长并明确显示：

```text
[segment 1/5 WAITING_FOR_IDLE 04:36:00Z] 1.12 GiB / 1.00 GiB (100.0%), overshoot 122.88 MiB, current rate 2.31 MiB/s
```

这仍是 segment 1，不是下一份。只有看到 `Segment 1/5 stopped` 和新的 `READY segment 2/5` 后，才真正创建了第二个 PCAP；第二份的大小、速率基线和百分比都会从零重新计算。

这个终端必须保持前台运行。不要再在终端 A 输入其他命令，也不要手动重复启动抓包。程序会在自然空闲边界封尾当前文件并启动下一份；只有看到下一个 `READY segment N/5` 后，才能开始下一类访问。

## 9. 第六步：启动 Windows 专用 Chrome

确认终端 A 已经显示抓包进度后，在“终端 B（Windows PowerShell）”执行：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File `
  "\\wsl.localhost\Ubuntu\home\indole\proxy-traffic-lab\scripts\browser\chrome.ps1"
```

脚本会先用 Windows `curl.exe` 验证 SOCKS5；验证失败时不会启动浏览器。验证成功后，它会清理上一次专用配置残留的后台进程，再打开标题类似 `Example Domain - Google Chrome` 的窗口。

如果关闭了这个窗口，直接重新执行上面同一条 PowerShell 命令即可。不要重启抓包、不要重启 Xray，也不要执行 `wsl --shutdown`。重新打开浏览器期间 PCAP 只会出现一段自然空闲。

专用配置目录是 `%LOCALAPPDATA%\ProxyLab\ChromeProfile`，下载默认保存到 `%USERPROFILE%\Downloads`。它不是日常 Chrome 配置；不要在这个专用窗口登录私人账号或安装代理扩展。

必须保留 `--disable-quic`。当前第 5 类的内层网页流量应走 TCP，避免 Chromium 使用普通 QUIC/HTTP3 后因为 SOCKS5 UDP 支持差异导致流量绕行或失败。以后采集 UDP 类别和 Hysteria2 时必须使用适合相应类别的客户端与流量方案，不能照搬此参数组合。

## 10. 第七步：在 Chromium 中进行真实访问

不要只循环访问 `example.com`，也不要只下载一个 1 GiB 文件。终端 A 显示的是 PCAP 文件进度，下面所有百分比都以终端 A 的进度为准，不要求网页下载量与 PCAP 字节完全相同。

只使用脚本启动的 Windows 专用 Chrome 做业务操作。不要用 `wget`、普通 `curl`、日常 Chrome 或 Edge 补流量，因为它们默认不经过本次 SOCKS5 客户端。每次最多保留 1–2 个活动标签页，完成一个动作再开始下一个动作，避免变成人为高并发压测。

五个 PCAP 合计应覆盖以下真实行为，但每一份按照自己的 profile 保持明确侧重：

1. 浏览 5–10 个获准访问的真实站点。
2. 打开首页、文章页、图片页，在页面内滚动、点击、返回和切换标签页。
3. 下载多个不同大小的合法公开文件，例如 10–100 MiB；部分完成，部分正常取消后稍后重试。
4. 播放允许访问的公开视频，每段约 3–10 分钟，包含暂停、继续和拖动进度。
5. 在不同动作之间保留数秒到几十秒的自然停顿。
6. 让网页、小文件、较大下载和视频共同构成 PCAP，不要让单一长连接占据几乎全部字节。

### 10.1 连续轮转的固定规则

1. 五份只启动一次抓包命令、一次 Chromium；中间不手动重启。
2. 当前段达到目标后，终端会要求完成当前 workload；此时不能开始下一类流量。
3. 当前段流量连续空闲 15 秒后，程序封尾它并立即创建下一份 PCAP。
4. 必须看到 `READY segment N/5` 后，才执行该段对应操作。
5. 如果出现 `target_reached_finish_timeout` 或你按 `Ctrl+C`，整个五段序列终止，不会把仍活跃的流硬切进下一份。
6. 五份共享同一个 `series_id`，它们不是五个独立浏览器会话。训练、验证、测试切分时必须整体放进同一分区。

### 10.2 Segment 1/5：大文件下载

抓包参数使用：

```bash
--profile large-download
```

按终端 A 的进度执行：

- 看到 `READY segment 1/5: large-download` 后才开始下载。
- 0%–70%：通过 Chromium 顺序下载多个获准文件，建议每个约 100–300 MiB；不要只用一个超大文件填满整份。
- 70%–90%：改用约 50–100 MiB 文件，减小最终超出 1 GiB 的幅度。
- 90%–100%：只开始一个预计能较快完成的文件。
- 出现 `target reached` 后，让当前文件正常完成，不再开始新下载。
- 当前下载完成后停止操作，等待 `READY segment 2/5: video`。

### 10.3 Segment 2/5：视频

抓包参数使用：

```bash
--profile video
```

按进度执行：

- 只播放获准访问的公开视频，不进行文件下载。
- 使用多个不同视频或片段，不要让一个视频连接贡献几乎全部字节。
- 每段播放约 3–10 分钟，包含自然暂停、继续和一两次进度拖动。
- 视频之间停顿约 5–20 秒，再开始下一个。
- 出现 `target reached` 后，在当前片段的合适位置暂停并关闭该视频标签页；不要开始新视频。
- 保持空闲，直到显示 `READY segment 3/5: images-resources`。

### 10.4 Segment 3/5：图片和静态资源

抓包参数使用：

```bash
--profile images-resources
```

按进度执行：

- 浏览允许访问的图片页、图集、产品展示页、地图/图表页和静态资源较多的站点。
- 打开原图或不同分辨率图片，正常滚动、翻页和站内跳转。
- 每个站点操作数分钟后更换站点，避免反复刷新同一 URL 或自动爬取。
- 不使用脚本批量请求，不用单个压缩包代替图片/资源访问。
- 出现 `target reached` 后，等待当前页面资源加载完成，关闭活动标签页并停止操作。
- 保持空闲，直到显示 `READY segment 4/5: web-news`。

### 10.5 Segment 4/5：普通网页和新闻

抓包参数使用：

```bash
--profile web-news
```

按进度执行：

- 以正常人工节奏访问获准使用的新闻、文章、门户和普通内容站点。
- 每个站点打开首页及 2–5 个内容页，执行滚动、站内跳转、返回和新标签页操作。
- 每个页面停留约 10–60 秒；在站点之间保留自然停顿。
- 不使用自动刷新、爬虫或高并发标签页来凑容量。纯网页达到 1 GiB 可能需要较长时间，这是正常现象。
- 出现 `target reached` 后，让当前页面加载完成，关闭活动标签页并停止操作。
- 保持空闲，直到显示 `READY segment 5/5: other`。

### 10.6 Segment 5/5：其余真实行为

抓包参数使用：

```bash
--profile other
```

- 组合前四类没有覆盖的正常行为，例如小文件上传/下载、表单页面、搜索、文档预览、音频或其他获准的交互内容。
- 不登录私人账号，不提交敏感信息，不运行压测或爬虫。
- 让多个真实动作共同构成该段，不要再用单一大文件填满。
- 出现 `target reached` 后完成当前动作，关闭活动页面并保持空闲。
- 最后一份封尾后，命令会输出五个会话目录并正常退出。

以上百分比是操作边界，不要求精确到 1%。跨过边界时先完成当前动作，不要为了命中容量突然杀死浏览器或抓包。

这些是通过真实浏览器、真实代理实现和真实网络产生的数据，不是伪造 PCAP。但“真实”不等于“随便堆满容量”：行为过于单一仍会导致数据偏差。

## 11. 达到目标后的自动停止逻辑

终端 A 达到 1 GiB 后会显示：

```text
Segment 1/5 target reached. Finish the current workload; do not start the next workload yet.
```

看到该提示后：

1. 不要再打开新页面。
2. 不要开始新下载或新视频。
3. 当前下载可以正常完成。
4. 当前网页加载完成后停止操作。
5. 视频不会自然结束流量时，应在合适位置暂停或关闭当前视频。

达到目标后，程序按以下规则处理：

- 隧道流量连续 15 秒不高于 32 KiB/s：正常封尾当前 PCAP；还有后续段时立即启动下一份并显示 `READY`。
- 达到目标后继续等待了 300 秒仍未空闲：当前 PCAP 以 `target_reached_finish_timeout` 停止，同时终止整个连续序列，不启动下一份，避免把活动流切开。

加密后的 PCAP 无法直接理解“网页已经访问完成”这一业务语义，因此程序使用隧道吞吐空闲作为判断。最终 PCAP 通常会略大于 1 GiB，这是正常现象。

每一段封尾后，终端 A 会显示该段路径：

```text
Segment 1/5 stopped: target_reached_and_traffic_idle; final size 1.02 GiB
PCAP: /home/indole/proxy-lab-data/formal/.../capture.pcap
```

前四段封尾后不要关闭 Chromium；等待下一条 `READY segment N/5`，再开始对应类别。第五段封尾、命令正常退出后再关闭 Chromium。

如果需要提前停止，在终端 A 按一次 `Ctrl+C`。程序会正常封尾当前 PCAP，并停止整个连续序列；已经正常完成的前序 PCAP 保留，当前未达到 1 GiB 的文件不能计入合格样本。

中断文件仍保存在 WSL，不会自动删除。立即查找最近一份：

```bash
find "$HOME/proxy-lab-data" \
  -type f \
  -name capture.pcap \
  -printf '%T@ %s %p\n' |
sort -nr |
head -n 5
```

查看最近一次的停止原因：

```bash
LATEST_JSON="$(
  find "$HOME/proxy-lab-data" \
    -type f \
    -name capture.json \
    -printf '%T@ %p\n' |
  sort -nr |
  head -n 1 |
  cut -d' ' -f2-
)"

jq '.capture | {file_bytes, target_bytes, target_met, stop_reason, tcpdump_log}' \
  "$LATEST_JSON"
```

## 12. 第八步：验收刚完成的 PCAP

在终端 A 找到最新会话：

```bash
CASE_DIR="$HOME/proxy-lab-data/formal/class-05-vmess-websocket-tls"

CAPTURE_JSON="$(
  find "$CASE_DIR" -type f -name capture.json -printf '%T@ %p\n' |
  sort -nr |
  head -n 1 |
  cut -d' ' -f2-
)"

SESSION_DIR="$(dirname "$CAPTURE_JSON")"
PCAP="$SESSION_DIR/capture.pcap"

echo "session=$SESSION_DIR"
echo "pcap=$PCAP"
```

### 12.1 检查自动停止结果

```bash
jq '{
  series_id,
  segment_index,
  segment_count,
  capture: (.capture | {
    target_bytes,
    file_bytes,
    target_met,
    stop_reason,
    bpf,
    tcpdump_log
  })
}' "$CAPTURE_JSON"
```

应满足：

- `target_met` 为 `true`。
- `file_bytes` 不小于 `1073741824`。
- 前四段的 `stop_reason` 必须为 `target_reached_and_traffic_idle`，否则序列不会进入下一段。最后一段若是兜底超时，需要确认不是在活跃动作中被截断。
- `tcpdump_log` 中的 `packets dropped by kernel` 应为 0，或至少不能持续出现明显丢包。

### 12.2 检查大小和可读性

```bash
SIZE="$(stat -c %s "$PCAP")"

if [ "$SIZE" -ge 1073741824 ]; then
  echo "size check: PASSED ($SIZE bytes)"
else
  echo "size check: FAILED ($SIZE bytes)"
fi

capinfos "$PCAP"
```

`capinfos` 必须能够正常读取，包数必须大于 0。

### 12.3 检查是否只包含目标隧道

```bash
UNEXPECTED="$(
  tshark \
    -r "$PCAP" \
    -Y "not (ip.addr == $VPS_IP and tcp.port == 24443)" \
    -T fields \
    -e frame.number \
    -c 1
)"

if [ -z "$UNEXPECTED" ]; then
  echo "tunnel-only audit: PASSED"
else
  echo "tunnel-only audit: FAILED at frame $UNEXPECTED"
fi
```

### 12.4 查看外层 TCP 流数量

```bash
STREAMS="$(
  tshark \
    -r "$PCAP" \
    -Y 'tcp.port == 24443' \
    -T fields \
    -e tcp.stream |
  sed '/^$/d' |
  sort -nu |
  wc -l
)"

echo "outer TCP streams: $STREAMS"
```

流数量不是唯一质量标准。即使是大文件或视频段，也不建议让一个连接贡献几乎全部字节；其他 profile 更应包含多个真实连接。

### 12.5 生成完整性哈希

```bash
sha256sum "$PCAP" | tee "$SESSION_DIR/manifest.sha256"
```

验收完成前不要删除浏览器下载内容或会话记录以外的证据；确认 PCAP 合格后再整理临时下载文件。

## 13. 第九步：确认连续五份全部完成

连续模式按以下顺序执行：

1. 确认服务端健康。
2. 确认客户端健康并通过 curl 得到 HTTP 200。
3. 在终端 A 只启动一次带五个 `--profile` 的 `lab capture run`。
4. 在终端 B 只启动一次专用 Chromium。
5. 严格按照五条 `READY segment N/5` 提示切换行为类别。
6. 每段达到目标后完成当前动作并等待空闲轮转，不按 `Ctrl+C`。
7. 第五段封尾、抓包命令退出后关闭 Chromium。
8. 分别验收五个 PCAP 并生成 SHA-256。

每一段都会创建带时间和随机 ID 的独立目录，不会覆盖上一份；五份 `capture.json` 记录相同的 `series_id` 和各自的 `segment_index`。

列出本类别全部 PCAP：

```bash
CASE_DIR="$HOME/proxy-lab-data/formal/class-05-vmess-websocket-tls"

find "$CASE_DIR" \
  -type f \
  -name capture.pcap \
  -printf '%s %p\n' |
sort -n
```

统计达到 1 GiB 的文件：

```bash
QUALIFIED="$(
  find "$CASE_DIR" \
    -type f \
    -name capture.pcap \
    -size +1073741823c |
  wc -l
)"

echo "qualified PCAP count: $QUALIFIED / 5"
```

计算所有合格 PCAP 的总容量：

```bash
find "$CASE_DIR" \
  -type f \
  -name capture.pcap \
  -size +1073741823c \
  -printf '%s\n' |
awk '{sum += $1} END {printf "qualified total: %.3f GiB\n", sum / 1024 / 1024 / 1024}'
```

最低验收条件是：

- 合格 PCAP 数量至少 5。
- 每个 PCAP 至少 1 GiB。
- 合格 PCAP 总容量至少 5 GiB。
- 每个文件都能被 `capinfos` 读取。
- 每个文件都只包含指定服务器 IP 和端口的隧道包。
- 没有明显的内核抓包丢包。
- 五份样本的站点、行为顺序和流量侧重具有差异。

五份 1 GiB 只是最低数量要求，不自动代表数据足够用于训练。后续切分数据集时，同一 PCAP 派生的所有窗口必须放在同一个 train、validation 或 test 分区，不能跨分区，否则会产生数据泄漏。

## 14. 常见故障

### 14.1 抓包命令立即退出

重新执行：

```bash
sudo -v
lab capture run --help
```

确认 `tcpdump` 存在：

```bash
command -v tcpdump
```

### 14.2 专用 Chrome 被关闭或窗口不可见

不要尝试恢复旧的 WSLg Chromium，也不要执行 `wsl --shutdown`。重新执行第 9 节的 PowerShell 启动命令；脚本会关闭专用配置残留进程并创建新的 Windows 原生窗口。抓包正在运行时也可以这样恢复，当前 PCAP 不会被关闭。

### 14.3 Chrome 报 `ERR_PROXY_CONNECTION_FAILED`

检查：

```bash
lab client status
ss -lnt | grep '127.0.0.1:10808'
```

然后重新执行 SOCKS5 curl 测试。未得到 HTTP 200 时不要抓正式数据。

### 14.4 达到 1 GiB 后一直不自动停止

原因通常是视频仍在播放、下载仍在继续或页面持续产生流量。看到目标提示后暂停视频、等待当前下载完成，并停止新操作。

必要时可在下一份采集中把空闲等待改为 20 秒、阈值改为 64 KiB/s：

```bash
--idle-seconds 20 --idle-kib-per-second 64
```

阈值越高，越容易被认为已经空闲，但也更可能在低码率视频仍活动时停止。默认的 32 KiB/s 更保守。

### 14.5 手动提前停止后文件不足 1 GiB

该文件可以保留用于调试，但不能计入五份正式样本。不要把多个不完整 PCAP 直接拼接成一份来满足大小要求；应重新采集一份完整、独立的 PCAP。

### 14.6 切换公司和家庭网络

切换网络后重新确认：

- Windows VPN、TUN 和系统代理已关闭。
- 云防火墙或安全组规则允许当前公网出口 IP 访问实验端口。
- `ip route get "$VPS_IP"` 返回预期 WSL 网卡。
- SOCKS5 curl 测试返回 HTTP 200。

任何一项不满足，都不要继续正式采集。

### 14.7 新 segment 报 `sudo: a password is required`

这是旧版本在前几个 segment 耗时较长后 sudo 缓存过期导致的。已经显示 `target_reached_and_traffic_idle` 的 PCAP 有效，不需要重采；报错 segment 的空文件或不足目标文件不能计入正式样本。

先确认已经使用包含 sudo 自动续期修复的最新代码，然后重新授权，只启动尚未完成的 profile。例如前两份已完成而第三份启动失败时：

```bash
cd ~/proxy-traffic-lab
. .venv/bin/activate
export VPS_IP="YOUR_SERVER_IP"

sudo -v

lab capture run \
  --case class-05-vmess-websocket-tls \
  --server-ip "$VPS_IP" \
  --server-port 24443 \
  --target-gib 1 \
  --profile images-resources \
  --profile web-news \
  --profile other \
  --progress-interval 5 \
  --idle-seconds 15 \
  --idle-kib-per-second 32 \
  --finish-timeout 300
```

这三份会获得新的 `series_id`；前两份仍保留原 `series_id`。后续做训练、验证、测试切分时，以 `series_id` 为组整体切分即可，不要把同一系列拆到不同分区。
