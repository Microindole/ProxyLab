# 正式 PCAP 采集操作手册（WSL 客户端 + 阿里云服务器）

## 1. 本手册的适用范围

本手册用于采集代理客户端与阿里云代理服务器之间的真实隧道流量。当前已经端到端验证、可以正式采集的是：

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

不是保存在阿里云服务器。Windows 可以通过下面的位置查看，但正式抓包期间不要移动或修改正在增长的文件：

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

- 终端 S：阿里云服务器终端，只负责服务端。
- 终端 A：WSL 抓包终端，前台运行 `lab capture run`。
- 终端 B：WSL Chromium 终端，启动显示在 Windows 桌面的 WSLg Chromium。

不需要在 WSL 命令里反复套 `ssh`。只有复制新客户端配置时才需要 `scp`。

建议同时关闭普通 Windows Chrome、Edge 等无关浏览器，避免误操作和带宽竞争。

## 4. 第一步：检查阿里云服务端

在“终端 S（阿里云服务器）”执行：

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

阿里云安全组只应允许当前采集客户端的公网 IP/CIDR 访问 TCP `24443`，不要为了方便向全网永久开放。家庭和公司的公网出口 IP 可能不同，切换网络后应更新安全组来源地址。

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

设置阿里云公网 IP：

```bash
export VPS_IP="47.103.159.9"
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

同时在阿里云“终端 S”检查：

```bash
lab server logs --tail 100
```

## 7. 第四步：确认 WSLg 和 Chromium

在“终端 B（WSL）”执行：

```bash
cd ~/proxy-traffic-lab
. .venv/bin/activate

echo "DISPLAY=$DISPLAY"
echo "WAYLAND_DISPLAY=$WAYLAND_DISPLAY"
ls -ld /mnt/wslg
```

`DISPLAY` 或 `WAYLAND_DISPLAY` 应有值，并且 `/mnt/wslg` 应存在。如果没有，在 Windows PowerShell 执行：

```powershell
wsl --shutdown
```

然后重新打开 Ubuntu，再继续本手册。执行 `wsl --shutdown` 前必须先停止正在进行的抓包。

检查 Playwright 和浏览器：

```bash
export PLAYWRIGHT_BROWSERS_PATH="$HOME/.cache/ms-playwright"

python -c 'from playwright.sync_api import sync_playwright; print("Playwright: OK")'
python -m playwright install --list
```

如果第一条出现 `ModuleNotFoundError`，使用已有离线 wheel 安装：

```bash
python -m pip install \
  --no-index \
  --find-links "$HOME/playwright-wheelhouse" \
  playwright
```

本手册要求使用 WSL 中由 Playwright 启动的 Chromium。窗口会通过 WSLg 显示在 Windows 桌面，但浏览器进程和代理配置属于 WSL。不要用普通 Windows Chrome 替代。

## 8. 第五步：开始一份 1 GiB 正式抓包

回到“终端 A（WSL）”。先刷新 sudo 凭据；抓包命令内部使用非交互 sudo，如果这里没有成功授权，抓包会立即退出：

```bash
cd ~/proxy-traffic-lab
. .venv/bin/activate
export VPS_IP="47.103.159.9"

sudo -v
```

启动抓包：

```bash
lab capture run \
  --case class-05-vmess-websocket-tls \
  --server-ip "$VPS_IP" \
  --server-port 24443 \
  --target-gib 1 \
  --profile mixed \
  --progress-interval 5 \
  --idle-seconds 15 \
  --idle-kib-per-second 32 \
  --finish-timeout 300
```

看到下面两类信息才表示抓包已经开始：

```text
Capturing class-05-vmess-websocket-tls on eth0 to .../capture.pcap
Target: 1.00 GiB
```

以及持续更新的进度：

```text
[04:30:00Z] 256.20 MiB / 1.00 GiB (25.0%), current rate 2.31 MiB/s
```

这个终端必须保持前台运行。不要再在终端 A 输入其他命令。

## 9. 第六步：启动专用 Chromium

确认终端 A 已经显示抓包进度后，在“终端 B（WSL）”执行：

```bash
cd ~/proxy-traffic-lab
. .venv/bin/activate

unset HTTP_PROXY HTTPS_PROXY ALL_PROXY
unset http_proxy https_proxy all_proxy
export PLAYWRIGHT_BROWSERS_PATH="$HOME/.cache/ms-playwright"

python - <<'PY'
from playwright.sync_api import Error, sync_playwright

with sync_playwright() as p:
    browser = p.chromium.launch(
        channel="chromium",
        headless=False,
        args=[
            "--disable-quic",
            "--disable-background-networking",
            "--disable-component-update",
            "--disable-sync",
            "--no-first-run",
        ],
    )

    context = browser.new_context(
        proxy={"server": "socks5://127.0.0.1:10808"},
        accept_downloads=True,
        viewport={"width": 1366, "height": 768},
        locale="zh-CN",
    )

    page = context.new_page()
    page.goto(
        "https://example.com/",
        wait_until="domcontentloaded",
        timeout=30000,
    )

    print("专用 Chromium 已启动，并通过 127.0.0.1:10808 访问。")
    print("请在浏览器窗口中手动操作；完成后直接关闭浏览器窗口。")

    try:
        while True:
            page.wait_for_timeout(1000)
    except KeyboardInterrupt:
        print("收到 Ctrl+C，正在关闭 Chromium。")
    except Error:
        print("Chromium 窗口已经关闭。")
    finally:
        if browser.is_connected():
            browser.close()
PY
```

必须保留 `--disable-quic`。当前第 5 类的内层网页流量应走 TCP，避免 Chromium 使用普通 QUIC/HTTP3 后因为 SOCKS5 UDP 支持差异导致流量绕行或失败。以后采集 UDP 类别和 Hysteria2 时必须使用适合相应类别的客户端与流量方案，不能照搬此参数组合。

## 10. 第七步：在 Chromium 中进行真实访问

不要只循环访问 `example.com`，也不要只下载一个 1 GiB 文件。建议在一份 mixed PCAP 中组合以下行为：

1. 浏览 5–10 个获准访问的真实站点。
2. 打开首页、文章页、图片页，在页面内滚动、点击、返回和切换标签页。
3. 下载多个不同大小的合法公开文件，例如 10–100 MiB；部分完成，部分正常取消后稍后重试。
4. 播放允许访问的公开视频，每段约 3–10 分钟，包含暂停、继续和拖动进度。
5. 在不同动作之间保留数秒到几十秒的自然停顿。
6. 让网页、小文件、较大下载和视频共同构成 PCAP，不要让单一长连接占据几乎全部字节。

推荐把同一类别的五份 PCAP 做成不同侧重：

| PCAP | 建议侧重 | 仍需包含的其他行为 |
|---|---|---|
| 1 | 普通网页、图片、脚本 | 少量下载和短视频 |
| 2 | 视频播放、暂停、拖动 | 多站点网页和小文件 |
| 3 | 不同大小的下载、取消、重试 | 网页和短视频 |
| 4 | 网页、下载、视频较均衡 | 自然空闲间隔 |
| 5 | 不同站点、不同时间段的混合行为 | 与前四份不同的访问顺序 |

这些是通过真实浏览器、真实代理实现和真实网络产生的数据，不是伪造 PCAP。但“真实”不等于“随便堆满容量”：行为过于单一仍会导致数据偏差。

## 11. 达到目标后的自动停止逻辑

终端 A 达到 1 GiB 后会显示：

```text
Target reached. Finish the current visit/download/video action; do not start another one.
```

看到该提示后：

1. 不要再打开新页面。
2. 不要开始新下载或新视频。
3. 当前下载可以正常完成。
4. 当前网页加载完成后停止操作。
5. 视频不会自然结束流量时，应在合适位置暂停或关闭当前视频。

达到目标后，程序在以下任一条件满足时停止：

- 隧道流量连续 15 秒不高于 32 KiB/s；停止原因是 `target_reached_and_traffic_idle`。
- 达到目标后继续等待了 300 秒；停止原因是 `target_reached_finish_timeout`。

加密后的 PCAP 无法直接理解“网页已经访问完成”这一业务语义，因此程序使用隧道吞吐空闲作为判断。最终 PCAP 通常会略大于 1 GiB，这是正常现象。

抓包停止后，终端 A 会显示最终路径：

```text
Capture stopped: target_reached_and_traffic_idle; final size 1.02 GiB
PCAP: /home/indole/proxy-lab-data/formal/.../capture.pcap
```

抓包停止后再关闭专用 Chromium。不要继续使用已经停止记录的浏览器会话作为下一份 PCAP；下一份应重新启动 Chromium，以获得独立的浏览器上下文。

如果需要提前停止，在终端 A 按一次 `Ctrl+C`。程序仍会正常封尾 PCAP，但未达到 1 GiB 的文件不能计入五份合格样本。

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
jq '.capture | {
  target_bytes,
  file_bytes,
  target_met,
  stop_reason,
  bpf,
  tcpdump_log
}' "$CAPTURE_JSON"
```

应满足：

- `target_met` 为 `true`。
- `file_bytes` 不小于 `1073741824`。
- `stop_reason` 通常为 `target_reached_and_traffic_idle`；兜底超时也可接受，但需要确认不是在活跃下载中被截断。
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
    -Y "not (ip.addr == $VPS_IP && tcp.port == 24443)" \
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

流数量不是唯一质量标准，但 mixed 样本只有一个长连接通常说明行为过于单一，应重新采集更丰富的访问组合。

### 12.5 生成完整性哈希

```bash
sha256sum "$PCAP" | tee "$SESSION_DIR/manifest.sha256"
```

验收完成前不要删除浏览器下载内容或会话记录以外的证据；确认 PCAP 合格后再整理临时下载文件。

## 13. 第九步：重复采集到五份

每份 PCAP 都按以下顺序执行：

1. 确认服务端健康。
2. 确认客户端健康并通过 curl 得到 HTTP 200。
3. 在终端 A 启动新的 `lab capture run`。
4. 在终端 B 启动一个新的专用 Chromium 上下文。
5. 执行与上一份不同侧重的真实访问行为。
6. 达到目标后完成当前动作并等待自动停止。
7. 关闭 Chromium。
8. 运行全部验收命令并生成 SHA-256。

每次 `lab capture run` 都会创建带时间和随机 ID 的新目录，不会覆盖上一份。

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

### 14.2 Chromium 一闪而过

不要在 heredoc 脚本中使用 `input()`；脚本本身已经从标准输入读取，`input()` 会立即遇到 EOF。本手册的 Chromium 脚本通过循环保持运行，关闭窗口或按 `Ctrl+C` 才结束。

### 14.3 Chromium 报 `ERR_PROXY_CONNECTION_FAILED`

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
- 阿里云安全组允许当前公网出口 IP 访问 TCP 24443。
- `ip route get "$VPS_IP"` 返回预期 WSL 网卡。
- SOCKS5 curl 测试返回 HTTP 200。

任何一项不满足，都不要继续正式采集。
