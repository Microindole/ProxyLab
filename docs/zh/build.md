# 从 0 构建与开发环境

本文说明如何从一份干净源码开始安装、验证和开发 Proxy Traffic Lab。

## Windows PowerShell 从 0 安装

进入项目目录：

```powershell
cd D:\ProxyLab
```

创建虚拟环境：

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
```

安装项目和开发依赖：

```powershell
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

验证命令：

```powershell
lab config validate
lab matrix list
lab doctor --no-network
pytest -q
```

如果要采集 Windows 普通网站流量，还需要安装 Wireshark 和 Npcap，并确认 `dumpcap.exe` 可用：

```powershell
lab capture windows-ipv6 --list-interfaces
```

## WSL/Ubuntu 从 0 安装

进入项目目录：

```bash
cd ~/proxy-traffic-lab
```

方式一，使用 Makefile：

```bash
make install
make validate
make test
```

方式二，手动命令：

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
lab config validate
lab matrix list
lab doctor --no-network
pytest -q
```

## 修改代码后的本地验证

每次修改 Python 代码后，至少运行：

```powershell
python -m py_compile src\proxy_traffic_lab\controller\cli.py
pytest -q
```

如果修改了 Windows 普通采集命令，再额外检查：

```powershell
lab capture windows-ipv6 --help
```

如果修改了脚本路径，检查旧脚本名是否还残留：

```powershell
Select-String -Path src\proxy_traffic_lab\**\*.py,docs\**\*.md -Pattern "capture_win_ipv6|launch_win_capture_browser|isolate_chrome_network"
```

## 当前脚本目录

脚本按用途放在 `scripts/` 下：

```text
scripts/
  browser/   # 代理隧道采集时启动浏览器
  pcap/      # PCAP 审计和过滤辅助脚本
  windows/   # Windows 普通流量采集、浏览器启动、网络隔离和滚动辅助
```

Python 代码会引用部分 Windows 脚本；重命名或移动脚本时，必须同步更新对应 Python 引用和文档。
