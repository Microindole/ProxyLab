# 从 0 构建与开发环境

本项目使用 `uv` 管理 Python。电脑不需要预装 Python，也不需要 Windows 的 `py`
启动器；`uv` 会下载项目指定的 Python 3.12，并只在 `.venv` 中使用它。以后其他项目需要
不同 Python 版本时仍由 `uv` 管理，不必反复安装、卸载系统 Python。

## Windows PowerShell 从 0 安装

### 1. 安装 Git 和 uv

Windows 10/11 可在普通 PowerShell 中运行：

```powershell
winget install --exact --id Git.Git
winget install --exact --id astral-sh.uv
```

关闭并重新打开 PowerShell，然后确认命令可用：

```powershell
git --version
uv --version
```

如果已经拿到源码压缩包，可直接进入源码目录；使用 Git 时执行：

```powershell
git clone <仓库地址> ProxyLab
cd ProxyLab
```

### 2. 创建项目环境

以下命令会自动下载 Python 3.12，不依赖 `python` 或 `py`：

```powershell
uv python install 3.12
uv venv --python 3.12 .venv
uv pip install --python .\.venv\Scripts\python.exe -e ".[dev]"
```

激活环境不是必须的。直接使用完整路径验证最可靠：

```powershell
.\.venv\Scripts\lab.exe config validate
.\.venv\Scripts\lab.exe matrix list
.\.venv\Scripts\lab.exe doctor --no-network
.\.venv\Scripts\python.exe -m pytest -q
```

如需激活后使用简短的 `lab`、`pytest` 命令：

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\.venv\Scripts\Activate.ps1
```

`Set-ExecutionPolicy -Scope Process` 只影响当前 PowerShell 窗口。

### 3. Windows 抓包依赖

Windows 普通流量采集需要 Wireshark 和 Npcap。安装 Wireshark 时同时安装 Npcap，随后
确认 `dumpcap.exe` 位于 `PATH`：

```powershell
where.exe dumpcap.exe
lab cap win6 -l
```

若 Wireshark 安装在自定义目录，可仅为当前窗口添加：

```powershell
$env:Path = "E:\Wireshark;$env:Path"
```

## WSL/Ubuntu 从 0 安装

WSL 中不使用 Windows 的 Python 环境。先安装基础工具和 `uv`：

```bash
sudo apt update
sudo apt install -y git curl make
curl -LsSf https://astral.sh/uv/install.sh | sh
source "$HOME/.local/bin/env"
uv --version
```

进入 WSL 中可访问的项目目录，然后安装：

```bash
cd ~/ProxyLab
uv python install 3.12
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -e '.[dev]'
```

验证：

```bash
.venv/bin/lab config validate
.venv/bin/lab matrix list
.venv/bin/lab doctor --no-network
.venv/bin/python -m pytest -q
```

也可以运行 `make install` 完成三个 `uv` 安装步骤。代理服务端或本地容器生命周期命令
还需要 Docker；仅验证 YAML、运行单元测试时不需要 Docker。

## 修改代码后的本地验证

```powershell
.\.venv\Scripts\python.exe -m compileall -q src tests
.\.venv\Scripts\python.exe -m pytest -q
.\scripts\tools\normalize-lf.ps1 -Check
```

修改 CLI 后再检查帮助和短别名：

```powershell
.\.venv\Scripts\lab.exe --help
.\.venv\Scripts\lab.exe cfg v
.\.venv\Scripts\lab.exe cap win6 --help
```

## 当前脚本目录

```text
scripts/
├── browser/   代理隧道采集时启动浏览器
├── pcap/      PCAP 审计和过滤辅助脚本
├── tools/     仓库维护和格式检查
└── windows/   Windows 抓包、浏览器启动、网络隔离和滚动辅助
```

Python 代码会引用部分 Windows 脚本；重命名或移动脚本时，需要同步修改对应代码。
