# 命令行短别名

所有原有长命令继续可用。短别名只用于输入，程序内部会归一成原命令，因此不会产生两套
处理逻辑。

## 命令别名

| 长命令 | 短命令 |
| --- | --- |
| `doctor` | `d` |
| `config validate` | `cfg v` |
| `matrix list` | `mx ls` |
| `matrix compose` | `mx cmp` |
| `xray` | `xr` |
| `hysteria2` | `hy2` |
| `shadowsocksr` | `ssr` |
| `server start/status/logs/stop` | `srv up/st/log/down` |
| `client start/status/logs/stop` | `cli up/st/log/down` |
| `capture run` | `cap r` |
| `capture windows-ipv6` | `cap win6` |
| `experiment web` | `exp w` |
| `experiment udp` | `exp u` |
| `dataset audit` | `ds a` |

内核子命令也支持：`lock-image -> lock`、`build-image -> build`、
`init-secrets -> init`、`render -> r`、`validate -> v`。

## 高频参数

| 短参数 | 长参数 | 用途 |
| --- | --- | --- |
| `-c` | `--case` | 目标 case ID |
| `-a` | `--server-address` / `--server-ip` | 服务端地址 |
| `-p` | `--server-port` | 服务端端口 |
| `-s` | `--socks-port` | 本地 SOCKS 端口 |
| `-k` | `--core` | 指定上游内核 |
| `-i` | `--interface` | 抓包接口 |
| `-P` | `--profile` | 流量 profile，可重复 |
| `-n` | `--target-flows` 或日志 `--tail` | 当前命令中的数量参数 |
| `-o` | `--output` / `--output-root` | 当前命令中的输出路径 |

示例：

```powershell
lab cfg v
lab mx ls
lab xr r -c class-05-vmess-websocket-tls -a 203.0.113.10 -p 443
lab srv up -c class-05-vmess-websocket-tls
lab cap r -c class-05-vmess-websocket-tls -a 203.0.113.10 -p 443 -n 3000
lab cap win6 -l
lab exp u -c class-02-shadowsocks-2022-udp -a 203.0.113.10 -p 24443 \
  -H 198.51.100.20 -P 19000 -n 20
lab ds a /data/session -a 203.0.113.10
```

每个子命令的短参数以 `lab <命令> --help` 显示为准。
