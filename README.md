# 代理流量实验室

本项目用于在受控、授权的环境中采集网络流量样本，服务于学习、研究和模型评估。项目关注的是数据采集流程、样本元数据、质量检查和可复现实验记录；不是公共代理部署工具，也不提供规避访问控制的使用指导。

## 使用边界

使用本项目时必须满足以下条件：

- 只在你拥有、管理或明确获准测试的设备、账号、网络和服务器上运行。
- 只采集你有权访问的公开内容或测试内容，不采集私人消息、密码、Cookie、账号令牌或敏感业务数据。
- 不对第三方网站进行高并发请求、自动化爬取、验证码绕过、压力测试或异常下载。
- 不将本项目用于提供公共代理、共享出口、绕过网络管理或规避访问控制。
- 不提交密钥、证书私钥、UUID、访问令牌、真实公网 IP、PCAP 或其他原始采集数据。

如不确定某个采集场景是否获得授权，应先停止采集并确认权限。

## 文档导航

- [从 0 构建与开发环境](docs/zh/build.md)：Windows/WSL 安装、验证、Makefile 用途和脚本目录说明。
- [项目架构](docs/zh/architecture.md)：源码层次、职责边界、YAML 目标矩阵与组合校验。
- [普通网站采集](docs/zh/plain-capture.md)：Windows 普通网页、AI 聊天和视频流量采集流程。
- [代理隧道采集](docs/zh/proxy-capture.md)：TCP 类别与 Hysteria 2/QUIC 类别的实验流量采集流程。
- [历史容量分段流程](docs/zh/legacy-size-capture.md)：旧的按文件大小分段流程，仅作历史参考。
- [中文文档索引](docs/zh/README.md)：中文文档入口。
- [English documentation](docs/en/README.md)：英文说明。

## 快速检查

```bash
python -m pip install -e '.[dev]'
lab config validate
lab matrix list
lab matrix compose --protocol vmess --transport websocket --encryption tls \
  --outer-transport tcp --client-core xray-core --server-core xray-core
lab doctor --no-network
pytest
```

Windows 普通流量采集前，先确认 Wireshark/Npcap 和 `dumpcap.exe` 可用：

```powershell
lab capture windows-ipv6 --list-interfaces
```

## 数据管理原则

原始 PCAP 可能包含个人信息、设备标识、访问域名、IP 地址和时间戳。建议：

- 原始数据只保存在本地受控目录或专用数据盘。
- 每份 PCAP 保留对应的 `capture.json` 元数据。
- 对外共享前先做脱敏、过滤或只共享提取后的特征。
- 训练集标签、采集口径和过滤规则应和 PCAP 一起记录。

## 许可、引用和数据产物

本项目源代码采用 [MPL-2.0](LICENSE)。

- 如果在研究、报告、数据集、工具链或派生项目中使用本项目，请在合适位置说明使用了 ProxyLab。
- 如果分发修改后的项目源代码，包括环境适配、问题修复、新协议形态、采集逻辑或体验改进，应按 MPL-2.0 公开对应修改文件的源代码。
- 使用本项目采集得到的 PCAP、特征 CSV、训练模型、评估报告和数据集属于运行者的数据产物，不会因为使用本项目而自动受 MPL-2.0 约束。是否公开、如何授权由数据产物持有人自行决定，但仍需遵守法律、授权、隐私和数据来源限制。

引用信息见 [CITATION](CITATION.cff)。

## 开发状态

本项目仍在实验阶段。采集口径会随任务目标调整，例如普通文本流量和视频流量的流数统计定义不同。正式使用某批数据前，应先用 Wireshark/tshark 或项目审计脚本复核样本数量、协议分布和背景噪声。
