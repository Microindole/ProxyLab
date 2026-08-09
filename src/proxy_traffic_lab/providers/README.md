# Provider boundary

A provider represents an upstream executable/core, not a wire protocol.
ProxyLab renders that core's native configuration and manages its process; it
does not implement proxy protocols.

Current mapping:

| Provider | Upstream core | Dataset cases |
| --- | --- | --- |
| `xray` | Xray-core | Shadowsocks 2022 (1/2), VMess (5/6), VLESS (7/8), Trojan (9/10) |
| `shadowsocksr_native` | ShadowsocksR-native | SSR (3/4) |
| `hysteria2` | Hysteria 2 | Hysteria 2 (11/12) |

Shadowsocks, VMess, VLESS and Trojan are therefore sibling case modules inside
the Xray provider. ShadowsocksR-native and Hysteria 2 are separate providers
because they are separate upstream executables.
