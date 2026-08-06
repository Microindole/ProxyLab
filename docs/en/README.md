# Proxy Traffic Lab

Proxy Traffic Lab is a controlled traffic-capture workspace for learning,
research, and model evaluation. It focuses on repeatable packet capture,
metadata, sample quality checks, and dataset preparation.

It is not a public proxy deployment guide and must not be used to provide
shared access, bypass network controls, or collect traffic from systems without
authorization.

Chinese documentation: [中文文档](../zh/README.md)

## Scope

The project currently covers two capture workflows:

- Plain website traffic: Windows browser traffic captured with
  Wireshark/Npcap `dumpcap`, including mixed IPv4/IPv6 website, AI-chat, and
  video samples.
- Authorized tunnel-shape experiments: outer tunnel traffic between a local
  capture client and a controlled test server, using existing open-source
  protocol implementations.

Protocol implementations are provided by existing software. This project does
not implement proxy protocols.

## Safety and data handling

Use this project only when all of the following are true:

- You own or are explicitly authorized to test the devices, accounts, networks,
  and servers involved.
- The accessed content is public or test content that you are allowed to use.
- You are not performing high-concurrency crawling, stress testing, CAPTCHA
  bypass, abnormal downloading, or access-control circumvention.
- Raw PCAPs, credentials, private keys, tokens, UUIDs, and real public IP
  addresses are not committed to Git.

Raw packet captures may contain personal data, device identifiers, DNS names,
IP addresses, timestamps, and service metadata. Share extracted features or
sanitized data instead of raw PCAPs whenever possible.

## Documents

- [Plain website capture](../zh/plain-capture.md)
- [Tunnel experiment capture](../zh/proxy-capture.md)
- [Legacy size-based capture](../zh/legacy-size-capture.md)

The maintained operational runbooks are currently written in Chinese because
the active capture environment is Windows/WSL based.
