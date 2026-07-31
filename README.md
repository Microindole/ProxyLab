# Proxy Traffic Lab

An authorized, reproducible pipeline for collecting encrypted proxy-tunnel
traffic. The first milestone supports one controlled case:
`VLESS + TCP + TLS`.

This repository is not a public proxy deployment kit. Run it only on systems
and networks you own or are explicitly authorized to test. Proxy ports must be
restricted to the capture client's source IP. Never commit credentials,
private keys, UUIDs, tokens, public IP addresses, or packet captures.

## Current milestone

- Typed YAML configuration
- `lab doctor` host diagnostics
- Conservative limits suitable for a 2-core / 4-GiB server
- Protocol-matrix validation for the MVP case
- Extension points for providers, isolation, capture, traffic, and datasets

## Ubuntu bootstrap

```bash
sudo apt update
sudo apt install -y python3 python3-venv git make iproute2 nftables \
  tcpdump tshark curl jq openssl

cd /root/proxy-traffic-lab
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
cp --update=none .env.example .env
lab doctor
pytest
```

Docker is checked by `lab doctor`, but this repository intentionally does not
use an untrusted one-line Docker or proxy installer.

## Configuration

The checked-in files contain placeholders and non-secret defaults. Put secrets
under `secrets/` or inject them through the environment. The entire `secrets/`
directory is ignored by Git.

```bash
lab config validate
lab matrix list
lab doctor --json
```

## MVP-1 Xray preparation

The selected baseline is the official `ghcr.io/xtls/xray-core` image at the
stable `v26.2.6` release (GHCR tag `26.2.6`). The first command resolves that tag to an immutable
repository digest and stores the result in `configs/locks/xray.json`.

```bash
lab xray lock-image
lab xray init-secrets --server-name lab.invalid --validity-days 30
lab xray render --server-address YOUR_VPS_PUBLIC_IP --server-port 24443
lab xray validate
lab server start
lab server status
lab server logs --tail 100
lab server stop
```

All generated credentials and client/server configurations are under the
Git-ignored `secrets/` directory. The short-lived self-signed certificate is
verified by certificate SHA-256 pinning; generated client configuration never
sets `allowInsecure`.

Do not open port `24443` until the cloud security group limits its source to
the capture client's public `/32`. The port will be made configurable and
rotated across later dataset groups.

`lab server start` is idempotent and re-validates both generated configurations
before starting. The server runs read-only with all Linux capabilities dropped,
no privilege escalation, one CPU, 512 MiB memory, and a 128-process limit.
