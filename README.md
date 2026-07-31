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
cp .env.example .env
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

