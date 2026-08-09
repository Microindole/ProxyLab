from __future__ import annotations

from proxy_traffic_lab.cli.commands.common import case_from_args
from proxy_traffic_lab.cli.commands.registry import COMMANDS
from proxy_traffic_lab.configuration.loader import load_lab_config, project_root
from proxy_traffic_lab.kernels.hysteria2 import lock_official_image as lock_hysteria2_image
from proxy_traffic_lab.kernels.shadowsocksr import build_pinned_image as build_ssr_image
from proxy_traffic_lab.lifecycle.hysteria2 import (
    render_endpoints as render_hysteria2_endpoints,
    validate_generated_configs as validate_hysteria2_configs,
)
from proxy_traffic_lab.lifecycle.shadowsocksr import (
    render_endpoints as render_ssr_endpoints,
    validate_generated_configs as validate_ssr_configs,
)
from proxy_traffic_lab.lifecycle.shadowsocksr_documents import (
    create_identity as create_ssr_identity,
)
from proxy_traffic_lab.encryptions.credentials import create_tls_material
from proxy_traffic_lab.kernels.xray import lock_official_image as lock_xray_image
from proxy_traffic_lab.lifecycle.xray.service import render_endpoints as render_xray_endpoints
from proxy_traffic_lab.lifecycle.xray.validation import validate_server_config_with_container


def register_parser(subcommands) -> None:
    _register_xray(subcommands)
    _register_hysteria2(subcommands)
    _register_ssr(subcommands)


def _add_render_args(parser) -> None:
    parser.add_argument("--case", required=True, help="case id from the target matrix")
    parser.add_argument("--server-address", required=True)
    parser.add_argument("--server-port", type=int, required=True)
    parser.add_argument("--socks-port", type=int, default=10808)


def _add_tls_init_args(parser) -> None:
    parser.add_argument("--server-name", default="lab.invalid")
    parser.add_argument("--validity-days", type=int, default=30)


def _register_xray(subcommands) -> None:
    parser = subcommands.add_parser("xray", help="Xray-core adapter operations")
    nested = parser.add_subparsers(dest="xray_command", required=True)
    nested.add_parser("lock-image")
    _add_tls_init_args(nested.add_parser("init-secrets"))
    _add_render_args(nested.add_parser("render"))
    nested.add_parser("validate")


def _register_hysteria2(subcommands) -> None:
    parser = subcommands.add_parser("hysteria2", help="Hysteria2 adapter operations")
    nested = parser.add_subparsers(dest="hysteria2_command", required=True)
    nested.add_parser("lock-image")
    _add_tls_init_args(nested.add_parser("init-secrets"))
    _add_render_args(nested.add_parser("render"))
    nested.add_parser("validate")


def _register_ssr(subcommands) -> None:
    parser = subcommands.add_parser("shadowsocksr", help="SSR-native adapter operations")
    nested = parser.add_subparsers(dest="shadowsocksr_command", required=True)
    nested.add_parser("build-image")
    nested.add_parser("init-secrets")
    _add_render_args(nested.add_parser("render"))
    nested.add_parser("validate")


@COMMANDS.handler("xray", "lock-image")
def xray_lock(_args) -> int:
    image = lock_xray_image(project_root() / "configs" / "locks" / "xray.json")
    print(f"Locked official image: {image}")
    return 0


@COMMANDS.handler("xray", "init-secrets")
def xray_init(args) -> int:
    material = create_tls_material(
        project_root() / "secrets" / "xray",
        server_name=args.server_name,
        validity_days=args.validity_days,
    )
    print(f"Created ignored Xray credentials; certificate_sha256={material.certificate_sha256}")
    return 0


@COMMANDS.handler("xray", "render")
def xray_render(args) -> int:
    case = case_from_args(args)
    root = project_root()
    render_xray_endpoints(
        root,
        case,
        server_address=args.server_address,
        server_port=args.server_port,
        socks_port=args.socks_port,
    )
    print(f"Rendered ignored Xray configs; case={case.id}")
    return 0


@COMMANDS.handler("xray", "validate")
def xray_validate(_args) -> int:
    print(validate_server_config_with_container(project_root()))
    return 0


@COMMANDS.handler("hysteria2", "lock-image")
def hysteria_lock(_args) -> int:
    image = lock_hysteria2_image(project_root() / "configs" / "locks" / "hysteria2.json")
    print(f"Locked official Hysteria2 image: {image}")
    return 0


@COMMANDS.handler("hysteria2", "init-secrets")
def hysteria_init(args) -> int:
    material = create_tls_material(
        project_root() / "secrets" / "hysteria2",
        server_name=args.server_name,
        validity_days=args.validity_days,
    )
    print(f"Created ignored Hysteria2 credentials; certificate_sha256={material.certificate_sha256}")
    return 0


@COMMANDS.handler("hysteria2", "render")
def hysteria_render(args) -> int:
    case = case_from_args(args)
    root = project_root()
    config = load_lab_config(args.lab_config)
    server, client = render_hysteria2_endpoints(
        root,
        case,
        server_address=args.server_address,
        server_port=args.server_port,
        socks_port=args.socks_port,
        bandwidth_mbps=config.limits.max_bandwidth_mbps,
    )
    print(f"Rendered ignored Hysteria2 configs; case={case.id}; server={server.name}; client={client.name}")
    return 0


@COMMANDS.handler("hysteria2", "validate")
def hysteria_validate(_args) -> int:
    print(validate_hysteria2_configs(project_root()))
    return 0


@COMMANDS.handler("shadowsocksr", "build-image")
def ssr_build(_args) -> int:
    print(f"Built source-pinned ShadowsocksR-native image: {build_ssr_image(project_root())}")
    return 0


@COMMANDS.handler("shadowsocksr", "init-secrets")
def ssr_init(_args) -> int:
    create_ssr_identity(project_root() / "secrets" / "shadowsocksr-native")
    print("Created ignored ShadowsocksR credentials")
    return 0


@COMMANDS.handler("shadowsocksr", "render")
def ssr_render(args) -> int:
    case = case_from_args(args)
    root = project_root()
    server, client = render_ssr_endpoints(
        root,
        case,
        server_address=args.server_address,
        server_port=args.server_port,
        socks_port=args.socks_port,
    )
    print(f"Rendered ignored SSR configs; case={case.id}; server={server.name}; client={client.name}")
    return 0


@COMMANDS.handler("shadowsocksr", "validate")
def ssr_validate(_args) -> int:
    print(validate_ssr_configs(project_root()))
    return 0



