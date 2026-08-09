from proxy_traffic_lab.cli.app import build_parser


def test_config_aliases_are_canonicalized() -> None:
    args = build_parser().parse_args(["cfg", "v"])
    assert (args.command, args.config_command) == ("config", "validate")


def test_capture_aliases_and_short_options_are_canonicalized() -> None:
    args = build_parser().parse_args(
        ["cap", "r", "-c", "case-05", "-a", "203.0.113.10", "-p", "443", "-n", "20"]
    )
    assert (args.command, args.capture_command) == ("capture", "run")
    assert args.case == "case-05"
    assert args.server_ip == "203.0.113.10"
    assert args.server_port == 443
    assert args.target_flows == 20


def test_windows_capture_alias_is_canonicalized() -> None:
    args = build_parser().parse_args(["cap", "win6", "-l"])
    assert (args.command, args.capture_command) == ("capture", "windows-ipv6")
    assert args.list_interfaces is True


def test_kernel_and_lifecycle_aliases_are_canonicalized() -> None:
    render = build_parser().parse_args(
        ["xr", "r", "-c", "case-05", "-a", "203.0.113.10", "-p", "443"]
    )
    status = build_parser().parse_args(["srv", "st", "-k", "xray-core"])
    assert (render.command, render.xray_command) == ("xray", "render")
    assert (status.command, status.server_command) == ("server", "status")
