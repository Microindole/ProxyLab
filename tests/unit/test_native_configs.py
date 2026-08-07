from proxy_traffic_lab.providers.native_configs import render_native_case


def test_class_01_renders_shadowsocks_2022_tcp() -> None:
    rendered = render_native_case(
        "class-01-shadowsocks-2022-tcp",
        server_address="203.0.113.10",
        server_port=24443,
        seed="seed",
    )
    server = rendered["server"]
    client = rendered["client"]
    assert server["implementation"] == "shadowsocks-rust"
    assert server["method"] == "2022-blake3-aes-128-gcm"
    assert server["mode"] == "tcp_only"
    assert client["implementation"] == "sing-box"
    assert client["outbounds"][0]["network"] == "tcp"


def test_class_02_renders_shadowsocks_2022_udp() -> None:
    rendered = render_native_case(
        "class-02-shadowsocks-2022-udp",
        server_address="203.0.113.10",
        server_port=24443,
        seed="seed",
    )
    server = rendered["server"]
    client = rendered["client"]
    assert server["mode"] == "udp_only"
    assert client["inbounds"][0]["udp"] is True
    assert client["outbounds"][0]["network"] == "udp"


def test_class_03_renders_ssr_md5_ticket_auth() -> None:
    rendered = render_native_case(
        "class-03-ssr-auth-aes128-md5",
        server_address="203.0.113.10",
        server_port=24443,
        seed="seed",
    )
    server = rendered["server"]
    client = rendered["client"]
    assert server["implementation"] == "shadowsocksr-libev"
    assert server["protocol"] == "auth_aes128_md5"
    assert server["obfs"] == "tls1.2_ticket_auth"
    assert client["binary"] == "ssr-local"


def test_class_04_renders_ssr_sha1_ticket_auth() -> None:
    rendered = render_native_case(
        "class-04-ssr-auth-aes128-sha1",
        server_address="203.0.113.10",
        server_port=24443,
        seed="seed",
    )
    server = rendered["server"]
    assert server["protocol"] == "auth_aes128_sha1"
    assert server["obfs"] == "tls1.2_ticket_auth"
