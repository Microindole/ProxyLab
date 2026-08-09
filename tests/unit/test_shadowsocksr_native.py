from pathlib import Path

import pytest

from proxy_traffic_lab.common.errors import ConfigurationError
from proxy_traffic_lab.configuration.loader import load_protocol_matrix, project_root
from proxy_traffic_lab.lifecycle.shadowsocksr_documents import (
    create_identity,
    load_identity,
)
from proxy_traffic_lab.protocols.shadowsocksr import (
    render_case,
    validate_documents,
)
from proxy_traffic_lab.kernels.shadowsocksr import SSR_SOURCE_COMMIT
import proxy_traffic_lab.kernels.shadowsocksr as ssr_kernel


def test_class_03_renders_upstream_native_config() -> None:
    rendered = render_case(
        load_protocol_matrix().cases[2],
        password="a-secure-test-password",
        server_address="203.0.113.10",
        server_port=24443,
    )
    assert rendered["server"]["protocol"] == "auth_aes128_md5"
    assert rendered["server"]["obfs"] == "tls1.2_ticket_auth"
    assert rendered["server"]["method"] == "aes-256-cfb"
    assert rendered["client"]["client_settings"]["server"] == "203.0.113.10"
    validate_documents(rendered["server"], rendered["client"])


def test_class_04_renders_sha1_and_ipv6() -> None:
    rendered = render_case(
        load_protocol_matrix().cases[3],
        password="a-secure-test-password",
        server_address="2001:db8::10",
        server_port=24443,
        socks_port=10809,
    )
    assert rendered["server"]["protocol"] == "auth_aes128_sha1"
    assert rendered["client"]["client_settings"]["server"] == "2001:db8::10"
    assert rendered["client"]["client_settings"]["listen_port"] == 10809


def test_identity_is_random_and_never_overwritten(tmp_path: Path) -> None:
    password = create_identity(tmp_path)
    assert load_identity(tmp_path) == password
    with pytest.raises(ConfigurationError, match="refusing to overwrite"):
        create_identity(tmp_path)


def test_upstream_source_is_full_commit_pinned() -> None:
    assert len(SSR_SOURCE_COMMIT) == 40
    assert all(character in "0123456789abcdef" for character in SSR_SOURCE_COMMIT)


def test_dockerfile_pins_source_and_base_image() -> None:
    dockerfile = (
        project_root() / "containers" / "shadowsocksr-native" / "Dockerfile"
    ).read_text(encoding="utf-8")
    assert f"ARG SSR_COMMIT={SSR_SOURCE_COMMIT}" in dockerfile
    assert dockerfile.count("debian:bookworm-slim@sha256:") == 2
    assert "FROM debian:bookworm-slim AS" not in dockerfile


def test_build_uses_pinned_commit_and_records_image_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    context = tmp_path / "containers" / "shadowsocksr-native"
    context.mkdir(parents=True)
    (context / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    calls: list[tuple[str, ...]] = []

    class Result:
        returncode = 0
        stderr = ""

        def __init__(self, stdout: str = "") -> None:
            self.stdout = stdout

    def fake_run(args, **kwargs):
        calls.append(tuple(args))
        return Result("sha256:" + "a" * 64 if "inspect" in args else "built")

    monkeypatch.setattr(ssr_kernel, "run_command", fake_run)
    image = ssr_kernel.build_pinned_image(tmp_path)
    assert image == "sha256:" + "a" * 64
    assert f"SSR_COMMIT={SSR_SOURCE_COMMIT}" in calls[0]
    assert ssr_kernel.load_image_lock(tmp_path) == image
