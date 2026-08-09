from __future__ import annotations

from pathlib import Path

from proxy_traffic_lab.common.errors import ConfigurationError
from proxy_traffic_lab.common.process import run_command
from proxy_traffic_lab.lifecycle.xray.documents import validate_generated_client_address
from proxy_traffic_lab.kernels.xray import load_image_lock


def validate_server_config_with_container(project_root: Path) -> str:
    image = load_image_lock(project_root / "configs" / "locks" / "xray.json")
    config_path = project_root / "secrets" / "generated" / "server.json"
    certificate_path = project_root / "secrets" / "xray" / "server.crt"
    private_key_path = project_root / "secrets" / "xray" / "server.key"
    for path in (config_path, certificate_path, private_key_path):
        if not path.is_file():
            raise ConfigurationError(f"required generated file is missing: {path}")
    server_result = run_command(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--user",
            "0:0",
            "--mount",
            f"type=bind,src={config_path},dst=/run/lab/server.json,readonly",
            "--mount",
            f"type=bind,src={certificate_path},dst=/run/secrets/xray/server.crt,readonly",
            "--mount",
            f"type=bind,src={private_key_path},dst=/run/secrets/xray/server.key,readonly",
            image,
            "run",
            "-test",
            "-config",
            "/run/lab/server.json",
        ],
        timeout_seconds=30,
    )
    if server_result.returncode != 0:
        raise ConfigurationError(
            "Xray rejected generated server configuration: "
            + (server_result.stderr or server_result.stdout)
        )

    client_path = project_root / "secrets" / "generated" / "client.json"
    if not client_path.is_file():
        raise ConfigurationError(f"required generated file is missing: {client_path}")
    validate_generated_client_address(client_path)
    client_result = run_command(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--user",
            "0:0",
            "--mount",
            f"type=bind,src={client_path},dst=/run/lab/client.json,readonly",
            image,
            "run",
            "-test",
            "-config",
            "/run/lab/client.json",
        ],
        timeout_seconds=30,
    )
    if client_result.returncode != 0:
        raise ConfigurationError(
            "Xray rejected generated client configuration: "
            + (client_result.stderr or client_result.stdout)
        )
    server_detail = server_result.stdout or server_result.stderr
    client_detail = client_result.stdout or client_result.stderr
    return f"SERVER\n{server_detail}\nCLIENT\n{client_detail}"



