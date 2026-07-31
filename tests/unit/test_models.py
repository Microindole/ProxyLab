import pytest
from pydantic import ValidationError

from proxy_traffic_lab.controller.models import ProtocolMatrix


def _case() -> dict[str, object]:
    return {
        "id": "vless-tcp-tls",
        "enabled": True,
        "protocol": "vless",
        "client": "xray",
        "server": "xray",
        "outer_transport": "tcp",
        "wrapper": "raw",
        "security": "tls",
        "flow": None,
        "inner_networks": ["tcp"],
    }


def test_accepts_mvp_case() -> None:
    matrix = ProtocolMatrix.model_validate(
        {"schema_version": 1, "cases": [_case()]}
    )
    assert matrix.cases[0].id == "vless-tcp-tls"


def test_rejects_mislabeled_mvp_case() -> None:
    case = _case()
    case["security"] = "none"
    with pytest.raises(ValidationError, match="supported MVP stack"):
        ProtocolMatrix.model_validate({"schema_version": 1, "cases": [case]})


def test_rejects_duplicate_ids() -> None:
    with pytest.raises(ValidationError, match="must be unique"):
        ProtocolMatrix.model_validate(
            {"schema_version": 1, "cases": [_case(), _case()]}
        )

