import pytest
from pydantic import ValidationError

from proxy_traffic_lab.controller.config import load_protocol_matrix
from proxy_traffic_lab.controller.models import ProtocolMatrix


def _matrix_document() -> dict[str, object]:
    return load_protocol_matrix().model_dump(mode="json")


def test_accepts_complete_target_matrix() -> None:
    matrix = ProtocolMatrix.model_validate(_matrix_document())
    assert [case.dataset_class for case in matrix.cases] == list(range(1, 13))
    assert [case.id for case in matrix.cases if case.enabled] == [
        "class-01-shadowsocks-2022-tcp",
        "class-02-shadowsocks-2022-udp",
        "class-03-ssr-auth-aes128-md5",
        "class-04-ssr-auth-aes128-sha1",
        "class-05-vmess-websocket-tls",
        "class-06-vmess-xhttp-h2-tls",
        "class-07-vless-raw-reality-vision",
        "class-08-vless-grpc-tls",
        "class-09-trojan-raw-tls",
        "class-10-trojan-websocket-tls",
    ]


def test_rejects_mislabeled_class_05() -> None:
    document = _matrix_document()
    document["cases"][4]["security"] = "none"  # type: ignore[index]
    with pytest.raises(ValidationError, match="class 5 must be"):
        ProtocolMatrix.model_validate(document)


def test_rejects_mislabeled_class_06() -> None:
    document = _matrix_document()
    document["cases"][5]["obfs_mode"] = "h3"  # type: ignore[index]
    with pytest.raises(ValidationError, match="class 6 must be"):
        ProtocolMatrix.model_validate(document)


def test_rejects_mislabeled_class_07() -> None:
    document = _matrix_document()
    document["cases"][6]["security"] = "tls"  # type: ignore[index]
    with pytest.raises(ValidationError, match="class 7 must be"):
        ProtocolMatrix.model_validate(document)


def test_rejects_mislabeled_class_08() -> None:
    document = _matrix_document()
    document["cases"][7]["wrapper"] = "raw"  # type: ignore[index]
    with pytest.raises(ValidationError, match="class 8 must be"):
        ProtocolMatrix.model_validate(document)


def test_rejects_duplicate_dataset_class() -> None:
    document = _matrix_document()
    document["cases"][1]["dataset_class"] = 1  # type: ignore[index]
    with pytest.raises(ValidationError):
        ProtocolMatrix.model_validate(document)
