import pytest
from pydantic import ValidationError

from proxy_traffic_lab.configuration.composition import validate_case_composition
from proxy_traffic_lab.configuration.loader import (
    load_component_catalogs,
    load_protocol_matrix,
)
from proxy_traffic_lab.common.errors import ConfigurationError
from proxy_traffic_lab.configuration.models import ProtocolMatrix


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
        "class-08-vless-xhttp-reality-vision",
        "class-09-trojan-raw-tls",
        "class-10-trojan-websocket-tls",
        "class-11-hysteria2-quic-tls",
        "class-12-hysteria2-quic-salamander-tls",
    ]


def _assert_unsupported(document: dict[str, object], index: int) -> None:
    case = ProtocolMatrix.model_validate(document).cases[index]
    catalogs = load_component_catalogs()
    with pytest.raises(ConfigurationError, match="unsupported composition|cannot use"):
        validate_case_composition(
            case,
            protocols=catalogs[0],
            transports=catalogs[1],
            encryptions=catalogs[2],
            compatibility=catalogs[3],
        )


def test_rejects_unsupported_vmess_security() -> None:
    document = _matrix_document()
    document["cases"][4]["encryption"] = "none"  # type: ignore[index]
    _assert_unsupported(document, 4)


def test_rejects_unsupported_xhttp_mode() -> None:
    document = _matrix_document()
    document["cases"][5]["parameters"]["mode"] = "h3"  # type: ignore[index]
    _assert_unsupported(document, 5)


def test_rejects_unsupported_reality_security() -> None:
    document = _matrix_document()
    document["cases"][6]["encryption"] = "tls"  # type: ignore[index]
    _assert_unsupported(document, 6)


def test_rejects_unsupported_vless_transport() -> None:
    document = _matrix_document()
    document["cases"][7]["transport"] = "raw"  # type: ignore[index]
    _assert_unsupported(document, 7)


def test_rejects_quic_over_tcp() -> None:
    document = _matrix_document()
    document["cases"][10]["outer_transport"] = "tcp"  # type: ignore[index]
    _assert_unsupported(document, 10)


def test_rejects_unknown_hysteria_parameter_shape() -> None:
    document = _matrix_document()
    document["cases"][11]["parameters"]["obfs"] = "unknown"  # type: ignore[index]
    _assert_unsupported(document, 11)


def test_class_labels_are_data_not_code_constraints() -> None:
    document = _matrix_document()
    document["cases"][4]["id"] = "my-vmess-target"  # type: ignore[index]
    matrix = ProtocolMatrix.model_validate(document)
    assert matrix.cases[4].id == "my-vmess-target"


def test_rejects_duplicate_dataset_class() -> None:
    document = _matrix_document()
    document["cases"][1]["dataset_class"] = 1  # type: ignore[index]
    with pytest.raises(ValidationError):
        ProtocolMatrix.model_validate(document)
