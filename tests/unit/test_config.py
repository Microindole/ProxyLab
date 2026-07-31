from proxy_traffic_lab.controller.config import (
    load_lab_config,
    load_protocol_matrix,
)


def test_checked_in_configuration_is_valid() -> None:
    config = load_lab_config()
    matrix = load_protocol_matrix()
    assert config.schema_version == 1
    assert [case.id for case in matrix.cases] == ["vless-tcp-tls"]

