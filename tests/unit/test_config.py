from proxy_traffic_lab.configuration.loader import (
    load_lab_config,
    load_protocol_matrix,
)


def test_checked_in_configuration_is_valid() -> None:
    config = load_lab_config()
    matrix = load_protocol_matrix()
    assert config.schema_version == 1
    assert len(matrix.cases) == 12
    assert [case.dataset_class for case in matrix.cases] == list(range(1, 13))
