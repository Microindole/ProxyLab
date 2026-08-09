import pytest

from proxy_traffic_lab.controller.config import load_lab_config, load_protocol_matrix
from proxy_traffic_lab.controller.models import LabConfig, RuntimeCore
from proxy_traffic_lab.providers.runtime import resolve_runtime_core


def test_runtime_defaults_to_xray_core() -> None:
    assert load_lab_config().runtime.default_core == RuntimeCore.XRAY_CORE


def test_runtime_uses_case_declared_core() -> None:
    matrix = load_protocol_matrix()
    case = next(item for item in matrix.cases if item.dataset_class == 11)
    config = load_lab_config()
    assert (
        resolve_runtime_core(config, case=case, side="server")
        == RuntimeCore.HYSTERIA2
    )
    assert (
        resolve_runtime_core(config, case=case, side="client")
        == RuntimeCore.HYSTERIA2
    )


def test_runtime_default_is_configurable() -> None:
    config = LabConfig.model_validate(
        {
            "schema_version": 1,
            "role": "combined-dev",
            "data_root": "./data",
            "runtime": {"default_core": "hysteria2"},
        }
    )
    assert resolve_runtime_core(config) == RuntimeCore.HYSTERIA2


def test_explicit_core_cannot_silently_mismatch_case() -> None:
    matrix = load_protocol_matrix()
    case = next(item for item in matrix.cases if item.dataset_class == 11)
    with pytest.raises(ValueError, match="declares hysteria2"):
        resolve_runtime_core(
            load_lab_config(),
            explicit=RuntimeCore.XRAY_CORE,
            case=case,
            side="server",
        )
