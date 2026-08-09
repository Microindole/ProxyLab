import pytest

from proxy_traffic_lab.capture.state_machine import (
    ExperimentState,
    InvalidTransition,
    transition,
)


def test_happy_path_start() -> None:
    state = transition(
        ExperimentState.PLANNED,
        ExperimentState.SERVER_CONFIGURED,
    )
    assert state is ExperimentState.SERVER_CONFIGURED


def test_transition_is_idempotent() -> None:
    state = transition(
        ExperimentState.CAPTURE_RUNNING,
        ExperimentState.CAPTURE_RUNNING,
    )
    assert state is ExperimentState.CAPTURE_RUNNING


def test_active_state_can_fail() -> None:
    assert (
        transition(ExperimentState.TRAFFIC_RUNNING, ExperimentState.FAILED)
        is ExperimentState.FAILED
    )


def test_cannot_skip_capture() -> None:
    with pytest.raises(InvalidTransition):
        transition(
            ExperimentState.CLIENT_RUNNING,
            ExperimentState.TRAFFIC_RUNNING,
        )
