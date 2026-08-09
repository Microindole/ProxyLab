from __future__ import annotations

from enum import StrEnum

from proxy_traffic_lab.common.errors import LabError


class ExperimentState(StrEnum):
    PLANNED = "PLANNED"
    SERVER_CONFIGURED = "SERVER_CONFIGURED"
    SERVER_RUNNING = "SERVER_RUNNING"
    CLIENT_CONFIGURED = "CLIENT_CONFIGURED"
    CLIENT_RUNNING = "CLIENT_RUNNING"
    CAPTURE_RUNNING = "CAPTURE_RUNNING"
    TRAFFIC_RUNNING = "TRAFFIC_RUNNING"
    TRAFFIC_FINISHED = "TRAFFIC_FINISHED"
    CAPTURE_FINISHED = "CAPTURE_FINISHED"
    VALIDATING = "VALIDATING"
    PASSED = "PASSED"
    FAILED = "FAILED"
    ARCHIVED = "ARCHIVED"


TRANSITIONS: dict[ExperimentState, frozenset[ExperimentState]] = {
    ExperimentState.PLANNED: frozenset(
        {ExperimentState.SERVER_CONFIGURED, ExperimentState.FAILED}
    ),
    ExperimentState.SERVER_CONFIGURED: frozenset(
        {ExperimentState.SERVER_RUNNING, ExperimentState.FAILED}
    ),
    ExperimentState.SERVER_RUNNING: frozenset(
        {ExperimentState.CLIENT_CONFIGURED, ExperimentState.FAILED}
    ),
    ExperimentState.CLIENT_CONFIGURED: frozenset(
        {ExperimentState.CLIENT_RUNNING, ExperimentState.FAILED}
    ),
    ExperimentState.CLIENT_RUNNING: frozenset(
        {ExperimentState.CAPTURE_RUNNING, ExperimentState.FAILED}
    ),
    ExperimentState.CAPTURE_RUNNING: frozenset(
        {ExperimentState.TRAFFIC_RUNNING, ExperimentState.FAILED}
    ),
    ExperimentState.TRAFFIC_RUNNING: frozenset(
        {ExperimentState.TRAFFIC_FINISHED, ExperimentState.FAILED}
    ),
    ExperimentState.TRAFFIC_FINISHED: frozenset(
        {ExperimentState.CAPTURE_FINISHED, ExperimentState.FAILED}
    ),
    ExperimentState.CAPTURE_FINISHED: frozenset(
        {ExperimentState.VALIDATING, ExperimentState.FAILED}
    ),
    ExperimentState.VALIDATING: frozenset(
        {ExperimentState.PASSED, ExperimentState.FAILED}
    ),
    ExperimentState.PASSED: frozenset({ExperimentState.ARCHIVED}),
    ExperimentState.FAILED: frozenset({ExperimentState.ARCHIVED}),
    ExperimentState.ARCHIVED: frozenset(),
}


class InvalidTransition(LabError):
    pass


def transition(
    current: ExperimentState,
    target: ExperimentState,
) -> ExperimentState:
    if target == current:
        return current
    if target not in TRANSITIONS[current]:
        raise InvalidTransition(f"invalid transition: {current} -> {target}")
    return target




