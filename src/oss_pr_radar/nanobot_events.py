"""Explicit NanoBot adapter over the durable event state machine.

No old NanoBot implementation or event history is synthesized here.
"""

from .agentscope_events import (
    EventLane as _EventLane,
)
from .agentscope_events import (
    GitHubIssuePoller as _GitHubIssuePoller,
)
from .agentscope_events import (
    PollResult,
    _receipt_has_live_bridge,
    advance_model_fallback,
    dispatch_once,
    github_event_effective_time,
)

__all__ = [
    "EventLane",
    "GitHubIssuePoller",
    "PollResult",
    "_receipt_has_live_bridge",
    "advance_model_fallback",
    "dispatch_once",
    "github_event_effective_time",
]

REPO = "HKUDS/nanobot"


class EventLane(_EventLane):
    def __init__(self, path, **kwargs):
        super().__init__(path, repo=REPO, namespace="nanobot", **kwargs)


class GitHubIssuePoller(_GitHubIssuePoller):
    def __init__(self, state_path, **kwargs):
        super().__init__(state_path, repo=REPO, **kwargs)
