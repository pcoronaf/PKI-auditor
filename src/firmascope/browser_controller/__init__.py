"""Control de un Chromium limpio por sesion (Playwright + CDP)."""

from .controller import BrowserController
from .isolation import (
    DEFAULT_STAGES,
    BlockedAttempt,
    NetworkIsolation,
    Stage,
    StageAction,
    StagedOfflineTest,
    StagedResult,
    processing_locality,
)

__all__ = [
    "DEFAULT_STAGES",
    "BlockedAttempt",
    "BrowserController",
    "NetworkIsolation",
    "Stage",
    "StageAction",
    "StagedOfflineTest",
    "StagedResult",
    "processing_locality",
]
