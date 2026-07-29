from __future__ import annotations

from .models import IntelligenceSource


class IntelligenceError(RuntimeError):
    """Concise typed failure at a public intelligence boundary."""

    code = "intelligence_error"
    retriable = False

    def __init__(
        self,
        message: str,
        *,
        source: IntelligenceSource | None = None,
        retriable: bool | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.source = source
        if retriable is not None:
            self.retriable = retriable


class IntelligenceLimitError(IntelligenceError):
    code = "limit_exceeded"


class IntelligenceTransportError(IntelligenceError):
    code = "transport_error"
    retriable = True


class IntelligenceParseError(IntelligenceError):
    code = "invalid_source_data"


class IntelligenceStoreError(IntelligenceError):
    code = "storage_error"


class AdvisoryNotFoundError(IntelligenceError):
    code = "advisory_not_found"
