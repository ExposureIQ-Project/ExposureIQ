"""Read-only, deterministic facts for the optional advisory AI layer."""

from exposureiq.insight.digest import scan_digest
from exposureiq.insight.risk import risk_score

__all__ = ["scan_digest", "risk_score"]
