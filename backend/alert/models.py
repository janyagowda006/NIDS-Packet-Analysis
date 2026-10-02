"""Data models and status definitions for the NIDS Alert layer."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Set


class AlertStatus:
    """Standardized lifecycle statuses for security alerts."""

    NEW = "NEW"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    RESOLVED = "RESOLVED"

    VALID_STATUSES: Set[str] = {NEW, ACKNOWLEDGED, RESOLVED}

    @classmethod
    def validate(cls, status: Any) -> str:
        """Validate and return normalized alert status string.

        Raises ValueError if the status is not one of NEW, ACKNOWLEDGED, or RESOLVED.
        """
        if not isinstance(status, str):
            raise ValueError(f"Invalid alert status type: {type(status).__name__}. Expected str.")

        norm = status.strip().upper()
        if norm not in cls.VALID_STATUSES:
            raise ValueError(
                f"Invalid alert status '{status}'. Must be one of: {sorted(cls.VALID_STATUSES)}"
            )
        return norm


@dataclass(frozen=True)
class Alert:
    """Represents a persisted security alert retrieved from the database.

    Supports both attribute access (alert.id) and dictionary-style access (alert['id'])
    for complete flexibility across backend and dashboard components.
    """

    id: int
    timestamp: str
    alert_type: str
    severity: str
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    protocol: Optional[str] = None
    description: Optional[str] = None
    detection_reason: Optional[str] = None
    evidence: Dict[str, Any] = field(default_factory=dict)
    status: str = AlertStatus.NEW

    def __getitem__(self, item: str) -> Any:
        """Allow dictionary-style key access."""
        if hasattr(self, item):
            return getattr(self, item)
        raise KeyError(item)

    def __contains__(self, item: str) -> bool:
        """Check key presence."""
        return hasattr(self, item)

    def get(self, item: str, default: Any = None) -> Any:
        """Dictionary-style get with default value."""
        return getattr(self, item, default)

    def to_dict(self) -> Dict[str, Any]:
        """Convert alert into a clean dictionary representation."""
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "alert_type": self.alert_type,
            "severity": self.severity,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "protocol": self.protocol,
            "description": self.description,
            "detection_reason": self.detection_reason,
            "evidence": dict(self.evidence) if isinstance(self.evidence, dict) else self.evidence,
            "status": self.status,
        }

    def __str__(self) -> str:
        target = f" -> {self.dst_ip}" if self.dst_ip else ""
        return f"Alert(id={self.id}, [{self.severity}] {self.alert_type}: {self.src_ip}{target}, status={self.status})"
