"""Traffic analysis and connection tracking package for NIDS.

Provides stateful session tracking, bidirectional flow models (`FlowRecord`, `FlowKey`),
and cumulative traffic statistics (`TrafficStatistics`) via `TrafficAnalyzer`.
"""

from backend.analysis.models import FlowKey, FlowRecord, TrafficStatistics
from backend.analysis.traffic import TrafficAnalyzer

__all__ = [
    "FlowKey",
    "FlowRecord",
    "TrafficStatistics",
    "TrafficAnalyzer",
]
