"""Packet parsing and protocol normalization layer.

Provides models and dissectors to transform raw captured Scapy packets into
consistent, strongly-typed `NormalizedPacket` representations.
"""

from backend.parser.dissector import PacketDissector
from backend.parser.models import NormalizedPacket

__all__ = [
    "NormalizedPacket",
    "PacketDissector",
]
