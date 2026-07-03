"""ProbeExecutor — RFC-004-02 C 拍抽象取证执行器接口"""
from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Any
from .probe import Probe


class ProbeExecutor(ABC):
    """C 拍取证执行器的抽象接口。

    实际部署时由具体适配器（EDR/SIEM/Cloud API）实现。
    测试和演示使用 MockExecutor。
    """

    @abstractmethod
    def execute_fanout(self, probes: list[Probe]) -> list[dict]:
        """并发扇出取证，返回原始事件列表。

        Each returned event dict should contain:
        - id: str (unique event identifier)
        - technique: str (MITRE technique if identifiable)
        - tactic: str
        - timestamp: float (unix epoch)
        - source: str (log source that produced this)
        - target: str (entity this evidence relates to)
        - probe_id: str (which probe generated this)
        - raw_data: dict (operator-specific payload)
        - attributes: dict (additional metadata)

        May return empty list if probes yield nothing (no_data outcome).
        """
        ...

    @abstractmethod
    def available(self) -> bool:
        """Check if executor is ready to accept probes."""
        ...
