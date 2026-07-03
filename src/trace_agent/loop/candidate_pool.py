"""CandidatePool — RFC-004-02 统一候选池（去重 + 合并来源）"""
from __future__ import annotations

from typing import Optional

from .probe import Probe


class CandidatePool:
    """统一候选池：所有生成器产出的 Probe 去重后汇入此池。

    去重策略：相同 dedup_key() 的探针只保留一个（保留 priority_hint 更高的）。
    """

    def __init__(self) -> None:
        self._pool: dict[str, Probe] = {}  # dedup_key → Probe

    def add(self, probes: list[Probe]) -> int:
        """去重后入池，返回实际新增数量。

        If a probe with the same dedup_key exists:
        - Keep the one with higher priority_hint
        - Merge explanation_ids from both
        """
        added = 0
        for probe in probes:
            key = probe.dedup_key()
            existing = self._pool.get(key)
            if existing is None:
                self._pool[key] = probe
                added += 1
            else:
                # Merge explanation_ids
                merged_ids = list(existing.explanation_ids)
                for eid in probe.explanation_ids:
                    if eid not in merged_ids:
                        merged_ids.append(eid)
                # Keep the one with higher priority_hint
                if probe.priority_hint > existing.priority_hint:
                    probe.explanation_ids = merged_ids
                    self._pool[key] = probe
                else:
                    existing.explanation_ids = merged_ids
        return added

    def drain(self) -> list[Probe]:
        """取出所有候选并清空池。Returns probes ordered by priority_hint desc."""
        probes = sorted(self._pool.values(), key=lambda p: p.priority_hint, reverse=True)
        self._pool.clear()
        return probes

    def size(self) -> int:
        """当前池中候选数量"""
        return len(self._pool)

    def peek(self) -> list[Probe]:
        """查看当前候选（不清空）"""
        return sorted(self._pool.values(), key=lambda p: p.priority_hint, reverse=True)

    def remove(self, probe_ids: list[str]) -> int:
        """移除指定 probe（被 VETO 剪枝后调用）"""
        removed = 0
        keys_to_remove = []
        for key, probe in self._pool.items():
            if probe.id in probe_ids:
                keys_to_remove.append(key)
        for key in keys_to_remove:
            del self._pool[key]
            removed += 1
        return removed
