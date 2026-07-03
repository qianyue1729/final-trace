"""日志源信任注册表 — 从 log_source_trust.json 加载和管理"""
from __future__ import annotations
import json
from pathlib import Path
from typing import Dict, Optional, List
from .types import LogSourceSpec, TrustTier


class LogSourceRegistry:
    """日志源注册表 - 缓存和查询 RFC-004-02 §5"""

    def __init__(self, registry_path: Path):
        self.registry_path = Path(registry_path)
        self.sources: Dict[str, LogSourceSpec] = {}
        self.load()

    def load(self) -> None:
        """从 JSON 加载注册表，跳过 _ 前缀字段"""
        if not self.registry_path.exists():
            raise FileNotFoundError(
                f"Log source trust registry not found: {self.registry_path}"
            )
        with open(self.registry_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        for source_id, spec_dict in data.items():
            if source_id.startswith('_'):
                continue
            self.sources[source_id] = LogSourceSpec(
                source_id=source_id,
                integrity=spec_dict.get('integrity', 0.5),
                tier=TrustTier(spec_dict.get('tier', 'low')),
                adversary_controllable_base=spec_dict.get('adversary_controllable_base', False),
                hard_veto_allowed=spec_dict.get('hard_veto_allowed', False),
                platforms=spec_dict.get('platforms', []),
                observes=spec_dict.get('observes', []),
                sigma_technique_coverage=spec_dict.get('sigma_technique_coverage', 0),
            )

    def get_source(self, source_id: str) -> Optional[LogSourceSpec]:
        """按 ID 查询日志源规格"""
        return self.sources.get(source_id)

    def list_forge_resistant(self) -> List[LogSourceSpec]:
        """列出所有 forge-resistant 级别的源"""
        return [s for s in self.sources.values() if s.tier == TrustTier.FORGE_RESISTANT]

    def get_by_platform(self, platform: str) -> List[LogSourceSpec]:
        """按平台筛选可用日志源"""
        return [s for s in self.sources.values() if platform in s.platforms]

    def get_expected_observations(self, platform: str, source_id: str) -> List[str]:
        """获取特定平台+源的预期观测类型"""
        source = self.get_source(source_id)
        if source and platform in source.platforms:
            return source.observes
        return []

    def summary(self) -> Dict:
        """返回注册表摘要"""
        all_platforms = set()
        for s in self.sources.values():
            all_platforms.update(s.platforms)
        return {
            "total_sources": len(self.sources),
            "forge_resistant": len(self.list_forge_resistant()),
            "platforms_covered": sorted(all_platforms),
        }
