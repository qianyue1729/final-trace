"""trace_agent - RFC-004-02 LOCK + 决策账运行时推理引擎

证据信任层 (EvidenceTrust) 是第一个实现的运行时模块。
使用 create_evidence_trust_model() 工厂函数快速创建完整配置的实例。
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from .core.evidence_trust import EvidenceTrustModel
from .core.trust_registry import LogSourceRegistry
from .core.downweight_rules import DownweightEngine
from .core.anti_forensics import AntiForensicsScanner
from .core.types import EvidenceTrust, TrustContext, TrustRevision, TrustTier, LogSourceSpec
from .veto_integration.veto_gates import VetoGates
from .obligation_integration.mandate_from_trust import (
    MandateObligation, mandate_from_absence, mandate_from_anti_forensics
)
from .agents.orchestrator import DecisionOrchestrator, InvestigationResult, run_investigation
from .utils.config import TAU_HARD, TAU_SOFT
from .decision.runtime_types import (
    LossMatrix, BoundaryBelief, PosteriorState, VOIResult, StopDecision,
    ObligationType, Obligation,
)
from .decision.runtime_ledger import RuntimeDecisionLedger
from .obligation_integration.obligation_ledger import ObligationLedger
from .probe.voi_engine import voi, bayes_risk, should_stop, predict_outcomes


def create_evidence_trust_model(
    data_dir: Optional[Path] = None,
    tau_hard: float = TAU_HARD,
    tau_soft: float = TAU_SOFT,
) -> EvidenceTrustModel:
    """
    工厂函数：创建完整配置的 EvidenceTrustModel。

    使用方式（主循环）：
        from trace_agent import create_evidence_trust_model
        self.trust = create_evidence_trust_model()

    Args:
        data_dir: 数据目录路径。默认读取环境变量 TRACE_AGENT_DATA，
                  或 fallback 到 src/trace_agent/data/
        tau_hard: forge-resistant 阈值（默认 0.8）
        tau_soft: "高"信任阈值（默认 0.65）
    """
    if data_dir is None:
        env_data = os.getenv('TRACE_AGENT_DATA')
        if env_data:
            data_dir = Path(env_data)
        else:
            # 默认相对于本文件
            data_dir = Path(__file__).resolve().parent / 'data'
    else:
        data_dir = Path(data_dir)

    registry = LogSourceRegistry(data_dir / 'log_source_trust.json')
    downweight = DownweightEngine()
    anti_forensics = AntiForensicsScanner()

    return EvidenceTrustModel(
        registry=registry,
        downweight_engine=downweight,
        anti_forensics=anti_forensics,
        tau_hard=tau_hard,
        tau_soft=tau_soft,
    )


def create_lock_runtime(
    seed,
    data_dir: Optional[Path] = None,
    loss: Optional[LossMatrix] = None,
) -> tuple:
    """
    工厂函数：从 SeedPayload 一行初始化完整 LOCK 运行时三大模块。

    使用方式（主循环）：
        from trace_agent import create_lock_runtime
        ledger, obligations, trust = create_lock_runtime(seed)

    Args:
        seed: SeedPayload（由 DecisionLedger.seed() 产出）
        data_dir: 数据目录路径（默认 src/trace_agent/data/）
        loss: LossMatrix（默认从 loss_baseline.json 加载）

    Returns:
        (RuntimeDecisionLedger, ObligationLedger, EvidenceTrustModel)
    """
    if data_dir is None:
        env_data = os.getenv('TRACE_AGENT_DATA')
        if env_data:
            data_dir = Path(env_data)
        else:
            data_dir = Path(__file__).resolve().parent / 'data'
    else:
        data_dir = Path(data_dir)

    # Loss matrix
    if loss is None:
        loss_path = data_dir / 'loss_baseline.json'
        if loss_path.exists():
            loss = LossMatrix.from_json(loss_path)
        else:
            loss = LossMatrix()

    # EvidenceTrustModel
    trust = create_evidence_trust_model(data_dir=data_dir)

    # RuntimeDecisionLedger
    ledger = RuntimeDecisionLedger.from_seed(seed, loss)

    # ObligationLedger
    templates_path = data_dir / 'lifecycle_templates.json'
    if templates_path.exists():
        obligations = ObligationLedger.from_json(templates_path, loss)
    else:
        obligations = ObligationLedger(loss=loss)

    return ledger, obligations, trust


__all__ = [
    # 工厂
    'create_evidence_trust_model',
    # 核心类
    'EvidenceTrustModel',
    'LogSourceRegistry',
    'DownweightEngine',
    'AntiForensicsScanner',
    # 数据类
    'EvidenceTrust',
    'TrustContext',
    'TrustRevision',
    'TrustTier',
    'LogSourceSpec',
    # VETO
    'VetoGates',
    # 义务
    'MandateObligation',
    'mandate_from_absence',
    'mandate_from_anti_forensics',
    # 配置
    'TAU_HARD',
    'TAU_SOFT',
    # 运行时决策账
    'RuntimeDecisionLedger',
    'LossMatrix',
    'BoundaryBelief',
    'PosteriorState',
    'VOIResult',
    'StopDecision',
    'ObligationType',
    'Obligation',
    # 义务台账
    'ObligationLedger',
    # VOI 引擎
    'voi',
    'bayes_risk',
    'should_stop',
    'predict_outcomes',
    # 运行时工厂
    'create_lock_runtime',
    # LOCK 主循环编排
    'DecisionOrchestrator',
    'InvestigationResult',
    'run_investigation',
]
