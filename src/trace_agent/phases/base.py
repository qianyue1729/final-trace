"""base — 拍级执行器的抽象基类与统一返回类型。"""
from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from trace_agent.agents.lock_session import LOCKSession

logger = logging.getLogger(__name__)


@dataclass
class PhaseResult:
    """单个拍的执行结果。

    Attributes:
        phase: 拍名称 ("L" / "Veto" / "O" / "C" / "K")
        success: 执行是否成功
        data: 拍特定的输出数据
        progress_event: 用于流事件的进度数据（由编排器发送）
        should_stop: 仅 K 拍使用，表示是否应停止主循环
    """
    phase: str
    success: bool
    data: dict = field(default_factory=dict)
    progress_event: dict = field(default_factory=dict)
    should_stop: bool = False


class PhaseExecutor(ABC):
    """拍级执行器抽象基类。

    所有具体拍（L/Veto/O/C/K）必须继承此类并实现 execute()。
    执行器不持有状态，所有读写均通过 session 参数传递。
    """

    @abstractmethod
    def execute(self, session: LOCKSession) -> PhaseResult:
        """执行本拍逻辑，返回 PhaseResult。

        Args:
            session: LOCK 循环共享状态容器

        Returns:
            PhaseResult 包含本拍输出、进度事件及停止信号
        """
        ...

    def _safe(self, fn, *args, default=None, label: str = ""):
        """容错调用：捕获异常并返回默认值，不中断执行流。"""
        try:
            return fn(*args)
        except Exception as exc:
            if label:
                logger.warning("[%s] %s failed: %s", self.__class__.__name__, label, exc)
            return default
