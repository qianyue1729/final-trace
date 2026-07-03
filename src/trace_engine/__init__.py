"""trace_engine — 企业级第三方告警溯源引擎服务层。

架构：
    告警(REST) → AlertEvent → DecisionOrchestrator(LOCK 单环 + 四本账)
                                    ↓ C 拍
                        SoarMcpProbeExecutor(单 SOAR MCP 多数据源)
                                    ↓
                    McpHttpTransport(生产) / LocalSoarTransport(验收)

内核（trace_agent）不变；本包只提供生产接入层：
- 执行器：真实 SOAR MCP 探针执行（与验收共用同一匹配内核）
- 归一化：配置驱动字段映射，适配任意 SOAR 记录格式
- 服务化：FastAPI + SQLite 持久化 + API Key 鉴权 + 审计日志
"""

import sys as _sys
from pathlib import Path as _Path

# 保证同仓 src/ 下的 trace_agent 内核优先于任何全局安装副本
_SRC = str(_Path(__file__).resolve().parent.parent)
if _SRC not in _sys.path:
    _sys.path.insert(0, _SRC)
elif _sys.path.index(_SRC) > 0:
    _sys.path.remove(_SRC)
    _sys.path.insert(0, _SRC)

__version__ = "1.0.0"
