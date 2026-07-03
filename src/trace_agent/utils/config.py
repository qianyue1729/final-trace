"""RFC-004-02 证据信任层关键参数"""

# 抗伪造阈值：integrity >= TAU_HARD + not adversary_controllable → forge-resistant
TAU_HARD: float = 0.8

# "高"信任阈值
TAU_SOFT: float = 0.65

# 独立来源佐证阈值
COROB_BONUS_THRESHOLD: int = 2

# 佐证加成值
COROB_BONUS_VALUE: float = 0.15

# 降权因子表（主机失陷时）
DOWNWEIGHT_FACTORS: dict = {
    "windows_event_log_security": 0.4,
    "windows_event_log_powershell": 0.4,
    "syslog": 0.4,
    "bash_history": 0.2,
    "file_system_timestamp": 0.3,
    "web_application_log": 0.2,
}

# 豁免降权的源
EXEMPT_SOURCES: set = {
    "edr_kernel_process_event",
    "sysmon",
    "auditd",
    "cloudtrail_management_event",
}

# 未知来源默认 integrity
UNKNOWN_SOURCE_INTEGRITY: float = 0.2

# 反取证检测：时间断层阈值（秒）
TIME_GAP_THRESHOLD: int = 300  # 5 minutes
TIME_GAP_HIGH_THRESHOLD: int = 3600  # 1 hour → high severity

# --- LOCK 运行时参数（RFC-004-02 §4/§6/§7/§8）---

# VOI 停止阈值：继续探查的期望收益低于此值则停止
EPS_VOI: float = 0.01

# 解释集合硬上限
K_MAX: int = 6

# 溯因维护阈值
TAU_SPAWN: float = 0.15   # 孵化：所有解释 max P(e|H) < τ_spawn
TAU_MERGE: float = 0.05   # 合并：两解释预测分歧 < τ_merge
EPS_CULL: float = 0.02    # 淘汰：后验 < ε_cull 持续 CULL_PATIENCE 轮
CULL_PATIENCE: int = 3    # 淘汰耐心（轮数）

# 义务预算上限占比
OBLIGATION_BUDGET_FRACTION: float = 0.5  # ⌈B/2⌉

# 决策鲁棒性扰动幅度
ROBUSTNESS_PERTURBATION: float = 0.1

# 判别债务触发阈值
DISCRIMINATIVE_MARGIN_THRESHOLD: float = 0.15
