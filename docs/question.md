为什么需要这三项优化
让我从测试中观察到的实际现象出发，逐条解释根因：
1. L-phase 探针多样性不足
现象：Orchestrator 每轮只选 3 个探针，且偏向 auth_log：
R1: ops=['auth_log', 'auth_log', 'network_flow']
R2: ops=['auth_log', 'auth_log', 'lateral_movement_check']
根因：L-phase 的探针生成逻辑基于已知上下文推断"下一步该查什么"。当入口告警是一个进程事件（T1068 提权）时，L-phase 倾向于查认证日志（auth_log → AUTH/LOGON），因为提权通常伴随认证异常。但实际攻击链的动作分布是：
CONNECT: 6次    ← network_flow 能匹配
EXEC: 7次       ← process_tree 能匹配
WRITE: 3次      ← file_hash_lookup / persistence_scan 能匹配
FORK: 3次       ← process_tree 能匹配
INJECT: 2次     ← process_tree 能匹配
auth_log 只匹配 AUTH/LOGON，而攻击链中没有一个事件是 AUTH 或 LOGON 动作。所以 auth_log 探针全部命中噪声。诊断对比：当我手动发出 process_tree + network_flow 探针时，单轮即命中 7 个攻击事件；而框架自己选的 auth_log 单轮命中 0 个。
2. VOI 过早触底
现象：框架在第 4 轮就停止了（stop_reason=voi_floor），此时 margin=0.96，entropy≈0。根因：VOI（Value of Information）的计算公式是：
max_voi = entropy × (1 - margin) × lambda_miss × 0.1
这里有一个鸡生蛋的困局：
攻击事件因为探针策略问题没有被大量采集 → 贝叶斯账本没有足够攻击证据
没有攻击证据 → null 假说（"无攻击"）的后验概率飙升到 ~1.0
null 后验高 → margin→1, entropy→0
VOI = 0 × 0.04 × lambda_miss × 0.1 ≈ 0 → 触发 voi_floor 停止
也就是说：框架因为没找到攻击，所以认为不值得继续找，所以停止了 — 但它没找到恰恰是因为没搜够。这是一个负反馈循环。在实际攻击响应中，即使初始证据不明显，分析师也不会在 4 轮就放弃。应至少保证 最小探索深度（比如至少 8 轮），再让 VOI 机制接管。
3. 攻击事件 tactic 字段为空
现象：ScenarioExecutor 的匹配策略有三层评分：
host_uid 匹配: +3.0 分
tactic 匹配:   +2.0 分  ← 攻击事件 tactic="" → 永远不加分
operator→action: +1.0 分
实际数据：
{"technique": "T1059.001", "tactic": "", "action": "EXEC"}   // 攻击事件
{"technique": null, "tactic": "", "action": "EXEC"}          // 噪声事件
两者在 tactic 维度完全相同（都是空），所以攻击事件和噪声事件得分相同。排序时按时间戳取前 10，哪个时间早就返回哪个 — 噪声事件数量是攻击的 150 倍，所以噪声几乎总是占满 10 个名额。如果 tactic 字段填充正确：
{"technique": "T1059.001", "tactic": "execution", "action": "EXEC"}  // 攻击事件 → +2分
{"technique": null, "tactic": "", "action": "EXEC"}                  // 噪声事件 → +0分
攻击事件会获得 host(+3) + tactic(+2) + action(+1) = 6 分，而噪声只有 host(+3) + action(+1) = 4 分。攻击事件就能排在前面被优先返回。
总结：三者形成恶性循环
tactic 字段为空 → 攻击事件无法优先被返回（与噪声得分相同）
         ↓
L-phase 偏 auth_log → 探针命中的全是噪声
         ↓
贝叶斯账本无攻击证据 → null 假说后验 → 1.0
         ↓
VOI 计算 → 0 → 触发 voi_floor → 过早停止
         ↓
最终决策: "dismiss_benign" (错误)
这三项优化针对的是链条上的三个不同断点，任何一个修复都能显著改善 recall，三者同时修复则可实现完整溯源。