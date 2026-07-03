import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { checkBackend, fetchScenarios } from '../data/apiSession';
import type { ScenarioInfo } from '../types';

export function EntryPage() {
  const navigate = useNavigate();
  const [scenarios, setScenarios] = useState<ScenarioInfo[]>([]);
  const [backendOk, setBackendOk] = useState<boolean | null>(null);

  useEffect(() => {
    checkBackend().then(setBackendOk);
    fetchScenarios().then((list) => {
      if (list.length > 0) {
        setScenarios(list);
      } else {
        setScenarios([
          { id: 'pipeline_18', name: '18 步全链路管道', description: '4 主机 · GT 18', tags: ['SOAR'], gtTotal: 18 },
          { id: 'apt_5host', name: '5 主机 APT 企业网', description: '4 主机 · GT 25', tags: ['SOAR'], gtTotal: 25 },
          { id: 'multipath_12host', name: '12 主机多路径企业网', description: '7 主机 · GT 31', tags: ['SOAR'], gtTotal: 31 },
        ]);
      }
    });
  }, []);

  return (
    <div className="entry-page">
      <div className="entry-card entry-card--wide">
        <div className="entry-card__badge">SOAR MCP · soar_mcp_env 真实场景</div>
        <h1>选择场景 · 还原完整 LOCK 溯源</h1>
        <p className="muted entry-intro">
          后端使用 <code>ScenarioExecutor</code> 驱动 <code>soar_mcp_env/scenarios</code> 三个 JSON，
          运行真实 <strong>L → ② → O → C → K</strong> 单环并逐拍回放。
        </p>
        {backendOk === false && (
          <p className="entry-warn">
            未检测到后端：请先在 <code>demo</code> 目录运行 <code>python server.py</code>（端口 8001）
          </p>
        )}
        {backendOk === true && (
          <p className="entry-ok">后端已连接 · 首次加载场景需 5–15 秒（完整 LOCK 循环）</p>
        )}
        <div className="scenario-grid">
          {scenarios.map((s) => (
            <button
              key={s.id}
              type="button"
              className="scenario-card"
              onClick={() => navigate(`/demo/session/${s.id}`)}
            >
              <div className="scenario-card__title">{s.name}</div>
              <div className="scenario-card__id">{s.id}</div>
              <p className="scenario-card__desc">{s.description}</p>
              <div className="scenario-card__meta">
                <span>GT {s.gtTotal} 条</span>
                {s.tags.map((t) => (
                  <span key={t} className="scenario-card__tag">{t}</span>
                ))}
              </div>
            </button>
          ))}
        </div>
      </div>
      <div className="entry-poster">
        <pre>{`soar_mcp_env/scenarios/*.json
        │
ScenarioExecutor + DecisionOrchestrator
        │
   LOCK 每轮 L→②→O→C→K
        │
  /api/session?scenario=…
        │
  前端作战室逐拍回放`}</pre>
      </div>
    </div>
  );
}
