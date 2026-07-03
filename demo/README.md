# RFC-004-02 前端演示原型

基于 React 的可交互 LOCK 溯源演示，**已接入 `soar_mcp_env` 三个真实场景**。

## 启动（需两个终端）

**终端 1 — Python 后端（真实 LOCK 循环）**

```bash
cd demo
python server.py
```

监听 `http://localhost:8001`，提供：

- `GET /api/scenarios` — 场景列表
- `GET /api/session?scenario=pipeline_18|apt_5host|multipath_12host` — 完整溯源回放 JSON

**终端 2 — 前端**

```bash
cd demo
npm install
npm run dev
```

浏览器打开 `http://localhost:5173/demo/entry`，选择场景后进入作战室逐拍回放。

## 场景

| ID | 说明 | GT |
|----|------|-----|
| `pipeline_18` | 18 步全链路管道 | 18 |
| `apt_5host` | 5 主机 APT | 25 |
| `multipath_12host` | 12 主机多路径 | 31 |

后端使用 `ScenarioExecutor` + `DecisionOrchestrator`，与 eval 脚本同一套 LOCK 引擎。

## 路由

| 路径 | 页面 |
|------|------|
| `/demo/entry` | P0 初诊门控入口 |
| `/demo/session/:id` | P1 作战室（LOCK + 四本账） |
| `/demo/session/:id/report` | P3 决策报告 |
| `/demo/compare` | P4 RFC-003 vs RFC-004-02 对比 |

## 操作

- **播放 / 暂停**：自动推进 LOCK 各拍
- **单步**：手动前进一拍
- **导游 / 探员模式**：切换旁白与播放速度
- 中栏切换：**攻击图 / 候选池 / 时间线**
- 左栏切换：**四本账**（决策账默认重点）

## 目录结构

```
src/
  components/     # LockStepper, LedgerTabs, SessionGraph, …
  pages/          # Entry, Session, Report, Compare
  data/           # mockSession 预置 case
  hooks/          # useDemoPlayback
  types.ts
```

## 技术栈

- React 19 + TypeScript + Vite
- react-router-dom
- 纯 CSS（RFC 色板），无 UI 框架依赖
