# Raw Layer

本目录存放**开源原始快照**，是先验产物的唯一权威输入。

- 源登记：`sources.json`
- 拉取结果：`manifest.json`（由 `build/fetch_opensource.py` 生成）
- 大文件默认不提交 git，CI/本地执行 fetch 后构建

```powershell
python prior_knowledge/build/fetch_opensource.py --required-only
```
