# pipeline_18 参考数据

从 Wazuh 服务器导出的攻击链 ground truth，用于归一化 diff 与契约回归。

## 下载（需本机 SSH 密钥）

```powershell
scp -r ubuntu@192.144.151.189:/home/ubuntu/soar-logs/pipeline_18/* `
  "F:\cursor all\final trace\reference\pipeline_18\"
```

预期文件：

- `attack_chain_18_events.json`
- `attack_chain_18_compact.json`
- `QUERY_CONTRACT.md`（服务器副本；仓库内已同步）

## 本地校验

```powershell
$env:PYTHONPATH="src"
python scripts/validate_pipeline_18_contract.py
```
