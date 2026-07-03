#!/usr/bin/env pwsh
# 检测 Wazuh MCP 并运行完整溯源测试（当 Wazuh 可用时）

$env:PYTHONPATH = "src"
$env:WAZUH_MCP_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ3YXp1aF9tY3BfdXNlciIsImlhdCI6MTc4Mjk4MzYxNCwic2NvcGUiOiJ3YXp1aDpyZWFkIHdhenVoOndyaXRlIiwiZXhwIjoxODE0NTE5NjE0fQ.zPNoPtrOfMqbXeG4Zc8aHubOucRNdyq2zL1TaM4BFCA"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Wazuh Real Scenario Test Runner (PowerShell)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check if python is available
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host "ERROR: Python not found in PATH" -ForegroundColor Red
    exit 1
}

# Step 1: Quick connectivity test
Write-Host "[Step 1/3] Testing Wazuh MCP connectivity..." -ForegroundColor Yellow
try {
    $testResult = python scripts/validate_wazuh_runtime.py --limit 3 2>&1 | ConvertFrom-Json
    
    if ($testResult.status -eq "ready") {
        Write-Host "✓ Wazuh MCP service is ONLINE" -ForegroundColor Green
        Write-Host "  Telemetry query: $($testResult.checks.telemetry_query.ok)"
        Write-Host "  Pagination mode: $($testResult.checks.pagination.mode)"
        
    } else {
        Write-Host "✗ Wazuh MCP service is OFFLINE" -ForegroundColor Red
        Write-Host "  Status: $($testResult.status)"
        Write-Host "  Error: $($testResult.checks.mcp_initialize.reason)"
        Write-Host ""
        Write-Host "Please wait for Wazuh service to recover or check:" -ForegroundColor DarkYellow
        Write-Host "  1. Remote server (192.144.151.189) status"
        Write-Host "  2. Token validity"
        Write-Host "  3. Network connectivity"
        exit 2
    }
} catch {
    Write-Host "ERROR: Validation script failed - $_" -ForegroundColor Red
    exit 1
}

Write-Host ""

# Step 2: Run real scenario test
Write-Host "[Step 2/3] Running Wazuh real scenario test..." -ForegroundColor Yellow
Write-Host ""

python test_wazuh_real_scenario.py 2>&1 | Tee-Object -FilePath wazuh_real_test_output.json

Write-Host ""

# Step 3: Summary
Write-Host "[Step 3/3] Test completed!" -ForegroundColor Yellow

if (Test-Path wazuh_real_test_output.json) {
    $report = Get-Content wazuh_real_test_output.json -Raw | ConvertFrom-Json
    
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Test Results Summary" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    
    foreach ($sid in $report.scenario.id) {
        Write-Host ""
        Write-Host "$($sid):" -ForegroundColor Cyan
        Write-Host "  Rounds: $($report.execution.rounds_completed)"
        Write-Host "  Budget used: $($report.execution.budget_used)/$($report.execution.probes_total)"
        Write-Host "  Decision: $($report.result.decision)"
        Write-Host "  Confidence: $([math]::Round($($report.result.confidence)*100, 1))%"
        Write-Host "  GT Coverage: $([math]::Round($($report.ground_truth.coverage_pct), 1))%"
    }
    
    Write-Host ""
    Write-Host "Full output saved to: wazuh_real_test_output.json" -ForegroundColor Green
} else {
    Write-Host "WARNING: No output file generated" -ForegroundColor DarkYellow
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Tests completed successfully!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
