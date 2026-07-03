param(
    [string]$HostAddress = "127.0.0.1",
    [int]$Port = 2024,
    [switch]$EnableProduction,
    [switch]$DemoProfile,
    [string]$EngineConfigPath = ""
)

$ErrorActionPreference = "Stop"
$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$BackendRoot = Join-Path $ProjectRoot "deep-agent-backend"
$CoreSrc = Join-Path $ProjectRoot "src"
$RootEnv = Join-Path $ProjectRoot ".env"
$HostClientEnv = Join-Path $ProjectRoot "host-client.env"

function Import-SelectedEnv {
    param(
        [string]$Path,
        [string[]]$Allowed
    )
    if (-not (Test-Path -LiteralPath $Path)) {
        return
    }
    foreach ($Line in Get-Content -LiteralPath $Path -Encoding UTF8) {
        if ($Line -match '^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$') {
            $Name = $Matches[1]
            if ($Allowed -contains $Name) {
                $Value = $Matches[2].Trim().Trim('"').Trim("'")
                [Environment]::SetEnvironmentVariable($Name, $Value, "Process")
            }
        }
    }
}

Import-SelectedEnv -Path $RootEnv -Allowed @(
        "TRACE_AGENT_MODEL_PROVIDER",
        "LLM_PROVIDER",
        "TRACE_AGENT_CONTEXT_WINDOW",
        "TRACE_AGENT_MAX_OUTPUT_TOKENS",
        "DEEPSEEK_API_KEY",
        "DEEPSEEK_BASE_URL",
        "DEEPSEEK_MODEL",
        "DEEPSEEK_TIMEOUT",
        "DEEPSEEK_VERIFY_TLS",
        "WAZUH_MCP_VERIFY_TLS",
        "OPENAI_API_KEY",
        "OPENAI_MODEL",
        "OPENAI_TIMEOUT"
)

if (-not $env:TRACE_AGENT_MODEL_PROVIDER -and $env:LLM_PROVIDER) {
    $env:TRACE_AGENT_MODEL_PROVIDER = $env:LLM_PROVIDER
}

if ($EnableProduction) {
    Import-SelectedEnv -Path $HostClientEnv -Allowed @(
        "WAZUH_MCP_TOKEN",
        "TRACE_ENGINE_MCP_TOKEN",
        "TRACE_ENGINE_MCP_ENDPOINT",
        "TRACE_ENGINE_BACKEND"
    )

    if (-not $EngineConfigPath) {
        if ($DemoProfile) {
            $EngineConfigPath = Join-Path $ProjectRoot "configs\engine_demo_wazuh.yaml"
        } else {
            $EngineConfigPath = Join-Path $ProjectRoot "configs\engine.yaml"
        }
    }
    $ResolvedConfig = (Resolve-Path -LiteralPath $EngineConfigPath).Path
    $env:TRACE_AGENT_ALLOW_PRODUCTION = "1"
    $env:TRACE_AGENT_ENGINE_CONFIG = $ResolvedConfig
    if ($DemoProfile) {
        $env:TRACE_ENGINE_DEMO_PROFILE = "1"
    }

    if (-not $env:WAZUH_MCP_TOKEN -and -not $env:TRACE_ENGINE_MCP_TOKEN) {
        throw "Production mode requires WAZUH_MCP_TOKEN or TRACE_ENGINE_MCP_TOKEN."
    }
}
else {
    $env:TRACE_AGENT_ALLOW_PRODUCTION = "0"
}

$env:PYTHONPATH = if ($env:PYTHONPATH) {
    "$CoreSrc;$env:PYTHONPATH"
} else {
    $CoreSrc
}
$env:PYTHONUTF8 = "1"
$env:PYTHONIOENCODING = "utf-8"

Push-Location $BackendRoot
try {
    uv run --python 3.11 --extra dev langgraph dev --host $HostAddress --port $Port --no-browser --no-reload
}
finally {
    Pop-Location
}
