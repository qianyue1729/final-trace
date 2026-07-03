param(
    [int]$Port = 3001
)

$ErrorActionPreference = "Stop"
$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$UiRoot = Join-Path $ProjectRoot "deep-agents-ui"

$env:NEXT_PUBLIC_DEPLOYMENT_URL = "http://127.0.0.1:2024"
$env:NEXT_PUBLIC_ASSISTANT_ID = "trace_agent"

Push-Location $UiRoot
try {
    if (-not (Test-Path -LiteralPath (Join-Path $UiRoot "node_modules"))) {
        yarn install --frozen-lockfile
    }
    yarn dev --port $Port
}
finally {
    Pop-Location
}
