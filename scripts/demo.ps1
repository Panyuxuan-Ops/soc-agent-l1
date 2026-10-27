$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$python = Join-Path $root ".venv\Scripts\python.exe"
if (-not (Test-Path $python)) {
    $python = "python"
}
$env:PYTHONPATH = "$root\src;$root"
$env:PYTHONIOENCODING = "utf-8"
& $python -m soc_agent demo @args
