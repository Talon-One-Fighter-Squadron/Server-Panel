# Nuclear Option Server Panel - Start (Admin)
# Self-elevating launcher. Required for firewall rule automation.

param()

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $here

function Test-IsAdmin {
  try {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  } catch { return $false }
}

if (-not (Test-IsAdmin)) {
  Start-Process -FilePath "powershell.exe" -Verb RunAs -ArgumentList @(
    "-NoProfile","-ExecutionPolicy","Bypass","-File","`"$PSCommandPath`""
  ) | Out-Null
  exit
}

$python = Join-Path $here "venv\Scripts\python.exe"
if (Test-Path $python) {
  & $python (Join-Path $here "app.py")
  exit $LASTEXITCODE
}

# Prefer py launcher
if (Get-Command py -ErrorAction SilentlyContinue) {
  & py -3 (Join-Path $here "app.py")
  exit $LASTEXITCODE
}

if (Get-Command python -ErrorAction SilentlyContinue) {
  & python (Join-Path $here "app.py")
  exit $LASTEXITCODE
}

Write-Host "[start-panel] ERROR: Python not found. Install Python 3.x or add it to PATH."
Read-Host "Press Enter to exit" | Out-Null
exit 1
