# PowerShell Runner for Defensive Guide to SQL Injection and Database Security (Python)
Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host "  DEFENSIVE GUIDE TO SQL INJECTION AND DATABASE SECURITY" -ForegroundColor White
Write-Host "  Python Edition - Value Added Course in Cybersecurity" -ForegroundColor Gray
Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host ""

$pythonCmd = "python"
$pyCheck = Get-Command python -ErrorAction SilentlyContinue

if (-not $pyCheck) {
    $fallbackPath = "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe"
    if (Test-Path $fallbackPath) {
        $pythonCmd = $fallbackPath
    } else {
        $pyLauncher = Get-Command py -ErrorAction SilentlyContinue
        if ($pyLauncher) {
            $pythonCmd = "py"
        } else {
            Write-Host "[ERROR] Python was not found on your system." -ForegroundColor Red
            Write-Host "Please install Python 3.10+ from https://www.python.org/" -ForegroundColor Yellow
            Exit
        }
    }
}

Write-Host "[INFO] Using Python interpreter: $pythonCmd" -ForegroundColor Green
Write-Host "[INFO] Checking Python dependencies..." -ForegroundColor Gray
& $pythonCmd -m pip install -r requirements.txt --quiet

Write-Host "[INFO] Starting Defensive Security Web Server..." -ForegroundColor Cyan
Write-Host ""
& $pythonCmd app.py
