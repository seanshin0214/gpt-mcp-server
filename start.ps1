# ============================================
# GPT MCP Server - PowerShell Startup Script
# 설계: Kevin Zhang (DevOps Lead)
# ============================================

$Host.UI.RawUI.WindowTitle = "GPT MCP Server"

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  GPT MCP Server for ChatGPT Desktop" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# 현재 디렉토리로 이동
Set-Location $PSScriptRoot

# Python 확인
try {
    $pythonVersion = python --version 2>&1
    Write-Host "[1/4] Python 확인 완료: $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] Python이 설치되지 않았습니다." -ForegroundColor Red
    Write-Host "Python 3.10 이상을 설치하세요: https://www.python.org/downloads/" -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 1
}

# 가상환경 확인 및 생성
if (-not (Test-Path "venv")) {
    Write-Host ""
    Write-Host "[2/4] 가상환경 생성 중..." -ForegroundColor Yellow
    python -m venv venv
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[ERROR] 가상환경 생성 실패" -ForegroundColor Red
        Read-Host "Press Enter to exit"
        exit 1
    }
} else {
    Write-Host "[2/4] 가상환경 확인 완료" -ForegroundColor Green
}

# 가상환경 활성화
Write-Host "[3/4] 가상환경 활성화 중..." -ForegroundColor Yellow
& ".\venv\Scripts\Activate.ps1"

# 의존성 설치 확인
$fastapi = pip show fastapi 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "[3/4] 의존성 설치 중..." -ForegroundColor Yellow
    pip install -r requirements.txt
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[ERROR] 의존성 설치 실패" -ForegroundColor Red
        Read-Host "Press Enter to exit"
        exit 1
    }
}

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  서버 시작" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  URL: " -NoNewline
Write-Host "http://127.0.0.1:8765" -ForegroundColor Green
Write-Host ""
Write-Host "  다음 단계:" -ForegroundColor Yellow
Write-Host "  1. 새 터미널에서: " -NoNewline
Write-Host "ngrok http 8765" -ForegroundColor Cyan
Write-Host "  2. ngrok URL을 ChatGPT에 등록"
Write-Host ""
Write-Host "  종료: " -NoNewline
Write-Host "Ctrl+C" -ForegroundColor Red
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# 서버 실행
python server.py

Read-Host "Press Enter to exit"
