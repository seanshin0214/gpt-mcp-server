@echo off
REM ============================================
REM GPT MCP Server - Windows Startup Script
REM 설계: Kevin Zhang (DevOps Lead)
REM ============================================

title GPT MCP Server

echo.
echo ============================================
echo   GPT MCP Server for ChatGPT Desktop
echo ============================================
echo.

REM 현재 디렉토리로 이동
cd /d "%~dp0"

REM Python 확인
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python이 설치되지 않았습니다.
    echo Python 3.10 이상을 설치하세요: https://www.python.org/downloads/
    pause
    exit /b 1
)

echo [1/4] Python 확인 완료
python --version

REM 가상환경 확인 및 생성
if not exist "venv" (
    echo.
    echo [2/4] 가상환경 생성 중...
    python -m venv venv
    if %errorlevel% neq 0 (
        echo [ERROR] 가상환경 생성 실패
        pause
        exit /b 1
    )
) else (
    echo [2/4] 가상환경 확인 완료
)

REM 가상환경 활성화
echo [3/4] 가상환경 활성화 중...
call venv\Scripts\activate.bat

REM 의존성 설치 확인
pip show fastapi >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo [3/4] 의존성 설치 중...
    pip install -r requirements.txt
    if %errorlevel% neq 0 (
        echo [ERROR] 의존성 설치 실패
        pause
        exit /b 1
    )
)

echo.
echo ============================================
echo   서버 시작
echo ============================================
echo.
echo   URL: http://127.0.0.1:8765
echo.
echo   다음 단계:
echo   1. 새 터미널에서: ngrok http 8765
echo   2. ngrok URL을 ChatGPT에 등록
echo.
echo   종료: Ctrl+C
echo ============================================
echo.

REM 서버 실행
python server.py

pause
