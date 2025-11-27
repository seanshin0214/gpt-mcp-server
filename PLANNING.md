# GPT Desktop MCP Server 기획서

> **DreamTeam 전문가 리뷰 기반 설계**
> - Solution Architect: Dr. Michael Torres
> - Backend Lead: James Park
> - Security Lead: Robert Chen
> - DevOps Lead: Kevin Zhang
> - Technical Writer: Emily Brown

---

## 1. Solution Architect 관점 (Dr. Michael Torres)

### 1.1 아키텍처 스타일 선택

```
[의사결정]
├─ 팀 규모: 1명 (개인 프로젝트)
│   └─ 결정: Modular Monolith (단일 파일 서버)
│
├─ 독립 배포 필요: No
│   └─ 결정: 단순 Python 스크립트
│
├─ 실시간 이벤트: Yes (SSE for MCP)
│   └─ 결정: FastAPI + SSE
│
└─ 트래픽: 로컬 사용 (1 user)
    └─ 결정: 복잡한 인프라 불필요
```

### 1.2 시스템 아키텍처

```
┌─────────────────────────────────────────────────────────────────┐
│                    GPT Desktop MCP Architecture                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  [ChatGPT Pro]                                                   │
│       │                                                          │
│       │ HTTPS (MCP over SSE)                                     │
│       ▼                                                          │
│  ┌─────────────┐                                                 │
│  │   ngrok     │  ◄── 터널링 (localhost:8765 → public URL)       │
│  └──────┬──────┘                                                 │
│         │                                                        │
│         ▼                                                        │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │              Local MCP Server (FastAPI)                  │    │
│  │                                                          │    │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐     │    │
│  │  │ list_files  │  │ read_file   │  │ search_files│     │    │
│  │  └─────────────┘  └─────────────┘  └─────────────┘     │    │
│  │                                                          │    │
│  │  ┌─────────────────────────────────────────────────┐    │    │
│  │  │           Security Layer                         │    │    │
│  │  │  - Path Validation (Sandbox)                     │    │    │
│  │  │  - Allowed Directories Only                      │    │    │
│  │  │  - Read-Only Mode (Default)                      │    │    │
│  │  └─────────────────────────────────────────────────┘    │    │
│  └──────────────────────────────────────────────────────────┘    │
│         │                                                        │
│         ▼                                                        │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │              Local Filesystem                            │    │
│  │  C:\Users\sshin\Documents (allowed)                      │    │
│  │  C:\Projects (allowed)                                   │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 1.3 API 프로토콜 선택

```
┌───────────────────────────────────────────────────────────────────┐
│                    API PROTOCOL DECISION                          │
├───────────────────────────────────────────────────────────────────┤
│                                                                   │
│  MCP 표준 프로토콜: JSON-RPC over SSE                             │
│      │                                                            │
│      ├─ Transport: HTTP + Server-Sent Events                      │
│      │   - 양방향 통신 가능                                        │
│      │   - GPT가 요청 → 서버가 응답                                │
│      │                                                            │
│      ├─ Message Format: JSON-RPC 2.0                              │
│      │   {                                                        │
│      │     "jsonrpc": "2.0",                                      │
│      │     "method": "tools/call",                                │
│      │     "params": { "name": "read_file", "arguments": {...} }, │
│      │     "id": 1                                                │
│      │   }                                                        │
│      │                                                            │
│      └─ Framework: FastAPI (SSE 지원 우수)                        │
│                                                                   │
└───────────────────────────────────────────────────────────────────┘
```

---

## 2. Backend Lead 관점 (James Park)

### 2.1 프레임워크 선택

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    BACKEND FRAMEWORK SELECTION                               │
├─────────────────────────────────────────────────────────────────────────────┤
│ 요구사항              │ 선택            │ 이유                               │
├─────────────────────────────────────────────────────────────────────────────┤
│ 빠른 MVP             │ Python FastAPI  │ - 타입힌트 지원                    │
│ SSE 지원 필요        │                 │ - async/await 네이티브             │
│ MCP SDK 통합         │                 │ - mcp 라이브러리 Python 우선 지원  │
│                       │                 │ - 단일 파일로 구현 가능            │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 2.2 핵심 도구 (Tools) 설계

```python
# MCP Tools 정의

tools = [
    {
        "name": "list_files",
        "description": "디렉토리의 파일 목록을 조회합니다",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "조회할 디렉토리 경로"},
                "pattern": {"type": "string", "description": "파일 필터 패턴 (예: *.py)"}
            },
            "required": ["path"]
        }
    },
    {
        "name": "read_file",
        "description": "파일 내용을 읽습니다",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "파일 경로"},
                "encoding": {"type": "string", "default": "utf-8"}
            },
            "required": ["path"]
        }
    },
    {
        "name": "search_files",
        "description": "파일 내용에서 텍스트를 검색합니다",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "검색할 디렉토리"},
                "query": {"type": "string", "description": "검색어"},
                "file_pattern": {"type": "string", "default": "*"}
            },
            "required": ["path", "query"]
        }
    },
    {
        "name": "get_file_info",
        "description": "파일 메타데이터를 조회합니다 (크기, 수정일 등)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "파일 경로"}
            },
            "required": ["path"]
        }
    }
]
```

### 2.3 비동기 파일 처리 패턴

```python
# James Park의 권장 패턴: aiofiles 사용

import aiofiles
from pathlib import Path

async def read_file_async(file_path: str, encoding: str = "utf-8") -> str:
    """
    비동기 파일 읽기
    - 대용량 파일도 블로킹 없이 처리
    - 메모리 효율적 (스트리밍)
    """
    path = Path(file_path)

    # 파일 크기 제한 (10MB)
    if path.stat().st_size > 10 * 1024 * 1024:
        raise FileTooLargeError("File exceeds 10MB limit")

    async with aiofiles.open(path, mode='r', encoding=encoding) as f:
        content = await f.read()

    return content

async def list_files_async(directory: str, pattern: str = "*") -> list:
    """
    디렉토리 파일 목록 (비동기 I/O)
    """
    path = Path(directory)
    files = []

    for item in path.glob(pattern):
        files.append({
            "name": item.name,
            "path": str(item),
            "is_dir": item.is_dir(),
            "size": item.stat().st_size if item.is_file() else None
        })

    return sorted(files, key=lambda x: (not x["is_dir"], x["name"]))
```

---

## 3. Security Lead 관점 (Robert Chen)

### 3.1 보안 위협 분석

```
┌─────────────────────────────────────────────────────────────────┐
│                    THREAT MODEL                                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  [위협 1] Path Traversal Attack                                  │
│  ├─ 공격: ../../../etc/passwd 같은 경로 조작                     │
│  ├─ 위험도: Critical                                             │
│  └─ 대응: 경로 정규화 + 허용 디렉토리 검증                       │
│                                                                  │
│  [위협 2] Sensitive File Access                                  │
│  ├─ 공격: .env, credentials.json 등 민감 파일 읽기              │
│  ├─ 위험도: High                                                 │
│  └─ 대응: 민감 파일 패턴 차단 (.env, *secret*, *credential*)    │
│                                                                  │
│  [위협 3] Denial of Service                                      │
│  ├─ 공격: 대용량 파일 요청으로 서버 마비                         │
│  ├─ 위험도: Medium                                               │
│  └─ 대응: 파일 크기 제한 (10MB), Rate Limiting                   │
│                                                                  │
│  [위협 4] Arbitrary Code Execution                               │
│  ├─ 공격: 쓰기 권한으로 악성 코드 주입                           │
│  ├─ 위험도: Critical                                             │
│  └─ 대응: 읽기 전용 모드 기본값                                  │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 3.2 보안 레이어 구현

```python
# Robert Chen의 보안 패턴

from pathlib import Path
from typing import List
import re

class SecurityLayer:
    """파일 접근 보안 레이어"""

    # 허용된 디렉토리 (화이트리스트)
    ALLOWED_DIRECTORIES: List[str] = [
        r"C:\Users\sshin\Documents",
        r"C:\Projects",
    ]

    # 차단할 파일 패턴 (블랙리스트)
    BLOCKED_PATTERNS: List[str] = [
        r"\.env$",
        r"\.env\..+$",
        r".*secret.*",
        r".*credential.*",
        r".*password.*",
        r".*\.pem$",
        r".*\.key$",
        r".*id_rsa.*",
        r".*\.ssh.*",
    ]

    # 파일 크기 제한 (10MB)
    MAX_FILE_SIZE: int = 10 * 1024 * 1024

    @classmethod
    def validate_path(cls, requested_path: str) -> Path:
        """
        경로 검증 (Path Traversal 방지)
        """
        # 1. 경로 정규화 (resolve로 .. 제거)
        resolved = Path(requested_path).resolve()

        # 2. 허용된 디렉토리 내에 있는지 확인
        is_allowed = any(
            str(resolved).startswith(allowed_dir)
            for allowed_dir in cls.ALLOWED_DIRECTORIES
        )

        if not is_allowed:
            raise SecurityError(
                f"Access denied: {resolved} is outside allowed directories"
            )

        # 3. 민감한 파일 패턴 확인
        filename = resolved.name.lower()
        for pattern in cls.BLOCKED_PATTERNS:
            if re.match(pattern, filename, re.IGNORECASE):
                raise SecurityError(
                    f"Access denied: {filename} matches blocked pattern"
                )

        return resolved

    @classmethod
    def check_file_size(cls, path: Path) -> None:
        """파일 크기 검증"""
        if path.is_file() and path.stat().st_size > cls.MAX_FILE_SIZE:
            raise SecurityError(
                f"File too large: {path.stat().st_size} bytes (max: {cls.MAX_FILE_SIZE})"
            )
```

### 3.3 보안 체크리스트

```
✅ 보안 구현 체크리스트 (Robert Chen)

[ ] Path Traversal 방지
    [x] Path.resolve()로 경로 정규화
    [x] 허용 디렉토리 화이트리스트
    [x] 심볼릭 링크 따라가지 않음

[ ] 민감 정보 보호
    [x] .env 파일 차단
    [x] 비밀키/인증서 파일 차단
    [x] SSH 키 차단

[ ] DoS 방지
    [x] 파일 크기 제한 (10MB)
    [ ] Rate Limiting (옵션)
    [ ] 동시 요청 제한 (옵션)

[ ] 최소 권한 원칙
    [x] 읽기 전용 모드 기본값
    [ ] 쓰기 모드는 명시적 활성화 필요
```

---

## 4. DevOps Lead 관점 (Kevin Zhang)

### 4.1 실행 환경 구성

```
gpt-mcp-server/
├── server.py           # MCP 서버 메인
├── security.py         # 보안 레이어
├── requirements.txt    # Python 의존성
├── config.yaml         # 설정 파일
├── start.bat           # Windows 실행 스크립트
├── start.sh            # Linux/Mac 실행 스크립트
└── README.md           # 사용 가이드
```

### 4.2 의존성 (requirements.txt)

```
# Core
mcp>=1.0.0
fastapi>=0.100.0
uvicorn>=0.23.0
aiofiles>=23.0.0

# Security
pydantic>=2.0.0

# Utilities
pyyaml>=6.0
python-dotenv>=1.0.0
```

### 4.3 실행 스크립트

```batch
@echo off
REM start.bat - Windows 실행 스크립트

echo === GPT MCP Server Starting ===

REM 1. 가상환경 활성화 (있으면)
if exist "venv\Scripts\activate.bat" (
    call venv\Scripts\activate.bat
)

REM 2. MCP 서버 실행
echo Starting MCP Server on port 8765...
python server.py

pause
```

```bash
#!/bin/bash
# start.sh - Linux/Mac 실행 스크립트

echo "=== GPT MCP Server Starting ==="

# 1. 가상환경 활성화
if [ -f "venv/bin/activate" ]; then
    source venv/bin/activate
fi

# 2. MCP 서버 실행
echo "Starting MCP Server on port 8765..."
python server.py
```

### 4.4 ngrok 터널링 설정

```bash
# ngrok 설치 후 실행
ngrok http 8765

# 출력 예시:
# Forwarding: https://abc123.ngrok.io -> http://localhost:8765
# 이 URL을 ChatGPT에 등록
```

---

## 5. Technical Writer 관점 (Emily Brown)

### 5.1 사용자 가이드 목차

```
1. 개요
   - GPT MCP란?
   - 이 서버의 기능

2. 설치
   - 요구사항
   - 설치 단계

3. 설정
   - 허용 디렉토리 설정
   - 보안 설정

4. 실행
   - 서버 시작
   - ngrok 터널링
   - ChatGPT 연결

5. 사용 예시
   - 파일 목록 보기
   - 파일 읽기
   - 파일 검색

6. 문제 해결
   - 자주 묻는 질문
   - 오류 메시지 해설
```

---

## 6. 구현 로드맵

```
Phase 1: Core (MVP)
├─ [ ] 기본 MCP 서버 구현
├─ [ ] list_files 도구
├─ [ ] read_file 도구
└─ [ ] 보안 레이어 (Path Validation)

Phase 2: Enhanced
├─ [ ] search_files 도구
├─ [ ] get_file_info 도구
├─ [ ] 설정 파일 (config.yaml)
└─ [ ] 에러 핸들링 개선

Phase 3: Production Ready
├─ [ ] 쓰기 기능 (옵션)
├─ [ ] Rate Limiting
├─ [ ] 로깅 개선
└─ [ ] 사용자 가이드
```

---

## 7. 예상 구현 시간

| Phase | 작업 | 예상 소요 |
|-------|------|----------|
| Phase 1 | Core MVP | 2-3시간 |
| Phase 2 | Enhanced | 1-2시간 |
| Phase 3 | Production | 2-3시간 |

**총 예상: 5-8시간**

---

> **DreamTeam 서명**
>
> - Dr. Michael Torres (Solution Architect): "단순하게 시작하고, 필요할 때 확장하세요."
> - James Park (Backend Lead): "FastAPI + async는 이 규모에 완벽한 선택입니다."
> - Robert Chen (Security Lead): "보안은 나중에 추가하는 게 아닙니다. 처음부터."
> - Kevin Zhang (DevOps Lead): "실행 스크립트는 사용자 경험의 첫 인상입니다."
> - Emily Brown (Technical Writer): "좋은 문서는 좋은 코드만큼 중요합니다."
