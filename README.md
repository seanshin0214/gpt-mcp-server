# GPT MCP Server

> **ChatGPT Desktop에서 로컬 파일시스템에 직접 접근**
>
> MCP (Model Context Protocol) 기반 파일시스템 서버

---

## 개요

이 서버를 실행하면 ChatGPT Desktop에서 로컬 파일을 읽고 검색할 수 있습니다.

```
ChatGPT Pro (클라우드)
       ↓
    ngrok (터널)
       ↓
  이 MCP 서버 (로컬)
       ↓
  로컬 파일시스템
```

## 기능

| 도구 | 설명 |
|------|------|
| `list_files` | 디렉토리 파일 목록 조회 |
| `read_file` | 파일 내용 읽기 |
| `search_files` | 파일 내용 검색 |
| `get_file_info` | 파일 메타데이터 조회 |
| `get_allowed_directories` | 접근 가능 디렉토리 확인 |

## 보안

- **화이트리스트 기반**: 허용된 디렉토리만 접근 가능
- **민감 파일 차단**: `.env`, `*.key`, `*secret*` 등 자동 차단
- **읽기 전용**: 기본적으로 쓰기 비활성화
- **파일 크기 제한**: 10MB 초과 파일 차단

---

## 빠른 시작

### 1. 서버 실행

```batch
# Windows (배치 파일)
start.bat

# 또는 PowerShell
.\start.ps1

# 또는 직접 실행
python server.py
```

### 2. ngrok 터널링

새 터미널에서:

```bash
ngrok http 8765
```

출력 예시:
```
Forwarding: https://abc123.ngrok-free.app -> http://localhost:8765
```

### 3. ChatGPT에 등록

1. ChatGPT Desktop → Settings → Developer Mode 활성화
2. MCP Connectors → Add Connector
3. ngrok URL 입력: `https://abc123.ngrok-free.app/mcp`

---

## 설치

### 요구사항

- Python 3.10+
- GPT Pro 구독 (Developer Mode 필요)
- ngrok (무료 계정)

### 설치 단계

```bash
# 1. 디렉토리 이동
cd gpt-mcp-server

# 2. 가상환경 생성
python -m venv venv

# 3. 가상환경 활성화 (Windows)
venv\Scripts\activate

# 4. 의존성 설치
pip install -r requirements.txt

# 5. 설정 파일 수정 (선택)
# config.yaml에서 allowed_directories 수정
```

---

## 설정

### config.yaml

```yaml
# 허용된 디렉토리 (이 폴더 내의 파일만 접근 가능)
filesystem:
  allowed_directories:
    - "C:\\Users\\your-username\\Documents"
    - "C:\\Projects"

  # 파일 크기 제한 (바이트)
  max_file_size: 10485760  # 10MB

  # 쓰기 모드 (기본: 비활성화)
  write_enabled: false
```

### 환경 변수로 설정

```bash
# 허용 디렉토리 (세미콜론으로 구분)
set GPT_MCP_ALLOWED_DIRS=C:\Users\me\Documents;C:\Projects

# 포트 변경
set GPT_MCP_PORT=8080

# 디버그 모드
set GPT_MCP_DEBUG=true
```

---

## 사용 예시

ChatGPT에서 다음과 같이 요청:

```
"Documents 폴더의 파일 목록을 보여줘"

"project/src 폴더에서 'import' 가 포함된 파일을 찾아줘"

"README.md 파일을 읽어줘"

"config.yaml 파일의 1-50 라인만 보여줘"
```

---

## 프로젝트 구조

```
gpt-mcp-server/
├── server.py           # MCP 서버 메인
├── security.py         # 보안 레이어
├── config.py           # 설정 관리
├── tools.py            # 고급 파일 도구
├── config.yaml         # 설정 파일
├── requirements.txt    # Python 의존성
├── start.bat           # Windows 실행 스크립트
├── start.ps1           # PowerShell 실행 스크립트
├── README.md           # 이 문서
└── PLANNING.md         # 설계 문서
```

---

## 문제 해결

### "Connection refused" 오류

```bash
# 서버가 실행 중인지 확인
curl http://127.0.0.1:8765/health
```

### "Access denied" 오류

`config.yaml`에서 `allowed_directories`에 해당 경로가 포함되어 있는지 확인.

### ngrok 연결 안 됨

1. ngrok 재시작
2. 새 URL 생성됨 → ChatGPT에 다시 등록

### 한글 파일명 깨짐

```yaml
# config.yaml
server:
  log_level: "DEBUG"
```

인코딩 문제 로그 확인 후 `encoding` 파라미터 조정.

---

## API 엔드포인트

| 엔드포인트 | 설명 |
|-----------|------|
| `GET /` | 서버 상태 |
| `GET /health` | 헬스체크 |
| `POST /mcp` | MCP JSON-RPC 엔드포인트 |
| `GET /sse` | SSE 스트림 |

---

## 라이선스

MIT License

---

## DreamTeam 설계

이 프로젝트는 DreamTeam 전문가들의 설계를 기반으로 구현되었습니다:

- **Dr. Michael Torres** (Solution Architect): 시스템 아키텍처
- **James Park** (Backend Lead): FastAPI 서버 구현
- **Robert Chen** (Security Lead): 보안 레이어
- **Kevin Zhang** (DevOps Lead): 실행 스크립트 및 설정
- **Emily Brown** (Technical Writer): 문서화

---

> **"로컬 파일에 직접 접근하는 GPT"**
>
> Claude Code처럼, 하지만 GPT로.
