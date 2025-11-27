"""
GPT MCP Server - Main Server
============================
설계: James Park (Backend Lead)

MCP (Model Context Protocol) 서버
- GPT Desktop에서 로컬 파일시스템 접근 가능
- SSE (Server-Sent Events) 기반 통신
- JSON-RPC 2.0 프로토콜

사용법:
1. python server.py
2. ngrok http 8765
3. ChatGPT에 URL 등록
"""

import os
import sys
import json
import asyncio
import logging
from pathlib import Path
from typing import Optional, List, Dict, Any, AsyncIterator
from datetime import datetime
from dataclasses import dataclass
from contextlib import asynccontextmanager

# FastAPI & Uvicorn
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import StreamingResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

# Async File I/O
import aiofiles
import aiofiles.os

# 로컬 모듈
from config import get_config, AppConfig, create_default_config_file
from security import (
    SecurityLayer, SecurityConfig, SecurityError,
    AccessDeniedError, FileTooLargeError, BlockedFileError,
    AccessMode, get_security_layer, reset_security_layer
)

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# ============================================================================
# MCP Protocol Types
# ============================================================================

@dataclass
class MCPTool:
    """MCP Tool 정의"""
    name: str
    description: str
    inputSchema: Dict[str, Any]


@dataclass
class MCPRequest:
    """MCP 요청"""
    jsonrpc: str
    method: str
    params: Optional[Dict[str, Any]] = None
    id: Optional[int] = None


@dataclass
class MCPResponse:
    """MCP 응답"""
    jsonrpc: str = "2.0"
    result: Optional[Any] = None
    error: Optional[Dict[str, Any]] = None
    id: Optional[int] = None

    def to_dict(self) -> Dict:
        d = {"jsonrpc": self.jsonrpc}
        if self.result is not None:
            d["result"] = self.result
        if self.error is not None:
            d["error"] = self.error
        if self.id is not None:
            d["id"] = self.id
        return d


# ============================================================================
# File Operations (비동기)
# ============================================================================

class FileOperations:
    """
    파일 작업 핸들러

    James Park의 설계 원칙:
    - 모든 I/O는 비동기
    - 에러 핸들링 철저히
    - 보안 레이어 통과 필수
    """

    def __init__(self, security: SecurityLayer, config: AppConfig):
        self.security = security
        self.config = config

    async def list_files(
        self,
        directory: str,
        pattern: str = "*",
        recursive: bool = False
    ) -> List[Dict[str, Any]]:
        """
        디렉토리 파일 목록 조회

        Args:
            directory: 조회할 디렉토리 경로
            pattern: glob 패턴 (예: *.py, *.txt)
            recursive: 하위 디렉토리 포함 여부

        Returns:
            파일 정보 리스트
        """
        # 보안 검증
        path = self.security.validate_path(directory)

        if not path.exists():
            raise FileNotFoundError(f"Directory not found: {directory}")

        if not path.is_dir():
            raise ValueError(f"Not a directory: {directory}")

        files = []
        max_items = self.config.filesystem.max_directory_items

        try:
            if recursive:
                glob_iter = path.rglob(pattern)
            else:
                glob_iter = path.glob(pattern)

            for item in glob_iter:
                if len(files) >= max_items:
                    logger.warning(f"Directory listing truncated at {max_items} items")
                    break

                try:
                    # 각 파일도 보안 검증 (차단 패턴 등)
                    self.security.validate_path(str(item))
                    file_info = self.security.get_safe_file_info(item)
                    files.append(file_info)
                except SecurityError:
                    # 차단된 파일은 건너뜀
                    continue

        except PermissionError as e:
            logger.error(f"Permission denied: {e}")
            raise AccessDeniedError(f"Permission denied: {directory}")

        # 정렬: 디렉토리 먼저, 이름순
        files.sort(key=lambda x: (not x.get("is_dir", False), x.get("name", "").lower()))

        return files

    async def read_file(
        self,
        file_path: str,
        encoding: str = "utf-8",
        start_line: Optional[int] = None,
        end_line: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        파일 내용 읽기

        Args:
            file_path: 파일 경로
            encoding: 문자 인코딩
            start_line: 시작 라인 (1부터 시작)
            end_line: 끝 라인

        Returns:
            파일 내용 및 메타데이터
        """
        # 보안 검증
        path = self.security.validate_path(file_path)

        if not path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        if not path.is_file():
            raise ValueError(f"Not a file: {file_path}")

        # 파일 크기 검증
        self.security.check_file_size(path)

        # 파일 정보
        stat_info = path.stat()

        try:
            async with aiofiles.open(path, mode='r', encoding=encoding) as f:
                if start_line is not None or end_line is not None:
                    # 라인 범위 읽기
                    lines = await f.readlines()
                    start = (start_line or 1) - 1
                    end = end_line or len(lines)
                    content = "".join(lines[start:end])
                    total_lines = len(lines)
                else:
                    content = await f.read()
                    total_lines = content.count('\n') + 1

                # 최대 라인 수 제한
                if total_lines > self.config.filesystem.max_lines:
                    lines = content.split('\n')[:self.config.filesystem.max_lines]
                    content = '\n'.join(lines)
                    content += f"\n\n... [Truncated at {self.config.filesystem.max_lines} lines]"

            # 민감 정보 마스킹 (설정에 따라)
            if self.config.security.mask_sensitive_content:
                content = self.security.sanitize_content(content)

            return {
                "path": str(path),
                "content": content,
                "encoding": encoding,
                "size": stat_info.st_size,
                "lines": total_lines,
                "modified": datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
            }

        except UnicodeDecodeError:
            # 바이너리 파일인 경우
            return {
                "path": str(path),
                "content": None,
                "error": "Binary file - cannot read as text",
                "size": stat_info.st_size,
                "is_binary": True,
            }

    async def get_file_info(self, file_path: str) -> Dict[str, Any]:
        """파일 메타데이터 조회"""
        # 보안 검증
        path = self.security.validate_path(file_path)

        if not path.exists():
            raise FileNotFoundError(f"Path not found: {file_path}")

        return self.security.get_safe_file_info(path)


    async def write_file(
        self,
        file_path: str,
        content: str,
        encoding: str = "utf-8",
        create_dirs: bool = False
    ) -> Dict[str, Any]:
        """파일 쓰기/생성"""
        self.security.check_write_permission()
        path = self.security.validate_path(file_path)
        
        if create_dirs and not path.parent.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
        
        if not path.parent.exists():
            raise FileNotFoundError(f"Parent directory not found: {path.parent}")
        
        existed = path.exists()
        
        try:
            async with aiofiles.open(path, mode='w', encoding=encoding) as f:
                await f.write(content)
            
            stat_info = path.stat()
            return {
                "path": str(path),
                "size": stat_info.st_size,
                "lines": content.count('\n') + 1,
                "encoding": encoding,
                "created": not existed,
                "success": True
            }
        except PermissionError:
            raise AccessDeniedError(f"Permission denied: {file_path}")

    async def create_directory(self, dir_path: str, parents: bool = True) -> Dict[str, Any]:
        """디렉토리 생성"""
        self.security.check_write_permission()
        path = self.security.validate_path(dir_path)
        
        if path.exists():
            return {"path": str(path), "created": False, "exists": True, "success": True}
        
        try:
            path.mkdir(parents=parents, exist_ok=True)
            return {"path": str(path), "created": True, "exists": True, "success": True}
        except PermissionError:
            raise AccessDeniedError(f"Permission denied: {dir_path}")

    async def delete_file(self, file_path: str) -> Dict[str, Any]:
        """파일 삭제"""
        self.security.check_write_permission()
        path = self.security.validate_path(file_path)
        
        if not path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        if not path.is_file():
            raise ValueError(f"Not a file: {file_path}")
        
        try:
            path.unlink()
            return {"path": str(path), "deleted": True, "success": True}
        except PermissionError:
            raise AccessDeniedError(f"Permission denied: {file_path}")

    async def search_files(
        self,
        directory: str,
        query: str,
        file_pattern: str = "*",
        case_sensitive: bool = False,
        max_results: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """
        파일 내용 검색

        Args:
            directory: 검색 디렉토리
            query: 검색어
            file_pattern: 파일 필터 패턴
            case_sensitive: 대소문자 구분
            max_results: 최대 결과 수

        Returns:
            검색 결과 리스트
        """
        # 보안 검증
        path = self.security.validate_path(directory)

        if not path.exists() or not path.is_dir():
            raise FileNotFoundError(f"Directory not found: {directory}")

        results = []
        max_results = max_results or self.config.filesystem.max_search_results
        search_query = query if case_sensitive else query.lower()

        for file_path in path.rglob(file_pattern):
            if len(results) >= max_results:
                break

            if not file_path.is_file():
                continue

            try:
                # 보안 검증
                self.security.validate_path(str(file_path))
                self.security.check_file_size(file_path)

                # 파일 읽기
                async with aiofiles.open(file_path, 'r', encoding='utf-8') as f:
                    content = await f.read()

                search_content = content if case_sensitive else content.lower()

                if search_query in search_content:
                    # 매칭 라인 찾기
                    matches = []
                    for i, line in enumerate(content.split('\n'), 1):
                        search_line = line if case_sensitive else line.lower()
                        if search_query in search_line:
                            matches.append({
                                "line_number": i,
                                "content": line.strip()[:200]  # 200자 제한
                            })
                            if len(matches) >= 5:  # 파일당 최대 5개 매치
                                break

                    results.append({
                        "path": str(file_path),
                        "matches": matches,
                        "match_count": len(matches)
                    })

            except (SecurityError, UnicodeDecodeError, PermissionError):
                # 접근 불가 파일 건너뜀
                continue

        return results


# ============================================================================
# MCP Server
# ============================================================================

class MCPServer:
    """
    MCP (Model Context Protocol) 서버

    GPT Desktop과 통신하는 메인 서버 클래스
    """

    # MCP 프로토콜 버전
    PROTOCOL_VERSION = "2024-11-05"

    # 서버 정보
    SERVER_INFO = {
        "name": "gpt-filesystem-mcp",
        "version": "1.1.0",
        "description": "Local filesystem access for GPT Desktop (read/write)"
    }

    def __init__(self, config: AppConfig):
        self.config = config
        self.security = self._create_security_layer()
        self.file_ops = FileOperations(self.security, config)
        self.tools = self._define_tools()

    def _create_security_layer(self) -> SecurityLayer:
        """보안 레이어 생성"""
        from security import SecurityConfig as SecConfig

        sec_config = SecConfig(
            allowed_directories=self.config.filesystem.allowed_directories,
            blocked_patterns=self.config.security.blocked_file_patterns,
            blocked_directories=self.config.security.blocked_directories,
            max_file_size=self.config.filesystem.max_file_size,
            max_lines=self.config.filesystem.max_lines,
            max_directory_items=self.config.filesystem.max_directory_items,
            max_search_results=self.config.filesystem.max_search_results,
            access_mode=AccessMode.READ_WRITE if self.config.filesystem.write_enabled else AccessMode.READ_ONLY,
            follow_symlinks=self.config.filesystem.follow_symlinks,
        )

        return SecurityLayer(sec_config)

    def _define_tools(self) -> List[MCPTool]:
        """MCP Tools 정의"""
        tools = [
            MCPTool(
                name="list_files",
                description="디렉토리의 파일 및 폴더 목록을 조회합니다. 허용된 디렉토리 내에서만 작동합니다.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "조회할 디렉토리 경로"
                        },
                        "pattern": {
                            "type": "string",
                            "description": "파일 필터 패턴 (예: *.py, *.txt)",
                            "default": "*"
                        },
                        "recursive": {
                            "type": "boolean",
                            "description": "하위 디렉토리 포함 여부",
                            "default": False
                        }
                    },
                    "required": ["path"]
                }
            ),
            MCPTool(
                name="read_file",
                description="파일의 내용을 읽습니다. 텍스트 파일만 지원합니다.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "읽을 파일의 경로"
                        },
                        "encoding": {
                            "type": "string",
                            "description": "문자 인코딩",
                            "default": "utf-8"
                        },
                        "start_line": {
                            "type": "integer",
                            "description": "시작 라인 번호 (1부터 시작)"
                        },
                        "end_line": {
                            "type": "integer",
                            "description": "끝 라인 번호"
                        }
                    },
                    "required": ["path"]
                }
            ),
            MCPTool(
                name="get_file_info",
                description="파일 또는 디렉토리의 메타데이터를 조회합니다 (크기, 수정일 등).",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "파일 또는 디렉토리 경로"
                        }
                    },
                    "required": ["path"]
                }
            ),
            MCPTool(
                name="search_files",
                description="지정된 디렉토리에서 파일 내용을 검색합니다.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "검색할 디렉토리 경로"
                        },
                        "query": {
                            "type": "string",
                            "description": "검색어"
                        },
                        "pattern": {
                            "type": "string",
                            "description": "파일 필터 패턴 (예: *.py)",
                            "default": "*"
                        },
                        "case_sensitive": {
                            "type": "boolean",
                            "description": "대소문자 구분",
                            "default": False
                        }
                    },
                    "required": ["path", "query"]
                }
            ),
            MCPTool(
                name="get_allowed_directories",
                description="접근 가능한 디렉토리 목록을 반환합니다.",
                inputSchema={
                    "type": "object",
                    "properties": {}
                }
            ),
        ]
        
        if self.config.filesystem.write_enabled:
            tools.extend([
                MCPTool(
                    name="write_file",
                    description="파일을 생성하거나 덮어씁니다.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "path": {"type": "string", "description": "파일 경로"},
                            "content": {"type": "string", "description": "파일 내용"},
                            "encoding": {"type": "string", "default": "utf-8"},
                            "create_dirs": {"type": "boolean", "default": False}
                        },
                        "required": ["path", "content"]
                    }
                ),
                MCPTool(
                    name="create_directory",
                    description="디렉토리를 생성합니다.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "path": {"type": "string", "description": "디렉토리 경로"},
                            "parents": {"type": "boolean", "default": True}
                        },
                        "required": ["path"]
                    }
                ),
                MCPTool(
                    name="delete_file",
                    description="파일을 삭제합니다.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "path": {"type": "string", "description": "파일 경로"}
                        },
                        "required": ["path"]
                    }
                ),
            ])
        
        return tools

    async def handle_initialize(self, params: Dict) -> Dict:
        """MCP initialize 핸들러"""
        return {
            "protocolVersion": self.PROTOCOL_VERSION,
            "serverInfo": self.SERVER_INFO,
            "capabilities": {
                "tools": {}
            }
        }

    async def handle_list_tools(self) -> Dict:
        """tools/list 핸들러"""
        return {
            "tools": [
                {
                    "name": tool.name,
                    "description": tool.description,
                    "inputSchema": tool.inputSchema
                }
                for tool in self.tools
            ]
        }

    async def handle_call_tool(self, params: Dict) -> Dict:
        """tools/call 핸들러"""
        tool_name = params.get("name")
        arguments = params.get("arguments", {})

        logger.info(f"Tool call: {tool_name} with args: {arguments}")

        try:
            if tool_name == "list_files":
                result = await self.file_ops.list_files(
                    directory=arguments["path"],
                    pattern=arguments.get("pattern", "*"),
                    recursive=arguments.get("recursive", False)
                )
                return {"content": [{"type": "text", "text": json.dumps(result, indent=2, ensure_ascii=False)}]}

            elif tool_name == "read_file":
                result = await self.file_ops.read_file(
                    file_path=arguments["path"],
                    encoding=arguments.get("encoding", "utf-8"),
                    start_line=arguments.get("start_line"),
                    end_line=arguments.get("end_line")
                )
                return {"content": [{"type": "text", "text": json.dumps(result, indent=2, ensure_ascii=False)}]}

            elif tool_name == "get_file_info":
                result = await self.file_ops.get_file_info(
                    file_path=arguments["path"]
                )
                return {"content": [{"type": "text", "text": json.dumps(result, indent=2, ensure_ascii=False)}]}

            elif tool_name == "search_files":
                result = await self.file_ops.search_files(
                    directory=arguments["path"],
                    query=arguments["query"],
                    file_pattern=arguments.get("pattern", "*"),
                    case_sensitive=arguments.get("case_sensitive", False)
                )
                return {"content": [{"type": "text", "text": json.dumps(result, indent=2, ensure_ascii=False)}]}

            elif tool_name == "get_allowed_directories":
                result = {
                    "allowed_directories": self.config.filesystem.allowed_directories,
                    "write_enabled": self.config.filesystem.write_enabled,
                    "max_file_size": self.config.filesystem.max_file_size
                }
                return {"content": [{"type": "text", "text": json.dumps(result, indent=2, ensure_ascii=False)}]}

            elif tool_name == "write_file":
                result = await self.file_ops.write_file(
                    file_path=arguments["path"],
                    content=arguments["content"],
                    encoding=arguments.get("encoding", "utf-8"),
                    create_dirs=arguments.get("create_dirs", False)
                )
                return {"content": [{"type": "text", "text": json.dumps(result, indent=2, ensure_ascii=False)}]}

            elif tool_name == "create_directory":
                result = await self.file_ops.create_directory(
                    dir_path=arguments["path"],
                    parents=arguments.get("parents", True)
                )
                return {"content": [{"type": "text", "text": json.dumps(result, indent=2, ensure_ascii=False)}]}

            elif tool_name == "delete_file":
                result = await self.file_ops.delete_file(
                    file_path=arguments["path"]
                )
                return {"content": [{"type": "text", "text": json.dumps(result, indent=2, ensure_ascii=False)}]}

            else:
                raise ValueError(f"Unknown tool: {tool_name}")

        except FileNotFoundError as e:
            return {"content": [{"type": "text", "text": f"Error: {e}"}], "isError": True}
        except SecurityError as e:
            return {"content": [{"type": "text", "text": f"Security Error: {e}"}], "isError": True}
        except Exception as e:
            logger.error(f"Tool error: {e}")
            return {"content": [{"type": "text", "text": f"Error: {e}"}], "isError": True}

    async def handle_request(self, request: MCPRequest) -> MCPResponse:
        """MCP 요청 처리"""
        try:
            if request.method == "initialize":
                result = await self.handle_initialize(request.params or {})
            elif request.method == "tools/list":
                result = await self.handle_list_tools()
            elif request.method == "tools/call":
                result = await self.handle_call_tool(request.params or {})
            elif request.method == "ping":
                result = {}
            else:
                return MCPResponse(
                    error={"code": -32601, "message": f"Method not found: {request.method}"},
                    id=request.id
                )

            return MCPResponse(result=result, id=request.id)

        except Exception as e:
            logger.error(f"Request error: {e}")
            return MCPResponse(
                error={"code": -32603, "message": str(e)},
                id=request.id
            )


# ============================================================================
# FastAPI Application
# ============================================================================

def create_app(config: Optional[AppConfig] = None) -> FastAPI:
    """FastAPI 애플리케이션 생성"""

    if config is None:
        config = get_config()

    # MCP 서버 생성
    mcp_server = MCPServer(config)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        logger.info("=" * 50)
        logger.info("GPT MCP Server Starting")
        logger.info(f"Allowed directories: {config.filesystem.allowed_directories}")
        logger.info(f"Write enabled: {config.filesystem.write_enabled}")
        logger.info("=" * 50)
        yield
        logger.info("GPT MCP Server Shutting down")

    app = FastAPI(
        title="GPT MCP Server",
        description="MCP Server for GPT Desktop - Local Filesystem Access",
        version="1.1.0",
        lifespan=lifespan
    )

    # CORS 설정
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/")
    async def root():
        """서버 상태 확인"""
        return {
            "status": "running",
            "server": MCPServer.SERVER_INFO,
            "protocol_version": MCPServer.PROTOCOL_VERSION,
            "write_enabled": config.filesystem.write_enabled
        }

    @app.get("/health")
    async def health():
        """헬스체크"""
        return {"status": "healthy"}

    @app.post("/mcp")
    async def mcp_endpoint(request: Request):
        """MCP JSON-RPC 엔드포인트"""
        try:
            body = await request.json()
            logger.debug(f"MCP Request: {body}")

            mcp_request = MCPRequest(
                jsonrpc=body.get("jsonrpc", "2.0"),
                method=body.get("method", ""),
                params=body.get("params"),
                id=body.get("id")
            )

            response = await mcp_server.handle_request(mcp_request)
            return JSONResponse(content=response.to_dict())

        except Exception as e:
            logger.error(f"MCP endpoint error: {e}")
            return JSONResponse(
                content={
                    "jsonrpc": "2.0",
                    "error": {"code": -32700, "message": str(e)},
                    "id": None
                },
                status_code=400
            )

    @app.get("/sse")
    async def sse_endpoint(request: Request):
        """SSE 엔드포인트 (MCP over SSE)"""

        async def event_generator() -> AsyncIterator[str]:
            # 연결 시 서버 정보 전송
            init_event = {
                "jsonrpc": "2.0",
                "method": "notifications/initialized",
                "params": {"serverInfo": MCPServer.SERVER_INFO}
            }
            yield f"data: {json.dumps(init_event)}\n\n"

            # Keep-alive
            while True:
                if await request.is_disconnected():
                    break
                yield f": keep-alive\n\n"
                await asyncio.sleep(30)

        return StreamingResponse(
            event_generator(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no"
            }
        )

    return app


# ============================================================================
# Main Entry Point
# ============================================================================

def main():
    """메인 실행 함수"""
    # 설정 로드
    config = get_config()

    # 설정 파일이 없으면 생성
    config_path = Path(__file__).parent / "config.yaml"
    if not config_path.exists():
        create_default_config_file(str(config_path))
        logger.info(f"Created default config file: {config_path}")
        logger.info("Please edit config.yaml to set allowed directories")

    # 로그 레벨 설정
    logging.getLogger().setLevel(getattr(logging, config.server.log_level.upper()))

    # 서버 시작 정보
    print("\n" + "=" * 60)
    print("  GPT MCP Server v1.1.0")
    print("=" * 60)
    print(f"  Host: {config.server.host}")
    print(f"  Port: {config.server.port}")
    print(f"  Debug: {config.server.debug}")
    print(f"  Write Enabled: {config.filesystem.write_enabled}")
    print("-" * 60)
    print("  Allowed Directories:")
    for d in config.filesystem.allowed_directories:
        print(f"    - {d}")
    print("-" * 60)
    print("  Next Steps:")
    print("    1. Run: ngrok http 8765")
    print("    2. Copy the HTTPS URL")
    print("    3. Add to ChatGPT MCP settings")
    print("=" * 60 + "\n")

    # FastAPI 앱 생성 및 실행
    app = create_app(config)

    uvicorn.run(
        app,
        host=config.server.host,
        port=config.server.port,
        log_level=config.server.log_level.lower(),
    )


if __name__ == "__main__":
    main()
