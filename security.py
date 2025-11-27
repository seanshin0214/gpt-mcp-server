"""
GPT MCP Server - Security Layer
================================
설계: Robert Chen (Security Lead)

보안 원칙:
1. 최소 권한 원칙 (Least Privilege)
2. 심층 방어 (Defense in Depth)
3. 기본 거부 (Default Deny)
"""

import os
import re
import stat
from pathlib import Path
from typing import List, Optional, Set
from dataclasses import dataclass, field
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class SecurityError(Exception):
    """보안 관련 예외"""
    pass


class AccessDeniedError(SecurityError):
    """접근 거부 예외"""
    pass


class PathTraversalError(SecurityError):
    """경로 조작 시도 예외"""
    pass


class FileTooLargeError(SecurityError):
    """파일 크기 초과 예외"""
    pass


class BlockedFileError(SecurityError):
    """차단된 파일 접근 예외"""
    pass


class AccessMode(Enum):
    """접근 모드"""
    READ_ONLY = "read_only"
    READ_WRITE = "read_write"


@dataclass
class SecurityConfig:
    """보안 설정"""
    # 허용된 디렉토리 (화이트리스트)
    allowed_directories: List[str] = field(default_factory=list)

    # 차단할 파일 패턴 (정규식)
    blocked_patterns: List[str] = field(default_factory=lambda: [
        r"^\.env$",                    # .env
        r"^\.env\..+$",                # .env.local, .env.production
        r".*secret.*",                 # any file with 'secret'
        r".*credential.*",             # any file with 'credential'
        r".*password.*",               # any file with 'password'
        r".*\.pem$",                   # SSL certificates
        r".*\.key$",                   # Private keys
        r".*\.p12$",                   # PKCS#12 files
        r".*\.pfx$",                   # PFX files
        r"^id_rsa.*",                  # SSH private keys
        r"^id_ed25519.*",              # SSH ED25519 keys
        r".*\.ssh.*",                  # SSH config
        r"^\.git$",                    # Git directory
        r"^\.gitconfig$",              # Git config
        r".*api[_-]?key.*",            # API keys
        r".*token.*\.json$",           # Token files
        r"^config\.json$",             # Common config (may contain secrets)
        r"^secrets\..*",               # Secrets files
    ])

    # 차단할 디렉토리 패턴
    blocked_directories: List[str] = field(default_factory=lambda: [
        r"\.git",
        r"\.ssh",
        r"node_modules",
        r"__pycache__",
        r"\.venv",
        r"venv",
    ])

    # 허용된 파일 확장자 (빈 리스트면 모두 허용)
    allowed_extensions: List[str] = field(default_factory=list)

    # 파일 크기 제한 (바이트)
    max_file_size: int = 10 * 1024 * 1024  # 10MB

    # 읽을 수 있는 최대 라인 수
    max_lines: int = 10000

    # 디렉토리 목록 최대 항목 수
    max_directory_items: int = 1000

    # 검색 결과 최대 개수
    max_search_results: int = 100

    # 접근 모드
    access_mode: AccessMode = AccessMode.READ_ONLY

    # 심볼릭 링크 따라가기 허용
    follow_symlinks: bool = False


class SecurityLayer:
    """
    파일 접근 보안 레이어

    Robert Chen의 보안 설계 원칙:
    1. 모든 경로는 정규화 후 검증
    2. 화이트리스트 기반 접근 제어
    3. 민감 파일 패턴 차단
    4. 크기 제한으로 DoS 방지
    """

    def __init__(self, config: SecurityConfig):
        self.config = config
        self._compiled_blocked_patterns: List[re.Pattern] = []
        self._compiled_blocked_dirs: List[re.Pattern] = []
        self._allowed_paths: Set[Path] = set()

        self._compile_patterns()
        self._resolve_allowed_directories()

    def _compile_patterns(self) -> None:
        """정규식 패턴 컴파일 (성능 최적화)"""
        self._compiled_blocked_patterns = [
            re.compile(pattern, re.IGNORECASE)
            for pattern in self.config.blocked_patterns
        ]
        self._compiled_blocked_dirs = [
            re.compile(pattern, re.IGNORECASE)
            for pattern in self.config.blocked_directories
        ]

    def _resolve_allowed_directories(self) -> None:
        """허용된 디렉토리 경로 정규화"""
        for dir_path in self.config.allowed_directories:
            try:
                resolved = Path(dir_path).resolve()
                if resolved.exists() and resolved.is_dir():
                    self._allowed_paths.add(resolved)
                    logger.info(f"Allowed directory: {resolved}")
                else:
                    logger.warning(f"Allowed directory not found: {dir_path}")
            except Exception as e:
                logger.error(f"Error resolving directory {dir_path}: {e}")

    def validate_path(self, requested_path: str) -> Path:
        """
        경로 검증 (핵심 보안 함수)

        검증 단계:
        1. 경로 정규화 (Path Traversal 방지)
        2. 허용된 디렉토리 내 확인
        3. 심볼릭 링크 검증
        4. 차단 패턴 확인
        5. 확장자 검증

        Args:
            requested_path: 요청된 경로

        Returns:
            검증된 Path 객체

        Raises:
            PathTraversalError: 경로 조작 시도
            AccessDeniedError: 접근 거부
            BlockedFileError: 차단된 파일
        """
        try:
            # 1. 경로 정규화
            path = Path(requested_path)

            # 심볼릭 링크 처리
            if self.config.follow_symlinks:
                resolved = path.resolve()
            else:
                # 심볼릭 링크를 따라가지 않고 정규화
                resolved = path.resolve()
                if path.is_symlink():
                    raise AccessDeniedError(
                        f"Symbolic links not allowed: {requested_path}"
                    )

            # 2. 허용된 디렉토리 내에 있는지 확인
            is_allowed = any(
                self._is_subpath(resolved, allowed_dir)
                for allowed_dir in self._allowed_paths
            )

            if not is_allowed:
                logger.warning(f"Access denied - outside allowed directories: {resolved}")
                raise AccessDeniedError(
                    f"Access denied: path is outside allowed directories"
                )

            # 3. 경로의 각 부분에서 차단된 디렉토리 확인
            for part in resolved.parts:
                for pattern in self._compiled_blocked_dirs:
                    if pattern.match(part):
                        logger.warning(f"Blocked directory pattern matched: {part}")
                        raise AccessDeniedError(
                            f"Access denied: blocked directory in path"
                        )

            # 4. 파일명 차단 패턴 확인
            filename = resolved.name
            for pattern in self._compiled_blocked_patterns:
                if pattern.match(filename):
                    logger.warning(f"Blocked file pattern matched: {filename}")
                    raise BlockedFileError(
                        f"Access denied: file matches blocked pattern"
                    )

            # 5. 확장자 검증 (설정된 경우)
            if self.config.allowed_extensions and resolved.is_file():
                ext = resolved.suffix.lower()
                if ext and ext not in self.config.allowed_extensions:
                    raise AccessDeniedError(
                        f"Access denied: file extension not allowed"
                    )

            logger.debug(f"Path validated: {resolved}")
            return resolved

        except (AccessDeniedError, BlockedFileError, PathTraversalError):
            raise
        except Exception as e:
            logger.error(f"Path validation error: {e}")
            raise PathTraversalError(f"Invalid path: {requested_path}")

    def _is_subpath(self, path: Path, parent: Path) -> bool:
        """path가 parent의 하위 경로인지 확인"""
        try:
            path.relative_to(parent)
            return True
        except ValueError:
            return False

    def check_file_size(self, path: Path) -> None:
        """
        파일 크기 검증

        Args:
            path: 검증할 파일 경로

        Raises:
            FileTooLargeError: 파일 크기 초과
        """
        if not path.exists():
            return

        if path.is_file():
            size = path.stat().st_size
            if size > self.config.max_file_size:
                raise FileTooLargeError(
                    f"File too large: {size:,} bytes "
                    f"(max: {self.config.max_file_size:,} bytes)"
                )

    def check_write_permission(self) -> None:
        """쓰기 권한 확인"""
        if self.config.access_mode != AccessMode.READ_WRITE:
            raise AccessDeniedError(
                "Write operations not allowed in read-only mode"
            )

    def sanitize_content(self, content: str) -> str:
        """
        컨텐츠 정제 (민감 정보 마스킹)

        API 키, 토큰 등을 마스킹
        """
        # API 키 패턴 마스킹
        patterns = [
            (r'(api[_-]?key\s*[=:]\s*["\']?)([a-zA-Z0-9_-]{20,})(["\']?)',
             r'\1[REDACTED]\3'),
            (r'(token\s*[=:]\s*["\']?)([a-zA-Z0-9_.-]{20,})(["\']?)',
             r'\1[REDACTED]\3'),
            (r'(password\s*[=:]\s*["\']?)([^\s"\']+)(["\']?)',
             r'\1[REDACTED]\3'),
            (r'(secret\s*[=:]\s*["\']?)([^\s"\']+)(["\']?)',
             r'\1[REDACTED]\3'),
        ]

        result = content
        for pattern, replacement in patterns:
            result = re.sub(pattern, replacement, result, flags=re.IGNORECASE)

        return result

    def get_safe_file_info(self, path: Path) -> dict:
        """안전한 파일 정보 반환"""
        try:
            stat_info = path.stat()
            return {
                "name": path.name,
                "path": str(path),
                "size": stat_info.st_size,
                "is_file": path.is_file(),
                "is_dir": path.is_dir(),
                "modified": stat_info.st_mtime,
                "created": stat_info.st_ctime,
                "readable": os.access(path, os.R_OK),
                "extension": path.suffix.lower() if path.is_file() else None,
            }
        except Exception as e:
            logger.error(f"Error getting file info: {e}")
            return {
                "name": path.name,
                "path": str(path),
                "error": str(e)
            }


def create_default_security_config() -> SecurityConfig:
    """기본 보안 설정 생성"""
    # 사용자 문서 폴더를 기본 허용 디렉토리로
    user_docs = str(Path.home() / "Documents")

    return SecurityConfig(
        allowed_directories=[user_docs],
        access_mode=AccessMode.READ_ONLY,
        follow_symlinks=False,
    )


# 싱글톤 인스턴스
_security_layer: Optional[SecurityLayer] = None


def get_security_layer(config: Optional[SecurityConfig] = None) -> SecurityLayer:
    """보안 레이어 싱글톤 획득"""
    global _security_layer

    if _security_layer is None:
        if config is None:
            config = create_default_security_config()
        _security_layer = SecurityLayer(config)

    return _security_layer


def reset_security_layer() -> None:
    """보안 레이어 리셋 (테스트용)"""
    global _security_layer
    _security_layer = None
