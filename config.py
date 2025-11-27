"""
GPT MCP Server - Configuration Management
==========================================
설계: Kevin Zhang (DevOps Lead)

설정 관리 원칙:
1. 환경별 설정 분리
2. 기본값 제공
3. 환경 변수 오버라이드
4. 설정 검증
"""

import os
import yaml
from pathlib import Path
from typing import List, Optional, Any, Dict
from dataclasses import dataclass, field, asdict
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class Environment(Enum):
    """실행 환경"""
    DEVELOPMENT = "development"
    PRODUCTION = "production"
    TEST = "test"


@dataclass
class ServerConfig:
    """서버 설정"""
    host: str = "127.0.0.1"
    port: int = 8765
    debug: bool = False
    log_level: str = "INFO"


@dataclass
class FilesystemConfig:
    """파일시스템 설정"""
    # 허용된 디렉토리
    allowed_directories: List[str] = field(default_factory=list)

    # 파일 크기 제한 (바이트)
    max_file_size: int = 10 * 1024 * 1024  # 10MB

    # 디렉토리 목록 최대 항목
    max_directory_items: int = 1000

    # 검색 결과 최대 개수
    max_search_results: int = 100

    # 최대 읽기 라인 수
    max_lines: int = 10000

    # 허용된 확장자 (빈 리스트면 모두 허용)
    allowed_extensions: List[str] = field(default_factory=list)

    # 쓰기 모드 활성화
    write_enabled: bool = False

    # 심볼릭 링크 따라가기
    follow_symlinks: bool = False


@dataclass
class SecurityConfig:
    """보안 설정"""
    # 차단할 파일 패턴
    blocked_file_patterns: List[str] = field(default_factory=lambda: [
        r"^\.env$",
        r"^\.env\..+$",
        r".*secret.*",
        r".*credential.*",
        r".*password.*",
        r".*\.pem$",
        r".*\.key$",
        r".*api[_-]?key.*",
    ])

    # 차단할 디렉토리
    blocked_directories: List[str] = field(default_factory=lambda: [
        r"\.git",
        r"\.ssh",
        r"node_modules",
        r"__pycache__",
    ])

    # 컨텐츠 민감 정보 마스킹
    mask_sensitive_content: bool = True

    # Rate Limiting (초당 요청 수)
    rate_limit: int = 60


@dataclass
class AppConfig:
    """전체 애플리케이션 설정"""
    environment: str = "development"
    server: ServerConfig = field(default_factory=ServerConfig)
    filesystem: FilesystemConfig = field(default_factory=FilesystemConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)

    def __post_init__(self):
        """기본 디렉토리 설정"""
        if not self.filesystem.allowed_directories:
            # 기본: 사용자 문서 폴더
            self.filesystem.allowed_directories = [
                str(Path.home() / "Documents")
            ]


class ConfigLoader:
    """
    설정 로더

    우선순위:
    1. 환경 변수
    2. 설정 파일 (config.yaml)
    3. 기본값
    """

    CONFIG_FILE_NAME = "config.yaml"
    ENV_PREFIX = "GPT_MCP_"

    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path or self._find_config_file()

    def _find_config_file(self) -> Optional[str]:
        """설정 파일 찾기"""
        # 현재 디렉토리
        current = Path.cwd() / self.CONFIG_FILE_NAME
        if current.exists():
            return str(current)

        # 스크립트 디렉토리
        script_dir = Path(__file__).parent / self.CONFIG_FILE_NAME
        if script_dir.exists():
            return str(script_dir)

        return None

    def load(self) -> AppConfig:
        """설정 로드"""
        config = AppConfig()

        # 1. 설정 파일에서 로드
        if self.config_path and Path(self.config_path).exists():
            config = self._load_from_file(config)
            logger.info(f"Loaded config from: {self.config_path}")

        # 2. 환경 변수로 오버라이드
        config = self._override_from_env(config)

        # 3. 설정 검증
        self._validate(config)

        return config

    def _load_from_file(self, config: AppConfig) -> AppConfig:
        """YAML 파일에서 설정 로드"""
        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f) or {}

            # 환경
            if 'environment' in data:
                config.environment = data['environment']

            # 서버 설정
            if 'server' in data:
                server_data = data['server']
                config.server = ServerConfig(
                    host=server_data.get('host', config.server.host),
                    port=server_data.get('port', config.server.port),
                    debug=server_data.get('debug', config.server.debug),
                    log_level=server_data.get('log_level', config.server.log_level),
                )

            # 파일시스템 설정
            if 'filesystem' in data:
                fs_data = data['filesystem']
                config.filesystem = FilesystemConfig(
                    allowed_directories=fs_data.get(
                        'allowed_directories',
                        config.filesystem.allowed_directories
                    ),
                    max_file_size=fs_data.get(
                        'max_file_size',
                        config.filesystem.max_file_size
                    ),
                    max_directory_items=fs_data.get(
                        'max_directory_items',
                        config.filesystem.max_directory_items
                    ),
                    max_search_results=fs_data.get(
                        'max_search_results',
                        config.filesystem.max_search_results
                    ),
                    max_lines=fs_data.get(
                        'max_lines',
                        config.filesystem.max_lines
                    ),
                    allowed_extensions=fs_data.get(
                        'allowed_extensions',
                        config.filesystem.allowed_extensions
                    ),
                    write_enabled=fs_data.get(
                        'write_enabled',
                        config.filesystem.write_enabled
                    ),
                    follow_symlinks=fs_data.get(
                        'follow_symlinks',
                        config.filesystem.follow_symlinks
                    ),
                )

            # 보안 설정
            if 'security' in data:
                sec_data = data['security']
                config.security = SecurityConfig(
                    blocked_file_patterns=sec_data.get(
                        'blocked_file_patterns',
                        config.security.blocked_file_patterns
                    ),
                    blocked_directories=sec_data.get(
                        'blocked_directories',
                        config.security.blocked_directories
                    ),
                    mask_sensitive_content=sec_data.get(
                        'mask_sensitive_content',
                        config.security.mask_sensitive_content
                    ),
                    rate_limit=sec_data.get(
                        'rate_limit',
                        config.security.rate_limit
                    ),
                )

        except Exception as e:
            logger.error(f"Error loading config file: {e}")

        return config

    def _override_from_env(self, config: AppConfig) -> AppConfig:
        """환경 변수로 설정 오버라이드"""
        # 서버 설정
        if os.getenv(f"{self.ENV_PREFIX}HOST"):
            config.server.host = os.getenv(f"{self.ENV_PREFIX}HOST")

        if os.getenv(f"{self.ENV_PREFIX}PORT"):
            config.server.port = int(os.getenv(f"{self.ENV_PREFIX}PORT"))

        if os.getenv(f"{self.ENV_PREFIX}DEBUG"):
            config.server.debug = os.getenv(f"{self.ENV_PREFIX}DEBUG").lower() == "true"

        if os.getenv(f"{self.ENV_PREFIX}LOG_LEVEL"):
            config.server.log_level = os.getenv(f"{self.ENV_PREFIX}LOG_LEVEL")

        # 파일시스템 설정
        if os.getenv(f"{self.ENV_PREFIX}ALLOWED_DIRS"):
            dirs = os.getenv(f"{self.ENV_PREFIX}ALLOWED_DIRS").split(";")
            config.filesystem.allowed_directories = [d.strip() for d in dirs if d.strip()]

        if os.getenv(f"{self.ENV_PREFIX}MAX_FILE_SIZE"):
            config.filesystem.max_file_size = int(os.getenv(f"{self.ENV_PREFIX}MAX_FILE_SIZE"))

        if os.getenv(f"{self.ENV_PREFIX}WRITE_ENABLED"):
            config.filesystem.write_enabled = os.getenv(f"{self.ENV_PREFIX}WRITE_ENABLED").lower() == "true"

        return config

    def _validate(self, config: AppConfig) -> None:
        """설정 검증"""
        errors = []

        # 허용 디렉토리 검증
        for dir_path in config.filesystem.allowed_directories:
            path = Path(dir_path)
            if not path.exists():
                logger.warning(f"Allowed directory does not exist: {dir_path}")
            elif not path.is_dir():
                errors.append(f"Not a directory: {dir_path}")

        # 포트 범위 검증
        if not (1 <= config.server.port <= 65535):
            errors.append(f"Invalid port: {config.server.port}")

        # 파일 크기 제한 검증
        if config.filesystem.max_file_size < 1024:
            errors.append("max_file_size must be at least 1KB")

        if errors:
            raise ValueError(f"Configuration errors: {', '.join(errors)}")


def create_default_config_file(path: str) -> None:
    """기본 설정 파일 생성"""
    default_config = {
        'environment': 'development',
        'server': {
            'host': '127.0.0.1',
            'port': 8765,
            'debug': False,
            'log_level': 'INFO',
        },
        'filesystem': {
            'allowed_directories': [
                str(Path.home() / "Documents"),
            ],
            'max_file_size': 10485760,  # 10MB
            'max_directory_items': 1000,
            'max_search_results': 100,
            'max_lines': 10000,
            'allowed_extensions': [],  # 빈 리스트 = 모두 허용
            'write_enabled': False,
            'follow_symlinks': False,
        },
        'security': {
            'blocked_file_patterns': [
                r'^\.env$',
                r'^\.env\..+$',
                r'.*secret.*',
                r'.*credential.*',
                r'.*\.pem$',
                r'.*\.key$',
            ],
            'blocked_directories': [
                r'\.git',
                r'\.ssh',
                r'node_modules',
            ],
            'mask_sensitive_content': True,
            'rate_limit': 60,
        }
    }

    with open(path, 'w', encoding='utf-8') as f:
        yaml.dump(default_config, f, default_flow_style=False, allow_unicode=True)

    logger.info(f"Created default config file: {path}")


# 전역 설정 인스턴스
_app_config: Optional[AppConfig] = None


def get_config(reload: bool = False) -> AppConfig:
    """설정 싱글톤 획득"""
    global _app_config

    if _app_config is None or reload:
        loader = ConfigLoader()
        _app_config = loader.load()

    return _app_config


def reset_config() -> None:
    """설정 리셋 (테스트용)"""
    global _app_config
    _app_config = None
