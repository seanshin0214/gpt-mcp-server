"""
GPT MCP Server - Advanced Tools
===============================
설계: James Park (Backend Lead)

고급 파일 분석 및 조작 도구
"""

import os
import re
import json
import hashlib
import mimetypes
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime
from dataclasses import dataclass
from collections import defaultdict
import asyncio

import aiofiles

from security import SecurityLayer, SecurityError


@dataclass
class FileStats:
    """파일 통계"""
    total_files: int = 0
    total_dirs: int = 0
    total_size: int = 0
    by_extension: Dict[str, int] = None
    largest_files: List[Dict] = None

    def __post_init__(self):
        if self.by_extension is None:
            self.by_extension = {}
        if self.largest_files is None:
            self.largest_files = []


class AdvancedTools:
    """
    고급 파일 도구

    추가 기능:
    - 디렉토리 트리 구조
    - 파일 통계 분석
    - 코드 분석 (라인 수, 함수 등)
    - 파일 비교
    - 중복 파일 찾기
    """

    def __init__(self, security: SecurityLayer):
        self.security = security

    async def get_directory_tree(
        self,
        directory: str,
        max_depth: int = 3,
        include_files: bool = True,
        pattern: str = "*"
    ) -> Dict[str, Any]:
        """
        디렉토리 트리 구조 생성

        Args:
            directory: 루트 디렉토리
            max_depth: 최대 깊이
            include_files: 파일 포함 여부
            pattern: 파일 필터 패턴

        Returns:
            트리 구조 딕셔너리
        """
        path = self.security.validate_path(directory)

        if not path.is_dir():
            raise ValueError(f"Not a directory: {directory}")

        def build_tree(current_path: Path, depth: int) -> Dict[str, Any]:
            if depth > max_depth:
                return {"name": current_path.name, "type": "dir", "truncated": True}

            node = {
                "name": current_path.name,
                "type": "dir",
                "path": str(current_path),
                "children": []
            }

            try:
                items = sorted(current_path.iterdir(), key=lambda x: (x.is_file(), x.name.lower()))

                for item in items:
                    try:
                        self.security.validate_path(str(item))
                    except SecurityError:
                        continue

                    if item.is_dir():
                        child = build_tree(item, depth + 1)
                        node["children"].append(child)
                    elif include_files and item.match(pattern):
                        node["children"].append({
                            "name": item.name,
                            "type": "file",
                            "path": str(item),
                            "size": item.stat().st_size,
                            "extension": item.suffix.lower()
                        })

            except PermissionError:
                node["error"] = "Permission denied"

            return node

        return build_tree(path, 0)

    async def analyze_directory(
        self,
        directory: str,
        recursive: bool = True
    ) -> Dict[str, Any]:
        """
        디렉토리 통계 분석

        Args:
            directory: 분석할 디렉토리
            recursive: 하위 디렉토리 포함

        Returns:
            통계 정보
        """
        path = self.security.validate_path(directory)

        if not path.is_dir():
            raise ValueError(f"Not a directory: {directory}")

        stats = FileStats()
        extension_counts = defaultdict(lambda: {"count": 0, "size": 0})
        all_files = []

        glob_func = path.rglob if recursive else path.glob

        for item in glob_func("*"):
            try:
                self.security.validate_path(str(item))
            except SecurityError:
                continue

            if item.is_file():
                stats.total_files += 1
                size = item.stat().st_size
                stats.total_size += size

                ext = item.suffix.lower() or "(no extension)"
                extension_counts[ext]["count"] += 1
                extension_counts[ext]["size"] += size

                all_files.append({
                    "path": str(item),
                    "name": item.name,
                    "size": size
                })

            elif item.is_dir():
                stats.total_dirs += 1

        # 확장자별 통계
        stats.by_extension = dict(extension_counts)

        # 가장 큰 파일 Top 10
        all_files.sort(key=lambda x: x["size"], reverse=True)
        stats.largest_files = all_files[:10]

        return {
            "path": str(path),
            "total_files": stats.total_files,
            "total_directories": stats.total_dirs,
            "total_size": stats.total_size,
            "total_size_human": self._format_size(stats.total_size),
            "by_extension": stats.by_extension,
            "largest_files": [
                {**f, "size_human": self._format_size(f["size"])}
                for f in stats.largest_files
            ]
        }

    async def analyze_code_file(
        self,
        file_path: str
    ) -> Dict[str, Any]:
        """
        코드 파일 분석

        Args:
            file_path: 파일 경로

        Returns:
            코드 분석 결과
        """
        path = self.security.validate_path(file_path)
        self.security.check_file_size(path)

        if not path.is_file():
            raise ValueError(f"Not a file: {file_path}")

        async with aiofiles.open(path, 'r', encoding='utf-8') as f:
            content = await f.read()

        lines = content.split('\n')
        total_lines = len(lines)
        blank_lines = sum(1 for line in lines if not line.strip())
        comment_lines = 0

        # 확장자에 따른 주석 패턴
        ext = path.suffix.lower()
        comment_patterns = {
            '.py': [r'^\s*#', r'^\s*"""', r"^\s*'''"],
            '.js': [r'^\s*//', r'^\s*/\*'],
            '.ts': [r'^\s*//', r'^\s*/\*'],
            '.java': [r'^\s*//', r'^\s*/\*'],
            '.c': [r'^\s*//', r'^\s*/\*'],
            '.cpp': [r'^\s*//', r'^\s*/\*'],
            '.go': [r'^\s*//'],
            '.rs': [r'^\s*//'],
            '.rb': [r'^\s*#'],
            '.sh': [r'^\s*#'],
        }

        patterns = comment_patterns.get(ext, [])
        for line in lines:
            for pattern in patterns:
                if re.match(pattern, line):
                    comment_lines += 1
                    break

        code_lines = total_lines - blank_lines - comment_lines

        # 함수/클래스 탐지 (간단한 패턴)
        function_patterns = {
            '.py': r'^(?:async\s+)?def\s+(\w+)',
            '.js': r'(?:function\s+(\w+)|(\w+)\s*=\s*(?:async\s+)?function|(\w+)\s*:\s*(?:async\s+)?function)',
            '.ts': r'(?:function\s+(\w+)|(\w+)\s*=\s*(?:async\s+)?function|(\w+)\s*:\s*(?:async\s+)?function)',
            '.java': r'(?:public|private|protected)?\s*(?:static\s+)?(?:\w+\s+)?(\w+)\s*\([^)]*\)\s*\{',
            '.go': r'^func\s+(?:\([^)]+\)\s+)?(\w+)',
        }

        class_patterns = {
            '.py': r'^class\s+(\w+)',
            '.js': r'^class\s+(\w+)',
            '.ts': r'^(?:export\s+)?(?:abstract\s+)?class\s+(\w+)',
            '.java': r'^(?:public|private)?\s*(?:abstract\s+)?class\s+(\w+)',
        }

        functions = []
        classes = []

        func_pattern = function_patterns.get(ext)
        class_pattern = class_patterns.get(ext)

        for i, line in enumerate(lines, 1):
            if func_pattern:
                match = re.search(func_pattern, line)
                if match:
                    name = next((g for g in match.groups() if g), None)
                    if name:
                        functions.append({"name": name, "line": i})

            if class_pattern:
                match = re.search(class_pattern, line)
                if match:
                    classes.append({"name": match.group(1), "line": i})

        return {
            "path": str(path),
            "extension": ext,
            "size": path.stat().st_size,
            "lines": {
                "total": total_lines,
                "code": code_lines,
                "blank": blank_lines,
                "comment": comment_lines
            },
            "functions": functions[:50],  # 최대 50개
            "function_count": len(functions),
            "classes": classes[:20],  # 최대 20개
            "class_count": len(classes)
        }

    async def find_duplicates(
        self,
        directory: str,
        by_content: bool = True
    ) -> List[Dict[str, Any]]:
        """
        중복 파일 찾기

        Args:
            directory: 검색 디렉토리
            by_content: True면 내용 기준, False면 이름 기준

        Returns:
            중복 파일 그룹 리스트
        """
        path = self.security.validate_path(directory)

        if not path.is_dir():
            raise ValueError(f"Not a directory: {directory}")

        if by_content:
            # 파일 해시 기준
            hash_groups = defaultdict(list)

            for file_path in path.rglob("*"):
                if not file_path.is_file():
                    continue

                try:
                    self.security.validate_path(str(file_path))
                    self.security.check_file_size(file_path)

                    # 빠른 해시 (처음 64KB만)
                    async with aiofiles.open(file_path, 'rb') as f:
                        chunk = await f.read(65536)
                        file_hash = hashlib.md5(chunk).hexdigest()

                    hash_groups[file_hash].append({
                        "path": str(file_path),
                        "name": file_path.name,
                        "size": file_path.stat().st_size
                    })

                except (SecurityError, PermissionError):
                    continue

            # 중복만 필터링
            duplicates = [
                {"hash": h, "files": files}
                for h, files in hash_groups.items()
                if len(files) > 1
            ]

        else:
            # 파일 이름 기준
            name_groups = defaultdict(list)

            for file_path in path.rglob("*"):
                if not file_path.is_file():
                    continue

                try:
                    self.security.validate_path(str(file_path))
                    name_groups[file_path.name].append({
                        "path": str(file_path),
                        "size": file_path.stat().st_size
                    })
                except SecurityError:
                    continue

            duplicates = [
                {"name": name, "files": files}
                for name, files in name_groups.items()
                if len(files) > 1
            ]

        return duplicates[:50]  # 최대 50 그룹

    async def compare_files(
        self,
        file1: str,
        file2: str
    ) -> Dict[str, Any]:
        """
        두 파일 비교

        Args:
            file1: 첫 번째 파일
            file2: 두 번째 파일

        Returns:
            비교 결과
        """
        path1 = self.security.validate_path(file1)
        path2 = self.security.validate_path(file2)

        self.security.check_file_size(path1)
        self.security.check_file_size(path2)

        # 메타데이터 비교
        stat1 = path1.stat()
        stat2 = path2.stat()

        # 내용 읽기
        async with aiofiles.open(path1, 'r', encoding='utf-8') as f:
            content1 = await f.read()

        async with aiofiles.open(path2, 'r', encoding='utf-8') as f:
            content2 = await f.read()

        lines1 = content1.split('\n')
        lines2 = content2.split('\n')

        # 간단한 diff (추가/삭제된 라인)
        set1 = set(lines1)
        set2 = set(lines2)

        added = set2 - set1
        removed = set1 - set2
        common = set1 & set2

        return {
            "file1": {
                "path": str(path1),
                "size": stat1.st_size,
                "lines": len(lines1)
            },
            "file2": {
                "path": str(path2),
                "size": stat2.st_size,
                "lines": len(lines2)
            },
            "identical": content1 == content2,
            "diff_summary": {
                "common_lines": len(common),
                "added_lines": len(added),
                "removed_lines": len(removed)
            },
            "sample_added": list(added)[:10],
            "sample_removed": list(removed)[:10]
        }

    async def get_recent_files(
        self,
        directory: str,
        count: int = 20,
        pattern: str = "*"
    ) -> List[Dict[str, Any]]:
        """
        최근 수정된 파일 목록

        Args:
            directory: 검색 디렉토리
            count: 반환할 파일 수
            pattern: 파일 패턴

        Returns:
            최근 파일 리스트
        """
        path = self.security.validate_path(directory)

        if not path.is_dir():
            raise ValueError(f"Not a directory: {directory}")

        files = []

        for file_path in path.rglob(pattern):
            if not file_path.is_file():
                continue

            try:
                self.security.validate_path(str(file_path))
                stat = file_path.stat()
                files.append({
                    "path": str(file_path),
                    "name": file_path.name,
                    "size": stat.st_size,
                    "modified": stat.st_mtime,
                    "modified_iso": datetime.fromtimestamp(stat.st_mtime).isoformat()
                })
            except SecurityError:
                continue

        # 수정 시간 기준 정렬
        files.sort(key=lambda x: x["modified"], reverse=True)

        return files[:count]

    def _format_size(self, size: int) -> str:
        """바이트를 읽기 쉬운 형식으로 변환"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} PB"
