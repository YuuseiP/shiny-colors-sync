# -*- coding: utf-8 -*-
"""
SHINY COLORS 文件名修复程序
- 扫描 WebDAV 目录
- 找到错误命名的文件（如 *_unknown.zip）
- 根据数据库修复为正确的文件名
"""

import os
import sys
import re
import json
import logging
import argparse
from datetime import datetime

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


class Config:
    """配置管理"""
    def __init__(self, config_path=None):
        self.config_path = config_path or self._find_config()
        self._load_config()

    def _find_config(self):
        candidates = ['./config.yaml', './config.yml']
        for path in candidates:
            if os.path.exists(path):
                return path
        return None

    def _load_config(self):
        self.webdav_url = os.getenv('WEBDAV_URL', '')
        self.webdav_username = os.getenv('WEBDAV_USERNAME', '')
        self.webdav_password = os.getenv('WEBDAV_PASSWORD', '')
        self.webdav_base_path = os.getenv('WEBDAV_BASE_PATH', '/SHINY_COLORS')
        self.db_path = os.getenv('DB_PATH', './shiny_colors_db.json')
        self.formats = ['WAV', 'AIFF', 'ALAC', 'FLAC']

        if self.config_path and os.path.exists(self.config_path):
            try:
                import yaml
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    cfg = yaml.safe_load(f) or {}

                webdav = cfg.get('webdav', {})
                self.webdav_url = webdav.get('url', self.webdav_url)
                self.webdav_username = webdav.get('username', self.webdav_username)
                self.webdav_password = webdav.get('password', self.webdav_password)
                self.webdav_base_path = webdav.get('base_path', self.webdav_base_path)

                sync = cfg.get('sync', {})
                self.formats = sync.get('formats', self.formats)

                self.db_path = cfg.get('database', self.db_path)
                logger.info(f"Loaded config from: {self.config_path}")
            except Exception as e:
                logger.warning(f"Failed to load config: {e}")


class WebDAVClient:
    """WebDAV 客户端"""

    def __init__(self, config):
        self.config = config
        self.client = None
        self._init_client()

    def _init_client(self):
        if not self.config.webdav_url:
            logger.warning("WebDAV URL not configured")
            return

        try:
            from webdav3.client import Client
            self.client = Client({
                'webdav_hostname': self.config.webdav_url,
                'webdav_login': self.config.webdav_username,
                'webdav_password': self.config.webdav_password,
            })
            logger.info("WebDAV client initialized")
        except ImportError:
            logger.error("webdavclient3 not installed")
        except Exception as e:
            logger.error(f"Failed to init WebDAV client: {e}")

    def test_connection(self):
        if not self.client:
            return False, "WebDAV client not initialized"
        try:
            return self.client.check(), "WebDAV connection OK"
        except Exception as e:
            return False, str(e)

    def list_dir(self, path):
        """列出目录内容"""
        if not self.client:
            return []
        try:
            return self.client.list(path)
        except Exception as e:
            logger.warning(f"Failed to list {path}: {e}")
            return []

    def rename(self, old_path, new_path):
        """重命名/移动文件"""
        if not self.client:
            return False
        try:
            self.client.move(remote_path_from=old_path, remote_path_to=new_path)
            return True
        except Exception as e:
            logger.error(f"Failed to rename {old_path} -> {new_path}: {e}")
            return False

    def check_exists(self, path):
        """检查文件是否存在"""
        if not self.client:
            return False
        try:
            return self.client.check(path)
        except:
            return False

    def scan_files(self, base_path):
        """递归扫描所有文件"""
        all_files = {}

        def scan_dir(path):
            try:
                items = self.client.list(path)
                for item in items:
                    item_clean = item.rstrip('/')
                    path_clean = path.rstrip('/')

                    if item.startswith('/'):
                        full_path = item
                    else:
                        item_name = item_clean.split('/')[-1]
                        if path_clean.endswith(item_name):
                            continue
                        full_path = path_clean + '/' + item.lstrip('/')

                    if full_path.rstrip('/') == path_clean:
                        continue

                    if full_path.endswith('/'):
                        scan_dir(full_path)
                    else:
                        all_files[full_path] = item_clean.split('/')[-1]
            except Exception as e:
                logger.warning(f"Failed to scan {path}: {e}")

        scan_dir(base_path)
        return all_files


class NameFixer:
    """文件名修复器"""

    def __init__(self, db_path, formats):
        self.db_path = db_path
        self.formats = formats
        self.data = self._load()

    def _load(self):
        if not os.path.exists(self.db_path):
            logger.error(f"Database not found: {self.db_path}")
            return {"series": {}}
        with open(self.db_path, 'r', encoding='utf-8') as f:
            return json.load(f)

    def get_all_albums(self):
        albums = []
        for series_name, series_data in self.data.get("series", {}).items():
            for album in series_data.get("albums", []):
                album["_series_name"] = series_name
                albums.append(album)
        return albums

    def build_album_map(self):
        """构建专辑代码到信息的映射"""
        album_map = {}
        for album in self.get_all_albums():
            code = album.get("code")
            if code:
                # 获取最佳格式的下载链接
                downloads = album.get("downloads", [])
                gd_downloads = [d for d in downloads if d.get("source") == "google_drive"]

                best_format = "unknown"
                if gd_downloads:
                    # 按格式优先级排序
                    format_order = {fmt: i for i, fmt in enumerate(self.formats)}
                    gd_downloads.sort(key=lambda x: format_order.get(x.get("format", "").upper(), 999))
                    best_format = gd_downloads[0].get("format", "unknown")

                    # 只有有效格式才转大写，unknown 保持原样
                    if best_format and best_format.upper() in self.formats:
                        best_format = best_format.upper()
                    else:
                        best_format = "unknown"

                album_map[code] = {
                    "series": album.get("_series_name"),
                    "format": best_format
                }
        return album_map

    def get_expected_filename(self, album_code, album_map):
        """获取预期的正确文件名"""
        if album_code not in album_map:
            return None, None

        info = album_map[album_code]
        return f"{album_code}_{info['format']}.zip", info['format']

    def analyze_files(self, remote_files, album_map):
        """分析需要修复的文件"""
        fixes = []

        for full_path, filename in remote_files.items():
            # 解析文件名: {code}_{format}.zip
            match = re.match(r'^(.+)_([^_]+)\.zip$', filename)
            if not match:
                continue

            album_code = match.group(1)
            current_format = match.group(2)

            # 检查是否需要修复（只有当前格式是 unknown 且数据库有有效格式时才修复）
            if current_format.lower() == "unknown":
                expected_filename, expected_format = self.get_expected_filename(album_code, album_map)

                # 只有当预期格式是有效格式（不是 unknown）时才添加到修复列表
                if expected_filename and expected_format and expected_format.lower() != "unknown":
                    fixes.append({
                        "full_path": full_path,
                        "old_name": filename,
                        "new_name": expected_filename,
                        "album_code": album_code,
                        "old_format": current_format,
                        "new_format": expected_format
                    })

        return fixes


def main():
    parser = argparse.ArgumentParser(description='SHINY COLORS Filename Fixer')
    parser.add_argument('--dry-run', action='store_true', help='Preview mode, do not rename files')
    parser.add_argument('--config', '-c', type=str, help='Path to config file')
    parser.add_argument('--db', type=str, help='Path to database file')
    args = parser.parse_args()

    print("=" * 60)
    print("SHINY COLORS Filename Fixer")
    print("=" * 60)

    # 加载配置
    config = Config(args.config)
    if args.db:
        config.db_path = args.db

    if not config.webdav_url:
        print("Error: WebDAV URL not configured")
        sys.exit(1)

    # 初始化客户端
    webdav = WebDAVClient(config)

    # 测试连接
    success, message = webdav.test_connection()
    if not success:
        logger.error(f"WebDAV connection failed: {message}")
        sys.exit(1)

    print(f"WebDAV Connection: OK")
    print()

    # 构建专辑映射
    logger.info("Building album map from database...")
    fixer = NameFixer(config.db_path, config.formats)
    album_map = fixer.build_album_map()
    logger.info(f"Found {len(album_map)} albums in database")

    # 扫描远程文件
    logger.info("Scanning WebDAV files...")
    remote_files = webdav.scan_files(config.webdav_base_path)
    logger.info(f"Found {len(remote_files)} remote files")

    # 分析需要修复的文件
    logger.info("Analyzing files for fixes...")
    fixes = fixer.analyze_files(remote_files, album_map)

    print("-" * 60)

    if not fixes:
        logger.info("No files need to be fixed!")
        print("=" * 60)
        return

    logger.info(f"Found {len(fixes)} files to fix:")
    print()

    for fix in fixes:
        print(f"  [{fix['album_code']}] {fix['old_name']}")
        print(f"      -> {fix['new_name']} ({fix['old_format']} -> {fix['new_format']})")

    print("-" * 60)

    if args.dry_run:
        logger.info("[DRY RUN] No files were renamed")
        print("=" * 60)
        return

    # 执行重命名
    print()
    logger.info("Renaming files...")

    success_count = 0
    fail_count = 0

    for fix in fixes:
        old_path = fix['full_path']
        new_path = old_path.rsplit('/', 1)[0] + '/' + fix['new_name']

        # 检查目标是否已存在
        if webdav.check_exists(new_path):
            logger.warning(f"  Skip {fix['old_name']}: target already exists")
            fail_count += 1
            continue

        logger.info(f"  Renaming: {fix['old_name']} -> {fix['new_name']}")

        if webdav.rename(old_path, new_path):
            success_count += 1
            logger.info(f"    OK")
        else:
            fail_count += 1
            logger.error(f"    FAILED")

    print("-" * 60)
    logger.info(f"Done: {success_count} renamed, {fail_count} failed")
    print("=" * 60)


if __name__ == "__main__":
    main()
