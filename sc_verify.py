# -*- coding: utf-8 -*-
"""
SHINY COLORS 数据库验证程序
- 扫描 WebDAV 目录
- 对比数据库中的专辑
- 更新上传状态标记
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
        """查找配置文件"""
        candidates = [
            './config.yaml',
            './config.yml',
            os.path.expanduser('~/.config/sc_sync/config.yaml'),
        ]
        for path in candidates:
            if os.path.exists(path):
                return path
        return None

    def _load_config(self):
        """加载配置"""
        # 默认配置
        self.webdav_url = os.getenv('WEBDAV_URL', '')
        self.webdav_username = os.getenv('WEBDAV_USERNAME', '')
        self.webdav_password = os.getenv('WEBDAV_PASSWORD', '')
        self.webdav_base_path = os.getenv('WEBDAV_BASE_PATH', '/SHINY_COLORS')
        self.db_path = os.getenv('DB_PATH', './shiny_colors_db.json')
        self.formats = ['WAV', 'AIFF', 'ALAC', 'FLAC']

        # 尝试加载 YAML 配置
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
            except ImportError:
                logger.warning("PyYAML not installed, using environment variables")
            except Exception as e:
                logger.warning(f"Failed to load config: {e}")


class WebDAVScanner:
    """WebDAV 目录扫描器"""

    def __init__(self, config):
        self.config = config
        self.client = None
        self._init_client()

    def _init_client(self):
        """初始化 WebDAV 客户端"""
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
            logger.error("webdavclient3 not installed. Run: pip install webdavclient3")
        except Exception as e:
            logger.error(f"Failed to init WebDAV client: {e}")

    def test_connection(self):
        """测试连接"""
        if not self.client:
            return False, "WebDAV client not initialized"

        try:
            if self.client.check():
                return True, "WebDAV connection OK"
            return False, "WebDAV connection failed"
        except Exception as e:
            return False, str(e)

    def _get_size_direct(self, remote_path):
        """直接使用 requests 获取文件大小（备用方法）"""
        try:
            import requests
            from requests.auth import HTTPBasicAuth
            from lxml import etree

            full_url = self.config.webdav_url.rstrip('/') + remote_path

            headers = {
                'Depth': '0',
                'Content-Type': 'application/xml; charset=utf-8',
            }

            body = '''<?xml version="1.0" encoding="utf-8" ?>
<propfind xmlns="DAV:">
    <prop><getcontentlength/></prop>
</propfind>'''

            response = requests.request(
                'PROPFIND', full_url,
                auth=HTTPBasicAuth(self.config.webdav_username, self.config.webdav_password),
                headers=headers, data=body, timeout=10
            )

            if response.status_code == 207:
                root = etree.fromstring(response.content)
                ns = {'D': 'DAV:'}
                for prop in root.findall('.//D:prop', ns):
                    content_length = prop.find('D:getcontentlength', ns)
                    if content_length is not None and content_length.text:
                        return int(content_length.text)
        except Exception:
            pass
        return 0

    def scan_all_files(self, base_path):
        """扫描所有远程文件，返回 {path: size} 字典"""
        all_files = {}
        all_dirs = set()

        if not self.client:
            return all_files, all_dirs

        def scan_dir(path, depth=0):
            """递归扫描目录"""
            indent = "  " * depth
            try:
                items = self.client.list(path)

                for item in items:
                    # 跳过目录本身
                    item_clean = item.rstrip('/')
                    path_clean = path.rstrip('/')

                    # 构建完整路径
                    if item.startswith('/'):
                        full_path = item
                    else:
                        # 检查是否会导致路径重复
                        item_name = item_clean.split('/')[-1]
                        if path_clean.endswith(item_name):
                            continue
                        full_path = path_clean + '/' + item.lstrip('/')

                    # 跳过目录本身
                    if full_path.rstrip('/') == path_clean:
                        continue

                    if full_path.endswith('/'):
                        # 是目录
                        dir_name = full_path.rstrip('/').split('/')[-1]
                        logger.info(f"{indent}[DIR] {dir_name}/")
                        all_dirs.add(full_path.rstrip('/'))
                        scan_dir(full_path, depth + 1)
                    else:
                        # 是文件
                        filename = full_path.split('/')[-1]
                        size = 0

                        # 方法1: 尝试使用 client.info()
                        try:
                            info = self.client.info(full_path)
                            # 尝试多种可能的 size 字段名
                            size_str = (
                                info.get('size') or
                                info.get('{DAV:}getcontentlength') or
                                info.get('getcontentlength') or
                                info.get('contentlength') or
                                info.get('{http://ns.example.com/ns}getcontentlength') or
                                '0'
                            )
                            size_str = str(size_str).strip()
                            size = int(float(size_str)) if size_str else 0
                        except Exception as e:
                            logger.debug(f"info() failed for {filename}: {e}")
                            size = 0

                        # 方法2: 如果 info() 失败，使用 requests 直接请求
                        if size == 0:
                            try:
                                size = self._get_size_direct(full_path)
                            except Exception as e:
                                logger.debug(f"direct request failed for {filename}: {e}")

                        all_files[full_path] = size

                        if size > 0:
                            size_mb = size / (1024 * 1024)
                            logger.info(f"{indent}  {filename} ({size_mb:.1f} MB)")
                        else:
                            logger.warning(f"{indent}  {filename} (size unknown)")

            except Exception as e:
                logger.warning(f"Failed to scan {path}: {e}")

        try:
            logger.info(f"Scanning WebDAV directory: {base_path}")
            print("-" * 60)
            scan_dir(base_path)
            print("-" * 60)
            logger.info(f"Found {len(all_dirs)} directories, {len(all_files)} files")
        except Exception as e:
            logger.error(f"Failed to scan: {e}")

        return all_files, all_dirs


class DatabaseVerifier:
    """数据库验证器"""

    def __init__(self, db_path, formats):
        self.db_path = db_path
        self.formats = formats
        self.data = self._load()

    def _load(self):
        """加载数据库"""
        if not os.path.exists(self.db_path):
            logger.error(f"Database not found: {self.db_path}")
            return {"series": {}, "metadata": {}}

        with open(self.db_path, 'r', encoding='utf-8') as f:
            return json.load(f)

    def save(self):
        """保存数据库"""
        self.data["metadata"]["last_verified"] = datetime.now().isoformat()
        with open(self.db_path, 'w', encoding='utf-8') as f:
            json.dump(self.data, f, ensure_ascii=False, indent=2)
        logger.info(f"Database saved: {self.db_path}")

    def get_all_albums(self):
        """获取所有专辑"""
        albums = []
        for series_name, series_data in self.data.get("series", {}).items():
            for album in series_data.get("albums", []):
                album["_series_name"] = series_name
                albums.append(album)
        return albums

    def get_best_download(self, album):
        """获取最佳下载链接"""
        downloads = album.get("downloads", [])
        format_order = {fmt: i for i, fmt in enumerate(self.formats)}

        gdrive_downloads = [
            d for d in downloads
            if d.get("source") == "google_drive"
        ]

        if not gdrive_downloads:
            return None

        gdrive_downloads.sort(
            key=lambda x: format_order.get(x.get("format", ""), 999)
        )

        return gdrive_downloads[0] if gdrive_downloads else None

    def extract_album_code_from_filename(self, filename):
        """从文件名中提取专辑代码"""
        # 常见格式：
        # [210120]THE IDOLM@STER SHINY COLORS COLORFUL FE@THERS -Stella-(ALAC 96kHz_32bit).zip
        # BW-01_Spread the Wings!! (WAV).zip
        # 等等

        # 尝试匹配专辑代码格式 (如 BW-01, CF-05, Canvas-06 等)
        patterns = [
            r'^\[?\d{6}\]?\s*.*?\s*([A-Z]+-\d+)',  # 带日期前缀的
            r'^([A-Z]+-\d+)[\s_\-]',  # 简单格式 BW-01_xxx
            r'^([A-Za-z]+-\d+)[\s_\-\.]',  # 混合格式
            r'^([A-Za-z]+-\d+)\.zip$',  # 只有代码
            r'^([A-Za-z]+-\d+)_',  # code_xxx
        ]

        for pattern in patterns:
            match = re.match(pattern, filename, re.IGNORECASE)
            if match:
                return match.group(1).upper()

        return None

    def extract_format_from_filename(self, filename):
        """从文件名中提取格式"""
        filename_upper = filename.upper()
        for fmt in self.formats:
            if fmt in filename_upper:
                return fmt
        return "unknown"

    def build_album_code_map(self):
        """构建专辑代码到专辑的映射"""
        code_map = {}
        for album in self.get_all_albums():
            code = album.get("code", "")
            if code:
                code_upper = code.upper()
                if code_upper not in code_map:
                    code_map[code_upper] = album
        return code_map

    def build_series_dir_map(self):
        """构建系列名到目录名的映射"""
        series_map = {}
        for series_name in self.data.get("series", {}).keys():
            safe_series = re.sub(r'[^\w\s-]', '', series_name).strip()
            safe_series = re.sub(r'[-\s]+', '_', safe_series)
            series_map[safe_series] = series_name
        return series_map

    def verify_and_update(self, remote_files, base_path, dry_run=False):
        """验证并更新数据库 - 使用原始文件名匹配"""
        logger.info("Verifying database against WebDAV files...")
        print("-" * 60)

        # 统计
        stats = {
            "total": 0,
            "uploaded_fixed_true": 0,
            "uploaded_fixed_false": 0,
            "downloaded_fixed": 0,
            "already_correct": 0,
            "no_gdrive_link": 0,
            "matched_by_code": 0,
        }

        # 构建映射
        album_code_map = self.build_album_code_map()
        series_dir_map = self.build_series_dir_map()

        # 构建专辑已匹配的文件集合
        matched_albums = set()

        # 遍历远程文件，匹配专辑
        for full_path, size in remote_files.items():
            # 提取目录名和文件名
            path_parts = full_path.replace(base_path, '').strip('/').split('/')
            if len(path_parts) < 2:
                continue

            dir_name = path_parts[0]
            filename = path_parts[-1]

            # 从文件名提取专辑代码
            album_code = self.extract_album_code_from_filename(filename)
            if not album_code:
                continue

            # 查找匹配的专辑
            album = album_code_map.get(album_code)
            if not album:
                logger.debug(f"No album found for code: {album_code} ({filename})")
                continue

            album_id = id(album)
            if album_id in matched_albums:
                continue  # 已匹配过

            matched_albums.add(album_id)
            stats["matched_by_code"] += 1

            # 获取当前状态
            sync_status = album.get("sync_status", {})
            current_uploaded = sync_status.get("uploaded", False)
            current_downloaded = sync_status.get("downloaded", False)

            # 提取格式
            file_format = self.extract_format_from_filename(filename)

            # 更新状态
            need_update = False
            new_status = sync_status.copy()

            if not current_uploaded:
                logger.info(f"[FIX -> True] {album_code}: found {filename}")
                stats["uploaded_fixed_true"] += 1
                need_update = True

            new_status["uploaded"] = True
            new_status["remote_path"] = full_path
            new_status["size"] = size
            new_status["format"] = file_format
            new_status["original_filename"] = filename
            if "synced_at" not in new_status:
                new_status["synced_at"] = datetime.now().isoformat()

            if current_downloaded:
                new_status["downloaded"] = False
                stats["downloaded_fixed"] += 1
                need_update = True

            if need_update:
                album["sync_status"] = new_status
            else:
                stats["already_correct"] += 1

        # 检查未匹配的专辑
        for album in self.get_all_albums():
            if id(album) not in matched_albums:
                stats["total"] += 1
                album_code = album.get("code", "Unknown")

                # 检查是否有 Google Drive 链接
                download_info = self.get_best_download(album)
                if not download_info:
                    stats["no_gdrive_link"] += 1
                    continue

                # 未匹配到远程文件
                sync_status = album.get("sync_status", {})
                if sync_status.get("uploaded", False):
                    logger.info(f"[FIX -> False] {album_code}: not found on remote")
                    sync_status["uploaded"] = False
                    stats["uploaded_fixed_false"] += 1

        stats["total"] = len(matched_albums) + stats["uploaded_fixed_false"]

        print("-" * 60)
        logger.info("Verification Statistics:")
        print(f"  Matched by code: {stats['matched_by_code']}")
        print(f"  Already correct: {stats['already_correct']}")
        print(f"  Fixed (uploaded -> True): {stats['uploaded_fixed_true']}")
        print(f"  Fixed (uploaded -> False): {stats['uploaded_fixed_false']}")
        print(f"  Fixed (downloaded -> False): {stats['downloaded_fixed']}")
        print(f"  No Google Drive link: {stats['no_gdrive_link']}")

        total_fixed = stats['uploaded_fixed_true'] + stats['uploaded_fixed_false'] + stats['downloaded_fixed']

        if not dry_run and total_fixed > 0:
            self.save()
        elif dry_run:
            logger.info("[DRY RUN] Database not saved")

        return stats


def main():
    parser = argparse.ArgumentParser(description='SHINY COLORS Database Verification Tool')
    parser.add_argument('--dry-run', action='store_true', help='Preview mode, do not save changes')
    parser.add_argument('--config', '-c', type=str, help='Path to config file')
    parser.add_argument('--db', type=str, help='Path to database file')
    parser.add_argument('--test', action='store_true', help='Test WebDAV connection only')
    parser.add_argument('--scan-only', action='store_true', help='Only scan WebDAV, do not verify DB')
    args = parser.parse_args()

    print("=" * 60)
    print("SHINY COLORS Database Verification Tool")
    print("=" * 60)

    # 加载配置
    config = Config(args.config)
    if args.db:
        config.db_path = args.db

    # 检查配置
    if not config.webdav_url:
        print("Error: WebDAV URL not configured")
        print("Set WEBDAV_URL environment variable or create config.yaml")
        sys.exit(1)

    # 初始化扫描器
    scanner = WebDAVScanner(config)

    # 测试连接
    if args.test:
        success, message = scanner.test_connection()
        print(f"WebDAV Connection: {'OK' if success else 'FAILED'} - {message}")
        return

    # 测试连接
    success, message = scanner.test_connection()
    if not success:
        logger.error(f"WebDAV connection failed: {message}")
        sys.exit(1)

    print(f"WebDAV Connection: OK")
    print()

    # 扫描远程文件
    remote_files, remote_dirs = scanner.scan_all_files(config.webdav_base_path)

    if args.scan_only:
        logger.info("Scan-only mode, exiting")
        return

    print()

    # 验证数据库
    verifier = DatabaseVerifier(config.db_path, config.formats)
    stats = verifier.verify_and_update(remote_files, config.webdav_base_path, dry_run=args.dry_run)

    print()
    print("=" * 60)
    print("Done!")
    print("=" * 60)


if __name__ == "__main__":
    main()
