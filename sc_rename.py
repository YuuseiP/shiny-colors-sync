# -*- coding: utf-8 -*-
"""
SHINY COLORS 文件重命名程序
- 扫描 WebDAV 上的简化命名文件 (如 CF-01_ALAC.zip)
- 从 Google Drive 获取原始文件名
- 重命名 WebDAV 文件为原始名称
"""

import os
import sys
import re
import json
import logging
import argparse
import time
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
        self.temp_dir = os.getenv('TEMP_DIR', './downloads')
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

                download = cfg.get('download', {})
                self.temp_dir = download.get('temp_dir', self.temp_dir)

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
        if not self.client:
            return False
        try:
            return self.client.check(path)
        except:
            return False


class GoogleDriveHelper:
    """Google Drive 辅助类"""

    @staticmethod
    def extract_file_id(url):
        """从 URL 提取文件 ID"""
        patterns = [
            r'/file/d/([a-zA-Z0-9_-]+)',
            r'/d/([a-zA-Z0-9_-]+)',
            r'id=([a-zA-Z0-9_-]+)',
            r'/open\?id=([a-zA-Z0-9_-]+)',
        ]
        for pattern in patterns:
            match = re.search(pattern, url)
            if match:
                return match.group(1)
        return None

    @staticmethod
    def get_original_filename(url, file_id=None):
        """获取 Google Drive 文件的原始文件名（不下载完整文件）"""
        import requests

        if not file_id:
            file_id = GoogleDriveHelper.extract_file_id(url)
        if not file_id:
            return None

        # 尝试从 Google Drive 获取文件信息
        try:
            # 方法1: 尝试获取文件元数据
            session = requests.Session()
            direct_url = f"https://drive.google.com/uc?id={file_id}"

            response = session.get(direct_url, stream=True, timeout=10, allow_redirects=True)

            # 检查响应头中的文件名
            content_disp = response.headers.get('Content-Disposition', '')
            if content_disp:
                # 解析 filename="xxx" 或 filename*=UTF-8''xxx
                import urllib.parse
                match = re.search(r'filename\*?=["\']?(?:UTF-8\'\')?([^"\';\s]+)', content_disp)
                if match:
                    filename = urllib.parse.unquote(match.group(1))
                    return filename

            # 方法2: 从 HTML 响应中提取文件名
            if 'text/html' in response.headers.get('Content-Type', ''):
                # 可能需要登录或文件不存在
                return None

        except Exception as e:
            logger.debug(f"Failed to get filename from headers: {e}")

        return None

    @staticmethod
    def get_filename_by_download(url, output_dir, file_id=None):
        """通过下载获取原始文件名（小文件或最后手段）"""
        try:
            import gdown

            if not file_id:
                file_id = GoogleDriveHelper.extract_file_id(url)
            if not file_id:
                return None

            direct_url = f"https://drive.google.com/uc?id={file_id}"

            # 使用 gdown 下载，获取原始文件名
            os.makedirs(output_dir, exist_ok=True)
            output_file = gdown.download(
                direct_url,
                output_dir,
                quiet=True,
                resume=True
            )

            if output_file and os.path.exists(output_file):
                filename = os.path.basename(output_file)
                # 删除下载的文件
                try:
                    os.remove(output_file)
                except:
                    pass
                return filename

        except Exception as e:
            logger.warning(f"Failed to get filename by download: {e}")

        return None


class RenameManager:
    """重命名管理器"""

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

    def save(self):
        with open(self.db_path, 'w', encoding='utf-8') as f:
            json.dump(self.data, f, ensure_ascii=False, indent=2)
        logger.info(f"Database saved: {self.db_path}")

    def get_all_albums(self):
        albums = []
        for series_name, series_data in self.data.get("series", {}).items():
            for album in series_data.get("albums", []):
                album["_series_name"] = series_name
                albums.append(album)
        return albums

    def get_best_download(self, album):
        downloads = album.get("downloads", [])
        format_order = {fmt: i for i, fmt in enumerate(self.formats)}

        gdrive_downloads = [
            d for d in downloads
            if d.get("source") == "google_drive"
        ]

        if not gdrive_downloads:
            return None

        gdrive_downloads.sort(
            key=lambda x: format_order.get(x.get("format", "").upper(), 999)
        )

        return gdrive_downloads[0] if gdrive_downloads else None

    def build_album_map(self):
        """构建专辑代码到专辑的映射"""
        album_map = {}
        for album in self.get_all_albums():
            code = album.get("code", "")
            if code:
                code_upper = code.upper()
                if code_upper not in album_map:
                    album_map[code_upper] = album
        return album_map

    def is_simplified_filename(self, filename):
        """检查是否是简化命名的文件"""
        # 简化命名格式: {CODE}_{FORMAT}.zip (如 CF-01_ALAC.zip)
        match = re.match(r'^([A-Za-z]+-\d+)_([A-Za-z]+)\.zip$', filename)
        if match:
            format_part = match.group(2).upper()
            if format_part in self.formats or format_part == "UNKNOWN":
                return True
        return False

    def analyze_files(self, remote_files, album_map, temp_dir):
        """分析需要重命名的文件"""
        renames = []

        for full_path, filename in remote_files.items():
            # 检查是否是简化命名
            if not self.is_simplified_filename(filename):
                continue

            # 从文件名提取专辑代码
            match = re.match(r'^([A-Za-z]+-\d+)_([A-Za-z]+)\.zip$', filename)
            if not match:
                continue

            album_code = match.group(1).upper()

            # 查找专辑
            album = album_map.get(album_code)
            if not album:
                logger.debug(f"No album found for code: {album_code}")
                continue

            # 获取 Google Drive 链接
            download_info = self.get_best_download(album)
            if not download_info:
                logger.debug(f"No Google Drive link for: {album_code}")
                continue

            gd_url = download_info.get("url")
            file_id = GoogleDriveHelper.extract_file_id(gd_url)

            renames.append({
                "full_path": full_path,
                "old_name": filename,
                "album_code": album_code,
                "gd_url": gd_url,
                "file_id": file_id,
                "album": album
            })

        return renames


def main():
    parser = argparse.ArgumentParser(description='SHINY COLORS File Rename Tool')
    parser.add_argument('--dry-run', action='store_true', help='Preview mode, do not rename files')
    parser.add_argument('--config', '-c', type=str, help='Path to config file')
    parser.add_argument('--db', type=str, help='Path to database file')
    parser.add_argument('--download', action='store_true', help='Download files to get original names (slower but more reliable)')
    args = parser.parse_args()

    print("=" * 60)
    print("SHINY COLORS File Rename Tool")
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
    manager = RenameManager(config.db_path, config.formats)
    album_map = manager.build_album_map()
    logger.info(f"Found {len(album_map)} albums in database")

    # 扫描远程文件
    logger.info("Scanning WebDAV files...")
    remote_files = webdav.scan_files(config.webdav_base_path)
    logger.info(f"Found {len(remote_files)} remote files")

    # 分析需要重命名的文件
    logger.info("Analyzing files for rename...")
    renames = manager.analyze_files(remote_files, album_map, config.temp_dir)

    print("-" * 60)

    if not renames:
        logger.info("No files need to be renamed!")
        print("=" * 60)
        return

    logger.info(f"Found {len(renames)} files to rename:")
    print()

    # 获取原始文件名
    success_count = 0
    fail_count = 0
    skip_count = 0

    for rename in renames:
        old_name = rename["old_name"]
        album_code = rename["album_code"]
        gd_url = rename["gd_url"]
        file_id = rename["file_id"]

        print(f"  [{album_code}] {old_name}")

        # 获取原始文件名
        original_filename = GoogleDriveHelper.get_original_filename(gd_url, file_id)

        if not original_filename and args.download:
            logger.info(f"    Downloading to get original name...")
            original_filename = GoogleDriveHelper.get_filename_by_download(
                gd_url, config.temp_dir, file_id
            )

        if not original_filename:
            logger.warning(f"    Cannot determine original filename")
            fail_count += 1
            continue

        rename["new_name"] = original_filename
        print(f"    -> {original_filename}")

        if args.dry_run:
            skip_count += 1
            continue

        # 执行重命名
        old_path = rename["full_path"]
        dir_path = old_path.rsplit('/', 1)[0]
        new_path = f"{dir_path}/{original_filename}"

        # 检查目标是否已存在
        if webdav.check_exists(new_path):
            logger.warning(f"    Skip: target already exists")
            skip_count += 1
            continue

        if webdav.rename(old_path, new_path):
            logger.info(f"    Renamed OK")
            success_count += 1

            # 更新数据库
            album = rename["album"]
            if "sync_status" not in album:
                album["sync_status"] = {}
            album["sync_status"]["original_filename"] = original_filename
            album["sync_status"]["remote_path"] = new_path
        else:
            logger.error(f"    Rename FAILED")
            fail_count += 1

        # 避免请求过快
        time.sleep(0.5)

    print("-" * 60)

    if args.dry_run:
        logger.info(f"[DRY RUN] Would rename {len(renames)} files")
    else:
        logger.info(f"Done: {success_count} renamed, {fail_count} failed, {skip_count} skipped")

        if success_count > 0:
            manager.save()

    print("=" * 60)


if __name__ == "__main__":
    main()
