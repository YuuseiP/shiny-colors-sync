# -*- coding: utf-8 -*-
"""
SHINY COLORS 下载同步程序
- 独立运行，只依赖 shiny_colors_db.json
- 从 Google Drive 下载文件
- 通过 WebDAV 上传到 OpenList
- 支持断点续传和增量同步
"""

import os
import sys
import re
import json
import time
import hashlib
import shutil
import logging
import argparse
from datetime import datetime
from pathlib import Path

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
            '/etc/sc_sync/config.yaml'
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
        self.temp_dir = os.getenv('TEMP_DIR', './downloads')
        self.db_path = os.getenv('DB_PATH', './shiny_colors_db.json')
        self.retry_count = 3
        self.retry_delay = 10
        self.formats = ['WAV', 'AIFF', 'ALAC', 'FLAC']
        self.max_concurrent = 2

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

                download = cfg.get('download', {})
                self.temp_dir = download.get('temp_dir', self.temp_dir)
                self.retry_count = download.get('retry_count', self.retry_count)
                self.retry_delay = download.get('retry_delay', self.retry_delay)
                self.max_concurrent = download.get('max_concurrent', self.max_concurrent)

                sync = cfg.get('sync', {})
                self.formats = sync.get('formats', self.formats)

                self.db_path = cfg.get('database', self.db_path)

                logger.info(f"Loaded config from: {self.config_path}")
            except ImportError:
                logger.warning("PyYAML not installed, using environment variables")
            except Exception as e:
                logger.warning(f"Failed to load config: {e}")


class Database:
    """数据库管理"""
    def __init__(self, db_path):
        self.db_path = db_path
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
        self.data["metadata"]["last_sync"] = datetime.now().isoformat()
        with open(self.db_path, 'w', encoding='utf-8') as f:
            json.dump(self.data, f, ensure_ascii=False, indent=2)

    def get_all_albums(self):
        """获取所有专辑"""
        albums = []
        for series_name, series_data in self.data.get("series", {}).items():
            for album in series_data.get("albums", []):
                album["_series_name"] = series_name
                albums.append(album)
        return albums

    def get_pending_albums(self):
        """获取待同步的专辑"""
        pending = []
        for album in self.get_all_albums():
            sync_status = album.get("sync_status", {})
            if not sync_status.get("uploaded"):
                pending.append(album)
        return pending


class GoogleDriveDownloader:
    """Google Drive 下载器"""

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
    def download(url, output_path, retry_count=3, retry_delay=10):
        """下载文件"""
        try:
            import gdown
        except ImportError:
            logger.error("gdown not installed. Run: pip install gdown")
            return False

        file_id = GoogleDriveDownloader.extract_file_id(url)
        if not file_id:
            logger.error(f"Cannot extract file ID from: {url}")
            return False

        direct_url = f"https://drive.google.com/uc?id={file_id}"

        for attempt in range(retry_count):
            try:
                logger.info(f"Downloading (attempt {attempt + 1}/{retry_count}): {file_id}")

                # 使用 gdown 下载
                gdown.download(
                    direct_url,
                    output_path,
                    quiet=False,
                    resume=True
                )

                if os.path.exists(output_path) and os.path.getsize(output_path) > 0:
                    logger.info(f"Downloaded: {output_path}")
                    return True
                else:
                    logger.warning("Downloaded file is empty, retrying...")

            except Exception as e:
                logger.warning(f"Download failed (attempt {attempt + 1}): {e}")
                if os.path.exists(output_path):
                    os.remove(output_path)
                if attempt < retry_count - 1:
                    time.sleep(retry_delay)

        return False


class WebDAVUploader:
    """WebDAV 上传器"""

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

    def ensure_dir(self, remote_path):
        """确保远程目录存在"""
        if not self.client:
            return False

        try:
            if not self.client.check(remote_path):
                self.client.mkdir(remote_path)
                logger.info(f"Created remote directory: {remote_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to create directory {remote_path}: {e}")
            return False

    def upload(self, local_path, remote_path, retry_count=3, retry_delay=10):
        """上传文件"""
        if not self.client:
            logger.error("WebDAV client not initialized")
            return False

        # 确保目录存在
        remote_dir = os.path.dirname(remote_path)
        if remote_dir:
            self.ensure_dir(remote_dir)

        for attempt in range(retry_count):
            try:
                logger.info(f"Uploading (attempt {attempt + 1}/{retry_count}): {remote_path}")

                self.client.upload_sync(
                    remote_path=remote_path,
                    local_path=local_path
                )

                # 验证上传
                if self.client.check(remote_path):
                    remote_info = self.client.info(remote_path)
                    remote_size = int(remote_info.get('size', 0))
                    local_size = os.path.getsize(local_path)

                    if remote_size == local_size:
                        logger.info(f"Uploaded successfully: {remote_path}")
                        return True
                    else:
                        logger.warning(f"Size mismatch: local={local_size}, remote={remote_size}")

            except Exception as e:
                logger.warning(f"Upload failed (attempt {attempt + 1}): {e}")
                if attempt < retry_count - 1:
                    time.sleep(retry_delay)

        return False


class SyncManager:
    """同步管理器"""

    def __init__(self, config):
        self.config = config
        self.db = Database(config.db_path)
        self.uploader = WebDAVUploader(config)

        # 创建临时目录
        os.makedirs(config.temp_dir, exist_ok=True)

    def get_best_download(self, album):
        """获取最佳下载链接"""
        downloads = album.get("downloads", [])

        # 按格式优先级排序
        format_order = {fmt: i for i, fmt in enumerate(self.config.formats)}

        # 筛选 Google Drive 链接并排序
        gdrive_downloads = [
            d for d in downloads
            if d.get("source") == "google_drive"
        ]

        if not gdrive_downloads:
            return None

        # 按格式优先级排序
        gdrive_downloads.sort(
            key=lambda x: format_order.get(x.get("format", ""), 999)
        )

        return gdrive_downloads[0] if gdrive_downloads else None

    def sync_album(self, album, dry_run=False):
        """同步单个专辑"""
        series_name = album.get("_series_name", "Unknown")
        album_code = album.get("code", "Unknown")
        album_title = album.get("title", "Unknown")

        logger.info(f"Processing: [{series_name}] {album_code} - {album_title}")

        # 获取下载链接
        download_info = self.get_best_download(album)
        if not download_info:
            logger.warning(f"No Google Drive link found for: {album_code}")
            return False, "no_link"

        url = download_info.get("url")
        file_format = download_info.get("format", "unknown")

        logger.info(f"  Format: {file_format}")
        logger.info(f"  URL: {url}")

        if dry_run:
            logger.info("  [DRY RUN] Would download and upload")
            return True, "dry_run"

        # 生成本地文件路径
        safe_series = re.sub(r'[^\w\s-]', '', series_name).strip()
        safe_series = re.sub(r'[-\s]+', '_', safe_series)
        filename = f"{album_code}_{file_format}.zip"
        local_path = os.path.join(self.config.temp_dir, safe_series, filename)
        os.makedirs(os.path.dirname(local_path), exist_ok=True)

        # 生成远程路径
        remote_path = f"{self.config.webdav_base_path}/{safe_series}/{filename}"

        # 下载
        if not GoogleDriveDownloader.download(
            url, local_path,
            self.config.retry_count, self.config.retry_delay
        ):
            return False, "download_failed"

        # 上传
        if not self.uploader.upload(
            local_path, remote_path,
            self.config.retry_count, self.config.retry_delay
        ):
            return False, "upload_failed"

        # 更新状态
        album["sync_status"] = {
            "downloaded": True,
            "uploaded": True,
            "format": file_format,
            "remote_path": remote_path,
            "synced_at": datetime.now().isoformat()
        }

        # 清理本地文件
        try:
            os.remove(local_path)
            logger.info(f"Cleaned up: {local_path}")
        except:
            pass

        return True, "success"

    def sync_all(self, dry_run=False, force=False, series_filter=None):
        """同步所有待处理专辑"""
        if force:
            albums = self.db.get_all_albums()
        else:
            albums = self.db.get_pending_albums()

        # 过滤系列
        if series_filter:
            albums = [a for a in albums if series_filter in a.get("_series_name", "")]

        total = len(albums)
        if total == 0:
            logger.info("No albums to sync")
            return

        logger.info(f"Found {total} albums to sync")
        print("-" * 60)

        success_count = 0
        failed_count = 0
        skipped_count = 0

        for i, album in enumerate(albums, 1):
            print(f"\n[{i}/{total}] ", end="")

            success, reason = self.sync_album(album, dry_run)

            if success:
                success_count += 1
            elif reason == "no_link":
                skipped_count += 1
            else:
                failed_count += 1

            # 保存进度
            if not dry_run and success:
                self.db.save()

            # 礼貌延迟
            time.sleep(1)

        print("-" * 60)
        logger.info(f"Sync complete: {success_count} success, {failed_count} failed, {skipped_count} skipped")

        if not dry_run:
            self.db.save()


def main():
    parser = argparse.ArgumentParser(description='SHINY COLORS Download Sync Tool')
    parser.add_argument('--dry-run', action='store_true', help='Preview mode, no actual download')
    parser.add_argument('--force', '-f', action='store_true', help='Force re-download all albums')
    parser.add_argument('--series', '-s', type=str, help='Filter by series name')
    parser.add_argument('--config', '-c', type=str, help='Path to config file')
    parser.add_argument('--test', action='store_true', help='Test WebDAV connection')
    parser.add_argument('--db', type=str, help='Path to database file')
    args = parser.parse_args()

    print("=" * 60)
    print("SHINY COLORS Download Sync Tool")
    print("=" * 60)

    # 加载配置
    config = Config(args.config)
    if args.db:
        config.db_path = args.db

    # 测试连接
    if args.test:
        uploader = WebDAVUploader(config)
        success, message = uploader.test_connection()
        print(f"WebDAV Connection: {'OK' if success else 'FAILED'} - {message}")
        return

    # 检查配置
    if not config.webdav_url:
        print("Error: WebDAV URL not configured")
        print("Set WEBDAV_URL environment variable or create config.yaml")
        sys.exit(1)

    # 运行同步
    manager = SyncManager(config)
    manager.sync_all(
        dry_run=args.dry_run,
        force=args.force,
        series_filter=args.series
    )


if __name__ == "__main__":
    main()
