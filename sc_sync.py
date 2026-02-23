# -*- coding: utf-8 -*-
"""
SHINY COLORS 下载同步程序
- 独立运行，只依赖 shiny_colors_db.json
- 从 Google Drive 下载文件
- 通过 WebDAV 上传到 OpenList
- 支持断点续传和增量同步
- 支持多线程并发下载
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
import threading
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# 线程锁用于保护共享资源
db_lock = threading.Lock()
log_lock = threading.Lock()


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

    def _reconnect(self):
        """重新连接"""
        self._init_client()
        return self.client is not None

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

    def get_file_info_from_dir(self, remote_path):
        """从目录列表获取文件信息，返回 (exists, size)"""
        if not self.client:
            return False, 0

        try:
            remote_dir = os.path.dirname(remote_path)
            filename = os.path.basename(remote_path)

            # 获取目录列表
            if not self.client.check(remote_dir):
                return False, 0

            items = self.client.list(remote_dir)
            for item in items:
                item_name = item.rstrip('/').split('/')[-1]
                if item_name == filename and not item.endswith('/'):
                    # 获取文件大小
                    try:
                        info = self.client.info(remote_path)
                        size = int(info.get('size', 0))
                        return True, size
                    except:
                        return True, 0

            return False, 0
        except Exception as e:
            logger.warning(f"Failed to get file info: {e}")
            return False, 0

    def check_file_match(self, remote_path, expected_size):
        """检查远程文件是否存在且大小匹配"""
        exists, remote_size = self.get_file_info_from_dir(remote_path)
        if exists and remote_size > 0 and remote_size == expected_size:
            return True, remote_size
        return False, remote_size

    def scan_all_files_with_size(self, base_path):
        """扫描所有远程文件，返回 {path: size} 字典"""
        all_files = {}
        if not self.client:
            return all_files

        def scan_dir(path):
            """递归扫描目录"""
            try:
                items = self.client.list(path)

                for item in items:
                    # 跳过目录本身（item 可能是相对路径或绝对路径）
                    item_clean = item.rstrip('/')
                    path_clean = path.rstrip('/')

                    # 如果 item 是目录本身（名称相同），跳过
                    if item_clean == path_clean or item_clean.endswith('/' + path_clean.split('/')[-1]):
                        # 检查是否真的是目录本身
                        if path_clean.endswith(item_clean) or item_clean.endswith(path_clean.split('/')[-1]):
                            # 构建完整路径检查
                            if not item.startswith('/') and '/' not in item_clean:
                                # 简单的目录名，可能是列表中的第一个元素
                                continue

                    # 构建完整路径
                    if item.startswith('/'):
                        full_path = item
                    else:
                        # 检查是否会导致路径重复
                        item_name = item_clean.split('/')[-1]
                        if path_clean.endswith(item_name):
                            # 路径已经包含该名称，跳过
                            continue
                        full_path = path_clean + '/' + item.lstrip('/')

                    # 再次检查是否是目录本身
                    if full_path.rstrip('/') == path_clean:
                        continue

                    if full_path.endswith('/'):
                        # 是目录，递归扫描
                        scan_dir(full_path)
                    else:
                        # 是文件，获取大小
                        size = 0
                        try:
                            info = self.client.info(full_path)
                            # 尝试多种可能的 size 字段名
                            size_str = (
                                info.get('size') or
                                info.get('{DAV:}getcontentlength') or
                                info.get('getcontentlength') or
                                info.get('contentlength') or
                                '0'
                            )
                            size_str = str(size_str).strip()
                            size = int(float(size_str)) if size_str else 0
                        except:
                            pass

                        # 如果 info() 失败，使用直接请求
                        if size == 0:
                            size = self._get_size_direct(full_path)

                        all_files[full_path] = size
            except Exception as e:
                logger.debug(f"Skip {path}: {e}")

        try:
            scan_dir(base_path)
            logger.info(f"Scanned {len(all_files)} remote files")
        except Exception as e:
            logger.warning(f"Failed to scan remote files: {e}")

        return all_files

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

    def check_file_exists(self, remote_path):
        """直接检查文件是否存在"""
        if not self.client:
            return False
        try:
            return self.client.check(remote_path)
        except:
            return False

    def get_file_size(self, remote_path):
        """直接获取文件大小"""
        if not self.client:
            return 0
        try:
            info = self.client.info(remote_path)
            return int(info.get('size', 0))
        except:
            return 0

    def verify_file_in_dir(self, remote_path, expected_size):
        """通过刷新目录列表验证文件"""
        if not self.client:
            return False, 0

        remote_dir = os.path.dirname(remote_path)
        filename = os.path.basename(remote_path)

        try:
            # 刷新获取目录列表
            items = self.client.list(remote_dir)
            for item in items:
                item_name = item.rstrip('/').split('/')[-1]
                if item_name == filename and not item.endswith('/'):
                    # 找到文件，获取大小
                    try:
                        info = self.client.info(remote_path)
                        size = int(info.get('size', 0))
                        if size == expected_size:
                            return True, size
                        return False, size
                    except:
                        return True, 0
            return False, 0
        except Exception as e:
            logger.debug(f"Verify dir error: {e}")
            return False, 0

    def upload(self, local_path, remote_path, local_size, retry_count=3, retry_delay=10):
        """上传文件"""
        if not self.client:
            logger.error("WebDAV client not initialized")
            return False

        remote_dir = os.path.dirname(remote_path)
        filename = os.path.basename(remote_path)

        # 确保目录存在
        if remote_dir:
            self.ensure_dir(remote_dir)

        # 上传前检查：文件是否已存在
        try:
            if self.client.check(remote_path):
                logger.info(f"  File already exists, skip upload")
                return True
        except:
            pass

        # 执行上传（upload_sync 失败会抛异常）
        for attempt in range(retry_count):
            try:
                logger.info(f"  Uploading (attempt {attempt + 1}/{retry_count})...")
                self.client.upload_sync(
                    remote_path=remote_path,
                    local_path=local_path
                )
                # 上传没报错就成功
                logger.info(f"  Upload OK: {filename} ({local_size} bytes)")
                return True

            except Exception as e:
                logger.warning(f"  Upload error (attempt {attempt + 1}): {e}")
                self._reconnect()
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

        # 生成路径
        safe_series = re.sub(r'[^\w\s-]', '', series_name).strip()
        safe_series = re.sub(r'[-\s]+', '_', safe_series)
        filename = f"{album_code}_{file_format}.zip"
        local_path = os.path.join(self.config.temp_dir, safe_series, filename)
        remote_path = f"{self.config.webdav_base_path}/{safe_series}/{filename}"

        os.makedirs(os.path.dirname(local_path), exist_ok=True)

        # 下载
        if not GoogleDriveDownloader.download(
            url, local_path,
            self.config.retry_count, self.config.retry_delay
        ):
            return False, "download_failed"

        # 获取本地文件大小
        local_size = os.path.getsize(local_path)

        # 上传 (上传前会自动检查是否已存在)
        if not self.uploader.upload(
            local_path, remote_path, local_size,
            self.config.retry_count, self.config.retry_delay
        ):
            return False, "upload_failed"

        # 清理本地文件
        try:
            os.remove(local_path)
            logger.info(f"  Cleaned up: {local_path}")
        except:
            pass

        # 更新状态 (downloaded=false 因为本地文件已删除)
        album["sync_status"] = {
            "downloaded": False,
            "uploaded": True,
            "format": file_format,
            "remote_path": remote_path,
            "size": local_size,
            "synced_at": datetime.now().isoformat()
        }

        return True, "success"

    def _sync_album_thread(self, album, index, total, dry_run, results):
        """线程安全的单曲同步"""
        album_code = album.get("code", "Unknown")

        with log_lock:
            logger.info(f"[{index}/{total}] Processing: {album_code}")

        success, reason = self.sync_album(album, dry_run)

        # 线程安全地保存结果
        with db_lock:
            results.append((index, album, success, reason))
            if not dry_run and success:
                self.db.save()

        return success, reason

    def sync_all(self, dry_run=False, force=False, series_filter=None, max_count=None, threads=1):
        """同步所有待处理专辑"""
        if force:
            albums = self.db.get_all_albums()
        else:
            albums = self.db.get_pending_albums()

        # 过滤系列
        if series_filter:
            albums = [a for a in albums if series_filter in a.get("_series_name", "")]

        # 限制数量
        total = len(albums)
        if max_count and max_count > 0:
            albums = albums[:max_count]

        process_count = len(albums)
        if process_count == 0:
            logger.info("No albums to sync")
            return

        # 自适应线程数
        actual_threads = min(threads, process_count)
        logger.info(f"Found {total} albums, will process {process_count} with {actual_threads} thread(s)")
        print("-" * 60)

        success_count = 0
        failed_count = 0
        no_link_count = 0

        if actual_threads <= 1:
            # 单线程模式
            for i, album in enumerate(albums, 1):
                print(f"\n[{i}/{process_count}] ", end="")
                success, reason = self.sync_album(album, dry_run)

                if success:
                    success_count += 1
                elif reason == "no_link":
                    no_link_count += 1
                else:
                    failed_count += 1

                if not dry_run and success:
                    self.db.save()
                time.sleep(1)
        else:
            # 多线程模式
            results = []

            with ThreadPoolExecutor(max_workers=actual_threads) as executor:
                futures = {
                    executor.submit(
                        self._sync_album_thread, album, i, process_count, dry_run, results
                    ): album
                    for i, album in enumerate(albums, 1)
                }

                for future in as_completed(futures):
                    try:
                        success, reason = future.result()
                        if success:
                            success_count += 1
                        elif reason == "no_link":
                            no_link_count += 1
                        else:
                            failed_count += 1
                    except Exception as e:
                        logger.error(f"Thread error: {e}")
                        failed_count += 1

        print("-" * 60)
        logger.info(f"Sync complete: {success_count} success, {failed_count} failed, {no_link_count} no_link")

        if not dry_run:
            self.db.save()

    def verify_db(self, dry_run=False):
        """自检程序：对比 db 和 webdav 目录，修正状态"""
        logger.info("Starting database verification...")
        print("-" * 60)

        # 1. 扫描远程所有文件
        logger.info("Scanning remote files...")
        remote_files = self.uploader.scan_all_files_with_size(self.config.webdav_base_path)

        # 构建远程文件路径集合
        remote_paths = set(remote_files.keys())

        updated_count = 0
        already_ok_count = 0

        # 2. 遍历所有专辑
        all_albums = self.db.get_all_albums()

        for album in all_albums:
            series_name = album.get("_series_name", "Unknown")
            album_code = album.get("code", "Unknown")

            # 获取最佳下载信息确定格式
            download_info = self.get_best_download(album)
            if not download_info:
                continue

            file_format = download_info.get("format", "unknown")

            # 生成远程路径
            safe_series = re.sub(r'[^\w\s-]', '', series_name).strip()
            safe_series = re.sub(r'[-\s]+', '_', safe_series)
            filename = f"{album_code}_{file_format}.zip"
            remote_path = f"{self.config.webdav_base_path}/{safe_series}/{filename}"

            # 获取当前状态
            sync_status = album.get("sync_status", {})
            current_uploaded = sync_status.get("uploaded", False)
            current_downloaded = sync_status.get("downloaded", False)

            # 检查远程是否存在
            remote_exists = remote_path in remote_paths
            remote_size = remote_files.get(remote_path, 0)

            # 判断是否需要更新
            need_update = False
            new_status = sync_status.copy()

            if remote_exists:
                # 远程存在
                if not current_uploaded:
                    logger.info(f"[FIX] {album_code}: uploaded False -> True (remote exists)")
                    need_update = True
                new_status["uploaded"] = True
                new_status["remote_path"] = remote_path
                new_status["size"] = remote_size
                new_status["format"] = file_format
                if "synced_at" not in new_status:
                    new_status["synced_at"] = datetime.now().isoformat()
            else:
                # 远程不存在
                if current_uploaded:
                    logger.info(f"[FIX] {album_code}: uploaded True -> False (remote missing)")
                    need_update = True
                new_status["uploaded"] = False
                new_status["downloaded"] = False

            # downloaded 应该始终为 false（本地不保留文件）
            if current_downloaded:
                new_status["downloaded"] = False
                need_update = True

            if need_update:
                album["sync_status"] = new_status
                updated_count += 1
            else:
                already_ok_count += 1

        print("-" * 60)
        logger.info(f"Verification complete: {updated_count} updated, {already_ok_count} already correct")

        if not dry_run and updated_count > 0:
            self.db.save()
            logger.info("Database saved")


def main():
    parser = argparse.ArgumentParser(description='SHINY COLORS Download Sync Tool')
    parser.add_argument('--dry-run', action='store_true', help='Preview mode, no actual download')
    parser.add_argument('--force', '-f', action='store_true', help='Force re-download all albums')
    parser.add_argument('--series', '-s', type=str, help='Filter by series name')
    parser.add_argument('--count', '-n', type=int, help='Max number of albums to sync')
    parser.add_argument('--threads', '-t', type=int, default=1, help='Number of concurrent threads (default: 1)')
    parser.add_argument('--config', '-c', type=str, help='Path to config file')
    parser.add_argument('--test', action='store_true', help='Test WebDAV connection')
    parser.add_argument('--db', type=str, help='Path to database file')
    parser.add_argument('--verify', action='store_true', help='Verify DB against WebDAV and fix status')
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

    # 运行
    manager = SyncManager(config)

    if args.verify:
        manager.verify_db(dry_run=args.dry_run)
    else:
        manager.sync_all(
            dry_run=args.dry_run,
            force=args.force,
            series_filter=args.series,
            max_count=args.count,
            threads=args.threads
        )


if __name__ == "__main__":
    main()
