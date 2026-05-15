# -*- coding: utf-8 -*-
"""
SHINY COLORS 下载同步程序
- 从 OneDrive/Google Drive 下载专辑
- 上传到 WebDAV 网盘
- 使用系列名和专辑名分类
"""

import os
import sys
import re
import json
import time
import logging
import argparse
import tempfile
import shutil
from datetime import datetime
from urllib.parse import quote

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


def clean_filename(filename):
    """清理文件名，去掉随机前缀"""
    # 常见的随机前缀模式：
    # ZsjVVrfu_[180606]...
    # abc123_[200101]...
    # 等等
    
    # 尝试匹配 [YYYYMM] 格式的日期，去掉前面的随机字符串
    match = re.match(r'^[a-zA-Z0-9]+_(\[\d{6}\].*)$', filename)
    if match:
        cleaned = match.group(1)
        logger.info(f"Cleaned filename: {filename} -> {cleaned}")
        return cleaned
    
    # 如果没有匹配，返回原始文件名
    return filename


class Config:
    """配置管理"""

    def __init__(self, config_path=None):
        self.config_path = config_path or self._find_config()
        self._load_config()

    def _find_config(self):
        """查找配置文件"""
        candidates = [
            "./config.yaml",
            "./config.yml",
            os.path.expanduser("~/.config/sc_sync/config.yaml"),
        ]
        for path in candidates:
            if os.path.exists(path):
                return path
        return None

    def _load_config(self):
        """加载配置"""
        # 默认配置
        self.webdav_url = os.getenv("WEBDAV_URL", "")
        self.webdav_username = os.getenv("WEBDAV_USERNAME", "")
        self.webdav_password = os.getenv("WEBDAV_PASSWORD", "")
        self.webdav_base_path = os.getenv("WEBDAV_BASE_PATH", "/SHINY_COLORS")
        self.db_path = os.getenv("DB_PATH", "./shiny_colors_db.json")
        self.status_path = os.getenv("STATUS_PATH", "./sync_status.json")  # 同步状态文件
        self.temp_dir = os.getenv("TEMP_DIR", "./downloads")
        self.formats = ["WAV", "AIFF", "ALAC", "FLAC"]
        self.retry_count = 3
        self.use_aria2 = False  # 是否使用 aria2 下载
        self.aria2_path = "aria2c"  # aria2c 命令路径

        # 尝试加载 YAML 配置
        if self.config_path and os.path.exists(self.config_path):
            try:
                import yaml

                with open(self.config_path, "r", encoding="utf-8") as f:
                    cfg = yaml.safe_load(f) or {}

                webdav = cfg.get("webdav", {})
                self.webdav_url = webdav.get("url", self.webdav_url)
                self.webdav_username = webdav.get("username", self.webdav_username)
                self.webdav_password = webdav.get("password", self.webdav_password)
                self.webdav_base_path = webdav.get("base_path", self.webdav_base_path)

                download = cfg.get("download", {})
                self.temp_dir = download.get("temp_dir", self.temp_dir)
                self.retry_count = download.get("retry_count", self.retry_count)
                self.use_aria2 = download.get("use_aria2", self.use_aria2)
                self.aria2_path = download.get("aria2_path", self.aria2_path)
                self.upload_retries = download.get("upload_retries", 3)  # 上传重试次数
                self.upload_timeout = download.get("upload_timeout", 300)  # 上传超时（秒）

                sync = cfg.get("sync", {})
                self.formats = sync.get("formats", self.formats)

                self.db_path = cfg.get("database", self.db_path)
                self.status_path = cfg.get("status_file", self.status_path)  # 加载状态文件配置

                logger.info(f"Loaded config from: {self.config_path}")
            except ImportError:
                logger.warning("PyYAML not installed, using environment variables")
            except Exception as e:
                logger.warning(f"Failed to load config: {e}")


class OneDriveDownloader:
    """OneDrive 下载器 (支持 wfhtony.space 链接)"""

    def __init__(self, temp_dir):
        self.temp_dir = temp_dir
        os.makedirs(temp_dir, exist_ok=True)

    def download(self, url, password, output_path, dry_run=False):
        """
        下载 OneDrive 文件
        返回: (success, original_filename)
        """
        if dry_run:
            logger.info(f"[DRY RUN] Would download: {url}")
            return True, None

        try:
            import requests

            # wfhtony.space 链接处理
            if "wfhtony.space" in url:
                return self._download_from_wfhtony(url, password, output_path)
            # 1drv.ms 短链接
            elif "1drv.ms" in url:
                return self._download_from_1drv(url, output_path)
            else:
                logger.error(f"Unknown OneDrive URL format: {url}")
                return False, None

        except Exception as e:
            logger.error(f"Download failed: {e}")
            return False, None

    def get_download_url_from_wfhtony(self, url, password):
        """从 wfhtony.space 获取下载直链（不下载文件）"""
        try:
            from playwright.sync_api import sync_playwright
            
            logger.info(f"Getting download URL from: {url}")
            
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                context = browser.new_context(
                    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                )
                page = context.new_page()
                
                # 监听网络请求
                download_urls = []
                original_filename = None
                
                def handle_response(response):
                    nonlocal download_urls
                    # 检查是否是下载请求
                    if response.status == 200:
                        url = response.url
                        content_type = response.headers.get('content-type', '')
                        content_disp = response.headers.get('content-disposition', '')
                        
                        # 严格的下载链接识别
                        # 1. 必须是 OneDrive/Microsoft 的下载链接
                        # 2. 或者包含 attachment 的 content-disposition
                        is_onedrive_download = (
                            'microsoftpersonalcontent.com' in url or
                            '1drv.ms' in url or
                            'sharepoint.com' in url
                        )
                        is_file_download = (
                            'application/zip' in content_type or
                            'application/x-zip' in content_type or
                            'application/octet-stream' in content_type or
                            'attachment' in content_disp
                        )
                        
                        if is_onedrive_download or is_file_download:
                            download_urls.append(url)
                            logger.info(f"Found download URL: {url[:100]}...")
                
                page.on('response', handle_response)
                
                try:
                    # 访问页面 - 使用 domcontentloaded 而不是 networkidle
                    page.goto(url, wait_until='domcontentloaded', timeout=60000)
                    
                    # 检查是否被重定向到失效页面 (home?path=cloudreve://)
                    current_url = page.url
                    if 'home?path=cloudreve://' in current_url:
                        logger.warning(f"Share link expired (redirected to home): {url}")
                        print(f"  ⚠️  Share link expired, skipping...")
                        return "SHARE_EXPIRED", None  # 特殊标记表示分享已失效
                    
                    # 等待页面加载
                    try:
                        page.wait_for_selector('#app-loader', state='hidden', timeout=15000)
                    except:
                        pass
                    
                    page.wait_for_timeout(3000)
                    
                    # 再次检查页面标题是否包含"已失效的分享"
                    page_title = page.title()
                    if '已失效的分享' in page_title or '分享不存在或已过期' in page.content():
                        logger.warning(f"Share link expired (title/content check): {url}")
                        print(f"  ⚠️  Share link expired, skipping...")
                        return "SHARE_EXPIRED", None
                    
                    # 输入密码
                    password_selectors = [
                        '.MuiInputBase-input.MuiFilledInput-input',
                        '.MuiInputBase-input',
                        'input[type="password"]',
                        'input[placeholder*="密码"]',
                    ]
                    
                    password_input = None
                    for selector in password_selectors:
                        password_input = page.query_selector(selector)
                        if password_input:
                            break
                    
                    if password_input:
                        if not password:
                            logger.error(f"Share requires password but none provided")
                            return None, None
                        
                        password_input.fill(password)
                        page.wait_for_timeout(500)
                        
                        # 点击提交
                        box = password_input.bounding_box()
                        if box:
                            click_x = box['x'] + box['width'] + 50
                            click_y = box['y'] + box['height'] / 2
                            page.mouse.click(click_x, click_y)
                        
                        # 等待页面加载
                        page.wait_for_timeout(5000)
                        try:
                            page.wait_for_selector('button:has-text("下载")', timeout=30000)
                        except:
                            pass
                        page.wait_for_timeout(2000)
                    
                    # 点击下载按钮
                    download_buttons = [
                        'button:has-text("下载")',
                        'button:has-text("Download")',
                    ]
                    
                    for selector in download_buttons:
                        try:
                            btn = page.query_selector(selector)
                            if btn and btn.is_visible():
                                logger.info(f"Clicking download button...")
                                
                                # 监听下载事件获取文件名
                                with page.expect_download(timeout=5000) as download_info:
                                    btn.click()
                                    try:
                                        download = download_info.value
                                        original_filename = download.suggested_filename
                                        logger.info(f"Original filename: {original_filename}")
                                        # 取消下载
                                        download.cancel()
                                    except:
                                        pass
                                
                                break
                        except Exception as e:
                            logger.debug(f"Button click failed: {e}")
                            continue
                    
                    # 等待网络请求完成
                    page.wait_for_timeout(3000)
                    
                    if download_urls:
                        # 返回最后一个下载链接（通常是实际文件）
                        final_url = download_urls[-1]
                        logger.info(f"Got download URL: {final_url[:100]}...")
                        return final_url, original_filename
                    else:
                        logger.error("No download URL found")
                        return None, None
                        
                finally:
                    browser.close()
                    
        except Exception as e:
            logger.error(f"Failed to get download URL: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return None, None

    def _download_from_wfhtony(self, url, password, output_path):
        """从 wfhtony.space (Cloudreve) 下载 - 使用 Playwright 浏览器自动化"""
        try:
            from playwright.sync_api import sync_playwright
            import time
            
            logger.info(f"Opening browser for: {url}")
            
            with sync_playwright() as p:
                # 启动浏览器 (headless 模式)
                browser = p.chromium.launch(headless=False, slow_mo=500)  # 显示浏览器，减慢操作以便观察
                context = browser.new_context(
                    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                )
                page = context.new_page()
                
                # 监听下载事件
                download_url = None
                download_event = None
                
                def handle_download(download):
                    nonlocal download_event
                    download_event = download
                
                page.on("download", handle_download)
                
                try:
                    # 访问分享页面 - 使用 domcontentloaded 而不是 networkidle
                    logger.info(f"Navigating to {url}...")
                    page.goto(url, wait_until="domcontentloaded", timeout=60000)
                    
                    # 检查是否被重定向到失效页面 (home?path=cloudreve://)
                    current_url = page.url
                    if 'home?path=cloudreve://' in current_url:
                        logger.warning(f"Share link expired (redirected to home): {url}")
                        print(f"  ⚠️  Share link expired, skipping...")
                        return "SHARE_EXPIRED", None  # 特殊标记表示分享已失效
                    
                    # 等待页面加载和 loader 消失
                    try:
                        page.wait_for_selector('#app-loader', state='hidden', timeout=15000)
                        logger.info("App loader hidden")
                    except:
                        logger.warning("App loader not found or still visible")
                    
                    page.wait_for_timeout(5000)  # 额外等待确保页面稳定
                    
                    # 再次检查页面标题是否包含"已失效的分享"
                    page_title = page.title()
                    if '已失效的分享' in page_title or '分享不存在或已过期' in page.content():
                        logger.warning(f"Share link expired (title/content check): {url}")
                        print(f"  ⚠️  Share link expired, skipping...")
                        return "SHARE_EXPIRED", None
                    # 保存初始页面截图用于调试
                    initial_screenshot = output_path.replace('.zip', '_initial.png')
                    try:
                        page.screenshot(path=initial_screenshot, timeout=10000)
                        logger.info(f"Initial screenshot saved: {initial_screenshot}")
                    except Exception as e:
                        logger.warning(f"Could not take initial screenshot: {e}")
                    
                    # Cloudreve 使用 MUI 组件，密码输入框是 .MuiInputBase-input
                    # 尝试多种选择器
                    password_selectors = [
                        '.MuiInputBase-input.MuiFilledInput-input',
                        '.MuiInputBase-input',
                        'input[type="password"]',
                        'input[placeholder*="密码"]',
                        'input[placeholder*="分享"]',
                    ]
                    
                    password_input = None
                    for selector in password_selectors:
                        password_input = page.query_selector(selector)
                        if password_input:
                            logger.info(f"Found password input with selector: {selector}")
                            break
                    
                    # 如果没找到密码输入框，检查是否已经解锁
                    if not password_input:
                        # 检查是否已经有下载按钮（可能不需要密码）
                        dl_btn = page.query_selector('button:has-text("下载")')
                        if dl_btn:
                            logger.info("No password required, download button already visible")
                            password_input = None  # 不需要密码
                        else:
                            logger.warning("Password input not found, checking page content...")
                            # 获取页面内容用于调试
                            page_content = page.content()[:500]
                            logger.debug(f"Page content preview: {page_content}")
                    if password_input:
                        if not password:
                            logger.error(f"Share requires password but none provided: {url}")
                            return False
                        
                        logger.info(f"Entering password...")
                        
                        # 使用 fill 方法直接输入密码
                        password_input.fill(password)
                        page.wait_for_timeout(500)
                        
                        entered = password_input.input_value()
                        logger.info(f"Password set: {entered[:10]}... (len={len(entered)})")
                        # 获取输入框位置，点击右侧的提交按钮
                        box = password_input.bounding_box()
                        if box:
                            click_x = box['x'] + box['width'] + 50
                            click_y = box['y'] + box['height'] / 2
                            logger.info(f"Clicking submit button at ({click_x:.0f}, {click_y:.0f})")
                            page.mouse.click(click_x, click_y)
                        
                        # 等待下载按钮出现 - Cloudreve 需要时间加载 OneDrive 预览
                        logger.info(f"Waiting for download button (OneDrive loading)...")
                        page.wait_for_timeout(5000)  # 增加等待时间
                        
                        try:
                            page.wait_for_selector('button:has-text("下载")', timeout=30000)  # 增加超时到30秒
                            logger.info(f"Download button appeared!")
                        except:
                            logger.warning(f"Download button not appeared after unlock")
                            debug_path = output_path.replace('.zip', '_unlock_failed.png')
                            page.screenshot(path=debug_path)
                            logger.info(f"Screenshot saved: {debug_path}")
                        
                        page.wait_for_timeout(2000)  # 额外等待2秒确保页面稳定
                    # 查找下载按钮
                    download_buttons = [
                        'button:has-text("下载")',
                        'button:has-text("Download")',
                        'a:has-text("下载")',
                        '.v-btn:has-text("下载")',
                        '[data-testid="download"]',
                        'button[aria-label*="download" i]',
                    ]
                    
                    clicked_download = False
                    for selector in download_buttons:
                        try:
                            btn = page.query_selector(selector)
                            if btn and btn.is_visible():
                                logger.info(f"Found download button, clicking...")
                                
                                # 获取下载链接 - 监听网络请求
                                logger.info(f"Waiting for download to start...")
                                print("\n  ⏳ Downloading...", end="", flush=True)
                                
                                with page.expect_download(timeout=120000) as download_info:
                                    btn.click()
                                    download = download_info.value
                                    
                                    # 获取原始文件名
                                    original_filename = download.suggested_filename
                                    print(f"\n  📁 File: {original_filename}")
                                    logger.info(f"Original filename: {original_filename}")
                                    
                                    # 显示下载进度
                                    print("  ⏬ Downloading...", end="", flush=True)
                                    
                                    # 保存到指定路径
                                    download.save_as(output_path)
                                    print(" ✅")
                                    logger.info(f"Downloaded: {output_path}")
                                    
                                    if os.path.exists(output_path):
                                        size = os.path.getsize(output_path)
                                        logger.info(f"File size: {size / (1024*1024):.1f} MB")
                                        return True, original_filename
                                    else:
                                        logger.error(f"File not saved: {output_path}")
                                        return False, None
                                
                                clicked_download = True
                                break
                        except Exception as e:
                            logger.debug(f"Button {selector} not found or not clickable: {e}")
                            continue
                    
                    if not clicked_download:
                        # 尝试直接查找下载链接
                        logger.info("Looking for direct download link...")
                        links = page.query_selector_all('a[href*="download"]')
                        for link in links:
                            href = link.get_attribute('href')
                            if href:
                                logger.info(f"Found download link: {href[:100]}...")
                                return self._download_file(href, output_path)
                        
                        # 截图保存以便调试
                        try:
                            screenshot_path = output_path.replace('.zip', '_debug.png')
                            page.screenshot(path=screenshot_path, timeout=30000)
                        except Exception as screenshot_error:
                            logger.warning(f"Could not take screenshot: {screenshot_error}")
                        logger.error(f"Could not find download button. Screenshot saved: {screenshot_path}")
                        logger.info(f"Please download manually: {url}")
                        logger.info(f"Password: {password}")
                        return False, None
                    
                finally:
                    browser.close()
                    
        except ImportError:
            logger.error("Playwright not installed. Run: pip install playwright && python -m playwright install chromium")
            return False, None
        except Exception as e:
            logger.error(f"wfhtony.space download error: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return False, None

    def _download_from_1drv(self, url, output_path):
        """从 1drv.ms 短链接下载
        返回: (success, original_filename)
        """
        import requests

        try:
            # 跟踪重定向获取真实链接
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            }
            response = requests.head(
                url, headers=headers, timeout=30, allow_redirects=True
            )
            real_url = response.url

            # 转换为直接下载链接
            if "drive.google.com" in real_url:
                return self._download_from_gdrive(real_url, output_path)
            elif "1drv.ms" in real_url or "onedrive.live.com" in real_url:
                # 转换为下载链接
                if "redir?" in real_url:
                    download_url = real_url.replace("redir?", "download?")
                else:
                    download_url = real_url + "?download=1"
                return self._download_file(download_url, output_path)
            else:
                logger.error(f"Unknown redirect URL: {real_url}")
                return False, None

        except Exception as e:
            logger.error(f"1drv.ms download error: {e}")
            return False, None

    def _download_from_gdrive(self, url, output_path):
        """从 Google Drive 下载"""
        try:
            import gdown

            # 提取文件 ID
            file_id = None
            if "file/d/" in url:
                file_id = url.split("/file/d/")[1].split("/")[0]
            elif "open?id=" in url:
                file_id = url.split("open?id=")[1].split("&")[0]

            if not file_id:
                logger.error(f"Could not extract Google Drive file ID from: {url}")
                return False

            # 使用 gdown 下载
            gdown_url = f"https://drive.google.com/uc?id={file_id}"
            logger.info(f"Downloading from Google Drive: {file_id}")

            gdown.download(gdown_url, output_path, quiet=False)
            return os.path.exists(output_path)

        except ImportError:
            logger.error("gdown not installed. Run: pip install gdown")
            return False
        except Exception as e:
            logger.error(f"Google Drive download error: {e}")
            return False

    def _download_file(self, url, output_path):
        """通用文件下载"""
        import requests

        try:
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            }

            with requests.get(
                url, headers=headers, stream=True, timeout=300
            ) as response:
                response.raise_for_status()

                total_size = int(response.headers.get("content-length", 0))
                downloaded = 0
                
                if total_size > 0:
                    print(f"  📦 Size: {total_size / (1024*1024):.1f} MB")

                with open(output_path, "wb") as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        if chunk:
                            f.write(chunk)
                            downloaded += len(chunk)
                            if total_size > 0:
                                progress = (downloaded / total_size) * 100
                                mb_downloaded = downloaded / (1024 * 1024)
                                mb_total = total_size / (1024 * 1024)
                                print(
                                    f"\r  ⏬ Progress: {progress:.1f}% ({mb_downloaded:.1f}/{mb_total:.1f} MB)",
                                    end="", flush=True
                                )

                print()  # 换行

            logger.info(
                f"Downloaded: {output_path} ({downloaded / (1024 * 1024):.1f} MB)"
            )
            return True

        except Exception as e:
            logger.error(f"File download error: {e}")
            return False

class Aria2Downloader:
    """Aria2 下载器"""

    def __init__(self, config):
        self.config = config
        self.temp_dir = config.temp_dir
        self.aria2_path = config.aria2_path
        os.makedirs(self.temp_dir, exist_ok=True)

    def is_available(self):
        """检查 aria2 是否可用"""
        try:
            import subprocess
            result = subprocess.run(
                [self.aria2_path, "--version"],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except Exception:
            return False

    def download(self, url, output_path, dry_run=False):
        """使用 aria2 下载文件"""
        if dry_run:
            logger.info(f"[DRY RUN] Would download with aria2: {url}")
            return True

        if not self.is_available():
            logger.error("aria2c not found. Please install aria2 first.")
            return False

        try:
            import subprocess
            
            # aria2c 命令参数 - 性能优化配置
            cmd = [
                self.aria2_path,
                # 连接和线程配置（拉满）
                "-x", "16",  # 每个服务器最大 16 个连接
                "-s", "16",  # 单文件最大 16 个分片
                "-k", "1M",  # 最小分片大小 1MB
                
                # 重试和超时配置
                "--max-tries=10",  # 最多重试 10 次
                "--retry-wait=5",   # 重试间隔 5 秒
                "--timeout=120",    # 超时 120 秒
                "--connect-timeout=60",  # 连接超时 60 秒
                
                # 性能优化
                "--max-concurrent-downloads=1",  # 同时下载 1 个文件
                "--max-overall-download-limit=0",  # 不限速
                "--file-allocation=none",  # 不预分配文件（更快开始）
                "--continue=true",  # 启用断点续传
                
                # 网络配置
                "--check-certificate=false",  # 跳过 SSL 验证
                "--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                
                # 输出配置
                "-d", os.path.dirname(output_path),  # 输出目录
                "-o", os.path.basename(output_path),  # 输出文件名
                url
            ]

            logger.info(f"Downloading with aria2: {url}")
            logger.info(f"Output: {output_path}")

            # 执行下载
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=3600  # 1 小时超时
            )

            if result.returncode == 0:
                if os.path.exists(output_path):
                    size = os.path.getsize(output_path)
                    logger.info(f"Downloaded: {output_path} ({size / (1024*1024):.1f} MB)")
                    return True
                else:
                    logger.error(f"File not found after download: {output_path}")
                    return False
            else:
                logger.error(f"aria2 download failed: {result.stderr}")
                return False

        except subprocess.TimeoutExpired:
            logger.error("Download timeout")
            return False
        except Exception as e:
            logger.error(f"aria2 download error: {e}")
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

            self.client = Client(
                {
                    "webdav_hostname": self.config.webdav_url,
                    "webdav_login": self.config.webdav_username,
                    "webdav_password": self.config.webdav_password,
                }
            )
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

    def ensure_directory(self, remote_path):
        """确保远程目录存在"""
        if not self.client:
            return False

        try:
            # 检查目录是否存在
            if not self.client.check(remote_path):
                # 递归创建目录
                parts = remote_path.strip("/").split("/")
                current = ""
                for part in parts:
                    current += "/" + part
                    try:
                        if not self.client.check(current):
                            self.client.mkdir(current)
                            logger.info(f"Created directory: {current}")
                    except Exception:
                        pass
            return True
        except Exception as e:
            logger.error(f"Failed to ensure directory: {e}")
            return False

    def upload(self, local_path, remote_path, dry_run=False, max_retries=None):
        """上传文件到 WebDAV（宽松验证模式：不报错即成功）"""
        if dry_run:
            logger.info(f"[DRY RUN] Would upload: {local_path} -> {remote_path}")
            return True

        if not self.client:
            logger.error("WebDAV client not initialized")
            return False
        
        # 从配置读取重试次数
        if max_retries is None:
            max_retries = getattr(self.config, 'upload_retries', 3)

        # 重试循环
        for attempt in range(max_retries):
            try:
                if attempt > 0:
                    logger.info(f"Retry attempt {attempt + 1}/{max_retries}")
                    print(f"  ⚠️  Retrying upload ({attempt + 1}/{max_retries})...")
                    time.sleep(5)  # 重试前等待

                # 确保目录存在
                remote_dir = os.path.dirname(remote_path)
                if remote_dir:
                    self.ensure_directory(remote_dir)

                # 上传文件
                logger.info(f"Uploading: {local_path} -> {remote_path}")
                file_size = os.path.getsize(local_path) / (1024 * 1024)  # MB
                print(f"  ⏬ Uploading {file_size:.1f} MB...")
                
                self.client.upload_sync(remote_path=remote_path, local_path=local_path)

                # 宽松验证：上传不报错即成功
                logger.info(f"Upload completed (no error): {remote_path}")
                print(f"  ✅ Upload done ({file_size:.1f} MB)")
                return True

            except Exception as e:
                logger.error(f"Upload failed (attempt {attempt + 1}/{max_retries}): {e}")
                print(f"  ❌ Upload error: {str(e)[:100]}")
                
                if attempt < max_retries - 1:
                    logger.info("Will retry after 5 seconds...")
                    continue
                else:
                    logger.error(f"All {max_retries} attempts failed")
                    return False

        return False

    def get_remote_path(self, series_name, album_code, album_title, filename):
        """
        生成 WebDAV 路径
        结构: /SHINY_COLORS/系列名/[专辑代码] 专辑名/文件名
        """
        # 清理系列名和专辑名中的特殊字符
        safe_series = self._sanitize_folder_name(series_name)
        safe_album = self._sanitize_folder_name(f"[{album_code}] {album_title}")
        safe_filename = self._sanitize_filename(filename)

        # 构建路径
        base_path = self.config.webdav_base_path.rstrip("/")
        remote_path = f"{base_path}/{safe_series}/{safe_album}/{safe_filename}"

        return remote_path

    def _sanitize_name(self, name):
        """清理名称中的特殊字符"""
        # 移除文件系统不支持的字符，但保留空格
        name = re.sub(r'[<>:"/\\|?*]', "", name)
        name = name.replace('"', "").replace('"', "")
        name = name.replace("\u201c", "'").replace("\u201d", "'")
        # 移除多余的空格
        name = re.sub(r" +", " ", name)
        return name.strip()
    
    def _sanitize_folder_name(self, name):
        """清理文件夹名称 - 保留空格"""
        # 移除文件系统不支持的字符
        name = re.sub(r'[<>:"/\\|?*]', "", name)
        name = name.replace('"', "").replace('"', "")
        name = name.replace("\u201c", "'").replace("\u201d", "'")
        # 保留空格，只移除首尾空格和多余空格
        name = re.sub(r" +", " ", name)
        return name.strip()

    def _sanitize_filename(self, filename):
        """清理文件名"""
        # 保留扩展名
        name, ext = os.path.splitext(filename)
        name = self._sanitize_folder_name(name)
        return f"{name}{ext}"

class SyncStatusManager:
    """同步状态管理器 - 独立管理上传状态"""
    
    def __init__(self, status_path="./sync_status.json"):
        self.status_path = status_path
        self.status = self._load()
    
    def _load(self):
        """加载同步状态"""
        if not os.path.exists(self.status_path):
            logger.info(f"Creating new sync status file: {self.status_path}")
            return {}
        
        try:
            with open(self.status_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load sync status: {e}")
            return {}
    
    def save(self):
        """保存同步状态"""
        try:
            with open(self.status_path, "w", encoding="utf-8") as f:
                json.dump(self.status, f, ensure_ascii=False, indent=2)
            logger.info(f"Sync status saved: {self.status_path}")
        except Exception as e:
            logger.error(f"Failed to save sync status: {e}")
    
    def get_status(self, series_name, album_code):
        """获取专辑同步状态"""
        if series_name not in self.status:
            return {}
        return self.status[series_name].get(album_code, {})
    
    def update_status(self, series_name, album_code, status_data):
        """更新专辑同步状态"""
        if series_name not in self.status:
            self.status[series_name] = {}
        
        self.status[series_name][album_code] = status_data
        self.save()
    
    def is_uploaded(self, series_name, album_code):
        """检查专辑是否已上传"""
        status = self.get_status(series_name, album_code)
        return status.get("uploaded", False)
    
    def mark_uploaded(self, series_name, album_code, remote_path, size, format_name):
        """标记专辑为已上传"""
        status_data = {
            "uploaded": True,
            "downloaded": False,
            "remote_path": remote_path,
            "size": size,
            "format": format_name,
            "synced_at": datetime.now().isoformat()
        }
        self.update_status(series_name, album_code, status_data)
    
    def clear_status(self, series_name=None, album_code=None):
        """清除同步状态"""
        if series_name is None:
            # 清除所有状态
            self.status = {}
        elif album_code is None:
            # 清除整个系列
            if series_name in self.status:
                del self.status[series_name]
        else:
            # 清除特定专辑
            if series_name in self.status:
                if album_code in self.status[series_name]:
                    del self.status[series_name][album_code]
        
        self.save()
    
    def get_all_uploaded(self):
        """获取所有已上传的专辑列表"""
        uploaded = []
        for series_name, albums in self.status.items():
            for album_code, status in albums.items():
                if status.get("uploaded", False):
                    uploaded.append({
                        "series": series_name,
                        "code": album_code,
                        "remote_path": status.get("remote_path"),
                        "size": status.get("size"),
                        "format": status.get("format"),
                        "synced_at": status.get("synced_at")
                    })
        return uploaded


class DatabaseManager:
    """数据库管理器"""

    def __init__(self, db_path):
        self.db_path = db_path
        self.data = self._load()

    def _load(self):
        """加载数据库"""
        if not os.path.exists(self.db_path):
            logger.error(f"Database not found: {self.db_path}")
            return {"series": {}, "metadata": {}}

        with open(self.db_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def save(self):
        """保存数据库"""
        self.data["metadata"]["last_synced"] = datetime.now().isoformat()
        with open(self.db_path, "w", encoding="utf-8") as f:
            json.dump(self.data, f, ensure_ascii=False, indent=2)
        logger.info(f"Database saved: {self.db_path}")

    def get_pending_albums(self, formats, status_manager=None, force=False):
        """
        获取待处理的专辑
        返回: [(series_name, album, download_info), ...]
        """
        pending = []
        format_order = {fmt: i for i, fmt in enumerate(formats)}

        for series_name, series_data in self.data.get("series", {}).items():
            for album in series_data.get("albums", []):
                album_code = album.get("code", "")
                
                # 从独立的 status_manager 获取状态
                if status_manager:
                    is_uploaded = status_manager.is_uploaded(series_name, album_code)
                else:
                    # 兼容旧模式
                    sync_status = album.get("sync_status", {})
                    is_uploaded = sync_status.get("uploaded", False)

                # 检查是否需要同步
                if not force and is_uploaded:
                    continue

                # 获取最佳下载链接
                downloads = album.get("downloads", [])
                best_download = self._get_best_download(downloads, format_order)

                if best_download:
                    pending.append((series_name, album, best_download))

        return pending

    def _get_best_download(self, downloads, format_order):
        """获取最佳下载链接 (优先 OneDrive，其次 Google Drive)"""
        if not downloads:
            return None

        # 分组: OneDrive 和 Google Drive
        onedrive_downloads = [d for d in downloads if d.get("source") == "onedrive"]
        gdrive_downloads = [d for d in downloads if d.get("source") == "google_drive"]

        # 按 format_order 排序
        def sort_key(d):
            return format_order.get(d.get("format", ""), 999)

        # 优先 OneDrive
        if onedrive_downloads:
            onedrive_downloads.sort(key=sort_key)
            return onedrive_downloads[0]

        # 其次 Google Drive
        if gdrive_downloads:
            gdrive_downloads.sort(key=sort_key)
            return gdrive_downloads[0]

        return None


def verify_all_uploads(config, status_manager, dry_run=False):
    """
    验证所有已上传的专辑，重新标注上传状态
    扫描 WebDAV 目录，对比状态文件，修正不准确的状态
    """
    print()
    print("=" * 60)
    print("[Final Verification] Scanning WebDAV and updating status...")
    print("=" * 60)
    
    try:
        from webdav3.client import Client
        
        client = Client({
            'webdav_hostname': config.webdav_url,
            'webdav_login': config.webdav_username,
            'webdav_password': config.webdav_password,
        })
        
        # 扫描远程文件
        all_remote_files = {}
        base_path = config.webdav_base_path
        
        def scan_dir(path, depth=0):
            """递归扫描目录"""
            try:
                items = client.list(path)
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
                        scan_dir(full_path, depth + 1)
                    else:
                        # 获取文件大小
                        try:
                            info = client.info(full_path)
                            size_str = info.get('size', '0')
                            size = int(float(str(size_str))) if size_str else 0
                        except:
                            size = 0
                        all_remote_files[full_path] = size
            except Exception as e:
                logger.warning(f"Failed to scan {path}: {e}")
        
        print(f"Scanning: {base_path}")
        scan_dir(base_path)
        print(f"Found {len(all_remote_files)} remote files")
        
        # 构建专辑代码到路径的映射
        remote_album_map = {}  # album_code -> (path, size)
        for full_path, size in all_remote_files.items():
            filename = full_path.split('/')[-1]
            # 从文件名提取专辑代码
            patterns = [
                r'^\[?\d{6}\]?\s*.*?\s*([A-Z]+-\d+)',
                r'^([A-Z]+-\d+)[\s_\-]',
                r'^([A-Za-z]+-\d+)[\s_\-\.]',
                r'^([A-Za-z]+-\d+)\.zip$',
                r'^([A-Za-z]+-\d+)_',
            ]
            for pattern in patterns:
                match = re.match(pattern, filename, re.IGNORECASE)
                if match:
                    code = match.group(1).upper()
                    remote_album_map[code] = (full_path, size)
                    break
        
        print(f"Extracted {len(remote_album_map)} album codes from filenames")
        
        # 验证并更新状态
        stats = {
            'verified': 0,
            'fixed_true': 0,    # 原来是 false，修正为 true
            'fixed_false': 0,   # 原来是 true，修正为 false
            'unchanged': 0,
        }
        
        # 遍历所有已记录的状态
        for series_name in list(status_manager.status.keys()):
            albums = status_manager.status.get(series_name, {})
            for album_code in list(albums.keys()):
                status = albums.get(album_code, {})
                current_uploaded = status.get('uploaded', False)
                
                # 检查远程是否存在
                if album_code in remote_album_map:
                    remote_path, remote_size = remote_album_map[album_code]
                    
                    if not current_uploaded:
                        # 远程存在但状态是 false，修正为 true
                        logger.info(f"[FIX -> True] {series_name}/{album_code}")
                        stats['fixed_true'] += 1
                        
                        if not dry_run:
                            status_manager.update_status(series_name, album_code, {
                                'uploaded': True,
                                'downloaded': False,
                                'remote_path': remote_path,
                                'size': remote_size,
                                'verified_at': datetime.now().isoformat()
                            })
                    else:
                        stats['verified'] += 1
                else:
                    # 远程不存在
                    if current_uploaded:
                        # 状态是 true 但远程不存在，修正为 false
                        logger.info(f"[FIX -> False] {series_name}/{album_code}")
                        stats['fixed_false'] += 1
                        
                        if not dry_run:
                            status['uploaded'] = False
                            status['verified_at'] = datetime.now().isoformat()
                            status_manager.save()
                    else:
                        stats['unchanged'] += 1
        
        print()
        print("Verification Results:")
        print(f"  Already verified: {stats['verified']}")
        print(f"  Fixed (uploaded -> True): {stats['fixed_true']}")
        print(f"  Fixed (uploaded -> False): {stats['fixed_false']}")
        print(f"  Unchanged (not uploaded): {stats['unchanged']}")
        
        if dry_run:
            print("  [DRY RUN] Status not saved")
        
        return stats
        
    except Exception as e:
        logger.error(f"Verification failed: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return None


def main():
    """主函数"""
    parser = argparse.ArgumentParser(description="SHINY COLORS 下载同步程序")
    parser.add_argument(
        "--dry-run", action="store_true", help="预览模式，不实际下载/上传"
    )
    parser.add_argument("--force", action="store_true", help="强制重新下载所有")
    parser.add_argument("--series", type=str, help="只同步指定系列")
    parser.add_argument("--test", action="store_true", help="测试 WebDAV 连接")
    parser.add_argument("--config", "-c", type=str, help="配置文件路径")
    parser.add_argument("--db", type=str, help="数据库文件路径")
    parser.add_argument("--skip-verify", action="store_true", help="跳过最后的验证步骤")
    args = parser.parse_args()

    print("=" * 60)
    print("SHINY COLORS 下载同步程序")
    print("=" * 60)

    # 加载配置
    config = Config(args.config)
    if args.db:
        config.db_path = args.db

    # 初始化组件
    db = DatabaseManager(config.db_path)
    status_manager = SyncStatusManager(config.status_path)  # 初始化状态管理器
    downloader = OneDriveDownloader(config.temp_dir)
    uploader = WebDAVUploader(config)

    # 测试模式
    if args.test:
        success, message = uploader.test_connection()
        print(f"WebDAV Connection: {'OK' if success else 'FAILED'} - {message}")
        return

    # 检查 WebDAV 连接
    success, message = uploader.test_connection()
    if not success:
        logger.error(f"WebDAV connection failed: {message}")
        sys.exit(1)

    print(f"WebDAV Connection: OK")
    print()

    # 获取待处理专辑
    print("[Step 1] Finding albums to sync...")
    print("-" * 60)

    pending = db.get_pending_albums(config.formats, status_manager=status_manager, force=args.force)

    # 过滤系列
    if args.series:
        pending = [(s, a, d) for s, a, d in pending if args.series in s]

    if not pending:
        print("No albums to sync. All up to date!")
        return

    print(f"Found {len(pending)} albums to sync")
    print()

    # 处理专辑
    print("[Step 2] Syncing albums...")
    print("-" * 60)

    success_count = 0
    fail_count = 0

    for i, (series_name, album, download_info) in enumerate(pending, 1):
        album_code = album.get("code", "Unknown")
        album_title = album.get("title", "Unknown")
        format_name = download_info.get("format", "Unknown")
        source = download_info.get("source", "Unknown")
        url = download_info.get("url", "")
        password = download_info.get("password", "")

        print(f"\n[{i}/{len(pending)}] {series_name} / {album_code}")
        print(f"  Title: {album_title}")
        print(f"  Format: {format_name} ({source})")

        if args.dry_run:
            print(f"  [DRY RUN] Would download from: {url}")
            success_count += 1
            continue

        # 下载文件
        temp_dir = os.path.join(config.temp_dir, series_name, album_code)
        os.makedirs(temp_dir, exist_ok=True)

        # 推测文件名
        filename = f"{album_code}_{format_name}.zip"
        local_path = os.path.join(temp_dir, filename)

        print(f"  Downloading from: {url}")

        original_filename = None
        success = False
        max_download_retries = 5  # 最大重试次数

        for retry_attempt in range(max_download_retries):
            if retry_attempt > 0:
                logger.info(f"Download retry attempt {retry_attempt + 1}/{max_download_retries}")
                print(f"  ⚠️  Retrying download ({retry_attempt + 1}/{max_download_retries})...")
                time.sleep(5)  # 重试前等待

            # 根据配置选择下载方式
            if config.use_aria2 and source == "onedrive" and "wfhtony.space" in url:
                # 混合模式：Playwright 获取直链 + aria2 下载
                logger.info("Using hybrid mode: Playwright + aria2")
                
                # 1. 获取下载直链
                download_url, original_filename = downloader.get_download_url_from_wfhtony(url, password)
                
                # 检查分享是否失效
                if download_url == "SHARE_EXPIRED":
                    logger.warning(f"Share link expired for {album_code}, skipping this source")
                    print(f"  ⚠️  Share expired, will try next available source")
                    fail_count += 1
                    break  # 跳出重试循环，进入下一个专辑
                
                if download_url:
                    # 2. 使用 aria2 下载
                    aria2_downloader = Aria2Downloader(config)
                    
                    # 推测文件名
                    if original_filename:
                        temp_filename = clean_filename(original_filename)
                    else:
                        temp_filename = f"{album_code}_{format_name}.zip"
                    
                    local_path = os.path.join(temp_dir, temp_filename)
                    success = aria2_downloader.download(download_url, local_path)
                    
                    # 验证下载结果
                    if success:
                        file_size = os.path.getsize(local_path) if os.path.exists(local_path) else 0
                        if file_size < 1024 * 1024:  # 小于 1MB，可能是错误响应
                            logger.error(f"Downloaded file too small: {file_size / 1024:.1f} KB, falling back to Playwright")
                            success = False
                            try:
                                os.remove(local_path)
                            except:
                                pass
                        else:
                            filename = temp_filename
                            print(f"  ✓ Downloaded: {file_size / (1024*1024):.1f} MB")
                            break  # 成功，退出重试循环
                    
                    # 如果 aria2 失败，回退到传统模式
                    if not success:
                        logger.info("Falling back to Playwright download...")
                        if source == "onedrive":
                            result = downloader.download(url, password, local_path, dry_run=False)
                            # 处理返回值 (success, original_filename) 或 ("SHARE_EXPIRED", None)
                            if isinstance(result, tuple) and len(result) == 2:
                                success = result[0]
                                original_filename = result[1]
                            else:
                                success = result
                                original_filename = None
                            
                            # 检查分享是否失效
                            if success == "SHARE_EXPIRED":
                                logger.warning(f"Share link expired for {album_code}, skipping")
                                print(f"  ⚠️  Share expired, will try next available source")
                                fail_count += 1
                                break  # 跳出重试循环
                            
                            if success and original_filename:
                                filename = clean_filename(original_filename)
                                # 重命名文件
                                if filename != original_filename:
                                    new_path = os.path.join(temp_dir, filename)
                                    shutil.move(local_path, new_path)
                                    local_path = new_path
                            if success:
                                break  # 成功，退出重试循环
                else:
                    logger.error("Failed to get download URL")
                    success = False
            else:
                # 传统模式：直接使用 Playwright 下载
                if source == "onedrive":
                    result = downloader.download(url, password, local_path, dry_run=False)
                    # 处理返回值 (success, original_filename) 或 ("SHARE_EXPIRED", None)
                    if isinstance(result, tuple) and len(result) == 2:
                        success = result[0]
                        original_filename = result[1]
                    else:
                        success = result
                        original_filename = None
                    
                    # 检查分享是否失效
                    if success == "SHARE_EXPIRED":
                        logger.warning(f"Share link expired for {album_code}, skipping this source")
                        print(f"  ⚠️  Share expired, will try next available source")
                        fail_count += 1
                        break  # 跳出重试循环
                elif source == "google_drive":
                    result = downloader._download_from_gdrive(url, local_path)
                    if isinstance(result, tuple) and len(result) == 2:
                        success = result[0]
                        original_filename = result[1]
                    else:
                        success = result
                        original_filename = None
                else:
                    print(f"  Unsupported source: {source}")
                    fail_count += 1
                    break  # 不支持源，退出重试循环
                
                if success and success != "SHARE_EXPIRED":
                    break  # 成功，退出重试循环
        
        # 检查最终下载结果
        if not success:
            logger.error(f"All {max_download_retries} download attempts failed")
            print(f"  ❌ Download failed after {max_download_retries} attempts")
            fail_count += 1
            continue  # 跳到下一个专辑

        # 使用原始文件名（如果有）
        if original_filename and not config.use_aria2:
            # 只在非 aria2 模式下处理文件名
            # 清理文件名，去掉随机前缀
            filename = clean_filename(original_filename)
            print(f"  Original filename: {original_filename}")
            print(f"  Cleaned filename: {filename}")
            
            # 如果文件名被修改了，需要重命名本地文件
            if filename != original_filename:
                new_local_path = os.path.join(temp_dir, filename)
                shutil.move(local_path, new_local_path)
                local_path = new_local_path
                logger.info(f"Renamed local file to: {filename}")
        elif not original_filename:
            filename = f"{album_code}_{format_name}.zip"
        else:
            # aria2 模式下文件名已经处理好
            filename = os.path.basename(local_path)
            print(f"  Downloaded as: {filename}")

        # 上传到 WebDAV
        remote_path = uploader.get_remote_path(
            series_name, album_code, album_title, filename
        )

        print(f"  Uploading to: {remote_path}")

        if uploader.upload(local_path, remote_path):
            # 更新状态 - 使用独立的状态管理器
            status_manager.mark_uploaded(
                series_name,
                album_code,
                remote_path,
                os.path.getsize(local_path),
                format_name
            )

            # 清理本地文件
            print(f"  Cleaning up...")
            shutil.rmtree(temp_dir, ignore_errors=True)

            print(f"  SUCCESS")
            success_count += 1
        else:
            print(f"  Upload FAILED")
            fail_count += 1

        # 延迟
        time.sleep(1)

    # 完成
    print()
    print("-" * 60)
    print("Done!")
    print(f"  Success: {success_count}")
    print(f"  Failed: {fail_count}")
    
    # 最后验证所有上传状态
    if not args.dry_run and not args.skip_verify:
        verify_all_uploads(config, status_manager, dry_run=False)
    elif args.dry_run and not args.skip_verify:
        print()
        print("[DRY RUN] Skipping final verification (would verify in real mode)")


if __name__ == "__main__":
    main()
