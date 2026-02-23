# -*- coding: utf-8 -*-
"""
SHINY COLORS 系列数据库管理器
- 从总览页动态获取系列列表
- 维护 JSON 数据库
- 支持增量更新
"""

import json
import urllib.request
import base64
import hashlib
import re
import time
import os
from datetime import datetime
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad

# 配置
JSON_FILE = "d:\\CodeFile\\imas\\shiny_colors_db.json"
INDEX_URL = "https://wfhtony.github.io/2019/05/04/imas-sc-hi-res-ls/"


def fetch_url(url, headers=None):
    """获取 URL 内容"""
    try:
        if headers is None:
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=30) as response:
            return response.read().decode('utf-8')
    except Exception as e:
        print(f"  Fetch error: {e}")
        return None


def fetch_password_from_pastebin(paste_id):
    """从 pastebin raw 获取密码"""
    url = f"https://pastebin.com/raw/{paste_id}"
    content = fetch_url(url)
    if content:
        # 取第一行，去掉各种前缀
        pw = content.strip().split('\n')[0]
        pw = re.sub(r'^(PW|pwd|password|enc_pwd)[\s:：]+', '', pw, flags=re.IGNORECASE)
        return pw.strip()
    return None


def fetch_password_from_rentry(slug):
    """从 rentry 获取密码"""
    url = f"https://rentry.co/{slug}"
    html = fetch_url(url)
    if html:
        # rentry 页面标题通常就是密码
        title_match = re.search(r'<title>([^<]+)</title>', html)
        if title_match:
            pw = title_match.group(1).strip()
            # 去掉各种前缀
            pw = re.sub(r'^(PW|pwd|password|enc_pwd)[\s:：]+', '', pw, flags=re.IGNORECASE)
            return pw.strip()
    return None


def fetch_password(password_url):
    """从外部链接获取密码"""
    if not password_url:
        return None

    # pastebin
    pastebin_match = re.search(r'pastebin\.com/(\w+)', password_url)
    if pastebin_match:
        return fetch_password_from_pastebin(pastebin_match.group(1))

    # rentry
    rentry_match = re.search(r'rentry\.(?:co|org)/(\w+)', password_url)
    if rentry_match:
        return fetch_password_from_rentry(rentry_match.group(1))

    return None


def scan_index_page():
    """扫描总览页，获取所有系列信息"""
    print(f"Scanning index page: {INDEX_URL}")
    html = fetch_url(INDEX_URL)
    if not html:
        print("  Failed to fetch index page")
        return []

    series_dict = {}  # 用 URL 作为 key 去重

    # 提取文章内容区域
    content_match = re.search(r'<div class="article-entry"[^>]*>(.*?)</div>\s*<footer', html, re.DOTALL)
    content = content_match.group(1) if content_match else html

    # 匹配 h3 和 h4 区块
    # h3 区块
    h3_pattern = r'<h3[^>]*>.*?</h3>(.*?)(?=<h[234][^>]*>|$)'
    h3_blocks = re.findall(h3_pattern, content, re.DOTALL)
    h3_titles = re.findall(r'<h3[^>]*><span[^>]*>([^<]+)</span>', content)

    # h4 区块 (Song for Prism 子系列)
    h4_pattern = r'<h4[^>]*>(.*?)</h4>(.*?)(?=<h[234][^>]*>|$)'
    h4_matches = re.findall(h4_pattern, content, re.DOTALL)

    # 链接和密码匹配模式
    link_pattern = r'<a href="(/2011/01/01/imas-hi-res/lts/sc/[^"]+)"[^>]*>[^<]*</a>'
    pw_pattern = r'(https?://(?:pastebin\.com|rentry\.(?:co|org))/[^\s"<>]+)'

    # 处理 h3 系列
    for title, block in zip(h3_titles, h3_blocks):
        # 提取链接
        link_match = re.search(link_pattern, block)
        if not link_match:
            continue

        url = "https://wfhtony.github.io" + link_match.group(1)

        # 跳过已处理的 URL
        if url in series_dict:
            continue

        # 提取密码链接
        pw_match = re.search(pw_pattern, block)
        pw_url = pw_match.group(1) if pw_match else None

        # 清理标题
        clean_title = re.sub(r'【[^】]+】', '', title)
        clean_title = re.sub(r'THE IDOLM@STER SHINY COLORS\s*', '', clean_title)
        clean_title = clean_title.replace('系列', '').replace('"', '').replace('"', '').strip()

        # 判断是否已完结
        completed = '更新完畢' in title and '更新中' not in title

        # 获取密码
        password = None
        if pw_url:
            print(f"  Fetching password for: {clean_title}")
            password = fetch_password(pw_url)
            time.sleep(0.3)

        if password:
            series_dict[url] = {
                "name": clean_title,
                "url": url,
                "password": password.strip(),
                "completed": completed,
                "pw_source": pw_url
            }
        else:
            print(f"  Warning: No password for {clean_title}")

    # 处理 h4 子系列
    for title_html, block in h4_matches:
        # 清理标题
        title = re.sub(r'<[^>]+>', '', title_html).strip()
        title = title.replace('¶', '').strip()

        # 提取链接
        link_match = re.search(link_pattern, block)
        if not link_match:
            continue

        url = "https://wfhtony.github.io" + link_match.group(1)

        # 跳过已处理的 URL
        if url in series_dict:
            continue

        # 提取密码链接
        pw_match = re.search(pw_pattern, block)
        pw_url = pw_match.group(1) if pw_match else None

        # 提取子系列名称 (括号内的内容)
        sub_title_match = re.search(r'Song for Prism[\(（]([^\)）]+)[\)）]', title)
        if sub_title_match:
            clean_title = f"Song for Prism ({sub_title_match.group(1)})"
        else:
            # 保留原始标题但简化
            clean_title = re.sub(r'【[^】]+】', '', title)
            clean_title = re.sub(r'THE IDOLM@STER SHINY COLORS\s*', '', clean_title)
            clean_title = clean_title.replace('系列', '').strip()

        if not clean_title:
            clean_title = "Unknown Series"

        # 判断是否已完结
        completed = '更新完畢' in title and '更新中' not in title

        # 获取密码
        password = None
        if pw_url:
            print(f"  Fetching password for: {clean_title}")
            password = fetch_password(pw_url)
            time.sleep(0.3)

        if password:
            series_dict[url] = {
                "name": clean_title,
                "url": url,
                "password": password.strip(),
                "completed": completed,
                "pw_source": pw_url
            }
        else:
            print(f"  Warning: No password for {clean_title}")

    series_list = list(series_dict.values())
    print(f"  Found {len(series_list)} series")
    return series_list


def cryptojs_decrypt(encrypted_b64, password):
    """CryptoJS AES 解密 (OpenSSL 兼容格式)"""
    try:
        encrypted = base64.b64decode(encrypted_b64)

        if encrypted[:8] != b'Salted__':
            return None

        salt = encrypted[8:16]
        ciphertext = encrypted[16:]

        def evp_bytes_to_key(password, salt, key_len=32, iv_len=16):
            d = b''
            d_i = b''
            while len(d) < key_len + iv_len:
                d_i = hashlib.md5(d_i + password.encode() + salt).digest()
                d += d_i
            return d[:key_len], d[key_len:key_len+iv_len]

        key, iv = evp_bytes_to_key(password, salt)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return decrypted.decode('utf-8')
    except Exception as e:
        print(f"    Decrypt error: {e}")
        return None


def fetch_and_decrypt(url, password):
    """获取页面并解密"""
    try:
        with urllib.request.urlopen(url, timeout=30) as response:
            html = response.read().decode('utf-8')

        match = re.search(r'<div id="enc_content"[^>]*>([^<]+)</div>', html)
        if match:
            return cryptojs_decrypt(match.group(1), password)
        return None
    except Exception as e:
        print(f"    Fetch error: {e}")
        return None


def parse_albums(content):
    """解析专辑信息"""
    albums = []

    # 匹配专辑块: <h3 id="xxx">[CODE] Title</h3> ... 直到下一个 <h3 或 <h2 或文档结尾
    album_pattern = r'<h3[^>]*id="([^"]+)"[^>]*>\[([^\]]+)\]\s*([^<]+)</h3>(.*?)(?=<h[23][^>]*>|$)'

    for match in re.finditer(album_pattern, content, re.DOTALL):
        anchor = match.group(1)
        code = match.group(2)
        title = match.group(3).strip()
        block = match.group(4)

        album = {
            "code": code,
            "title": title,
            "anchor": anchor,
            "cover_url": None,
            "description": None,
            "track_list": [],
            "downloads": []
        }

        # 提取封面图
        img_match = re.search(r'<img[^>]*src="([^"]+)"[^>]*>', block)
        if img_match:
            album["cover_url"] = img_match.group(1)

        # 提取简介 (第一个 blockquote 中收錄於开头的文字)
        desc_match = re.search(r'<blockquote>\s*<p>(收錄於[^<]+)', block)
        if desc_match:
            desc = desc_match.group(1).strip()
            desc = re.sub(r'<[^>]+>', '', desc)
            album["description"] = desc[:300]

        # 提取曲目列表
        track_block_match = re.search(r'<strong>曲目列表</strong>.*?<blockquote>(.*?)</blockquote>', block, re.DOTALL)
        if track_block_match:
            track_block = track_block_match.group(1)
            # 提取曲目名称
            tracks = re.findall(r'<strong>([^<]+)</strong>', track_block)
            album["track_list"] = [t.strip() for t in tracks if t.strip()]

        # 提取下载链接块 - 匹配从 "下載" 到块结束的所有内容
        download_block_match = re.search(r'<strong>下載</strong>(.*?)(?=<h[23]|$)', block, re.DOTALL)
        if download_block_match:
            download_block = download_block_match.group(1)

            # 提取所有链接格式
            # 格式: <a href="URL">名称</a> PW：xxx 或 <a href="URL"><strong>名称</strong></a> PW：xxx

            # 按格式分组提取 - 支持多种格式名称和变体 (WAV, AIFF, ALAC, FLAC, WVP, FLAC+CUE+LOG 等)
            # 匹配 <strong>后面跟着格式名</strong> 的模式
            format_sections = re.split(r'<strong>([A-Z][A-Z0-9+]+)</strong>', download_block)

            current_format = "unknown"
            format_keywords = ['WAV', 'AIFF', 'ALAC', 'FLAC', 'WVP']

            for i, section in enumerate(format_sections):
                # 检查是否是格式名称
                section_upper = section.upper()
                if any(section_upper.startswith(kw) for kw in format_keywords):
                    current_format = section
                    continue

                if not section.strip():
                    continue

                # 提取百度盘链接 (支持有/无strong标签，链接文字可能包含后缀)
                baidu_matches = re.findall(
                    r'<a href="(https?://pan\.baidu\.com/s/[^"]+)"[^>]*>(?:<strong>)?[^<]*(?:百度|百毒)[^<]*(?:</strong>)?</a>[^P]*PW[：:]\s*([^<\s]+)',
                    section
                )
                for url, pw in baidu_matches:
                    pw = re.sub(r'<br\s*/?>$', '', pw)  # 清理末尾的 <br>
                    album["downloads"].append({
                        "format": current_format,
                        "source": "baidu",
                        "url": url,
                        "password": pw
                    })

                # 提取 OneDrive 链接 (支持多种域名格式)
                # 支持 wfhtony.space 和 1drv.ms 短链接
                onedrive_matches = re.findall(
                    r'<a href="(https?://[^\s"]+wfhtony\.space/s/[^"]+)"[^>]*>(?:<strong>)?[Oo]ne[Dd]rive[^<]*(?:</strong>)?</a>[^P]*PW[：:]\s*([^<\s]+)',
                    section
                )
                for url, pw in onedrive_matches:
                    pw = re.sub(r'<br\s*/?>$', '', pw)  # 清理末尾的 <br>
                    album["downloads"].append({
                        "format": current_format,
                        "source": "onedrive",
                        "url": url,
                        "password": pw
                    })

                # 提取 OneDrive 短链接 (1drv.ms)
                onedrive_short_matches = re.findall(
                    r'<a href="(https?://1drv\.ms/[^\s"]+)"[^>]*>(?:<strong>)?[Oo]ne[Dd]rive[^<]*(?:</strong>)?</a>[^P]*PW[：:]\s*([^<\s]+)',
                    section
                )
                for url, pw in onedrive_short_matches:
                    pw = re.sub(r'<br\s*/?>$', '', pw)
                    album["downloads"].append({
                        "format": current_format,
                        "source": "onedrive",
                        "url": url,
                        "password": pw
                    })

                # 提取 Google Drive 链接 (支持 file/d 和 open?id 两种格式，链接文字可能包含后缀)
                gdrive_matches = re.findall(
                    r'<a href="(https?://drive\.google\.com/(?:file/d/[^\s"]+|open\?id=[^\s"]+))"[^>]*>(?:<strong>)?Google\s*Drive[^<]*(?:</strong>)?</a>',
                    section
                )
                for url in gdrive_matches:
                    album["downloads"].append({
                        "format": current_format,
                        "source": "google_drive",
                        "url": url,
                        "password": None
                    })

        albums.append(album)

    return albums


def load_database():
    """加载数据库"""
    if os.path.exists(JSON_FILE):
        with open(JSON_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {"series": {}, "metadata": {}}


def save_database(db):
    """保存数据库"""
    db["metadata"]["last_updated"] = datetime.now().isoformat()
    with open(JSON_FILE, 'w', encoding='utf-8') as f:
        json.dump(db, f, ensure_ascii=False, indent=2)
    print(f"\nDatabase saved: {JSON_FILE}")


def scan_series(series_config, existing_db=None, force=False):
    """扫描系列"""
    name = series_config["name"]
    url = series_config["url"]
    password = series_config["password"]
    completed = series_config.get("completed", False)

    # 检查是否需要跳过
    if not force and existing_db:
        existing = existing_db["series"].get(name, {})
        # 如果数据库中标记为已完结，且当前也标记为已完结，则跳过
        if existing.get("completed") == True:
            print(f"  Skip (completed): {name}")
            return None

    print(f"  Scanning: {name}")

    content = fetch_and_decrypt(url, password)
    if not content:
        print(f"    Failed to decrypt")
        return None

    albums = parse_albums(content)
    print(f"    Found {len(albums)} albums")

    return {
        "name": name,
        "url": url,
        "password": password,
        "completed": completed,
        "albums": albums,
        "album_count": len(albums),
        "scanned_at": datetime.now().isoformat()
    }


def main():
    """主函数"""
    import sys

    force_all = "--force" in sys.argv or "-f" in sys.argv
    mark_completed = "--completed" in sys.argv

    print("=" * 60)
    print("SHINY COLORS Database Manager")
    print("=" * 60)

    # 加载现有数据库
    db = load_database()

    # 扫描总览页获取系列列表
    print("\n[Step 1] Scanning index page...")
    print("-" * 60)
    current_series = scan_index_page()

    if not current_series:
        print("No series found, exiting.")
        return

    # 处理标记已完结的参数
    if mark_completed:
        print("\n[Mark Completed Mode]")
        print("Usage: python sc_manager.py --completed <series_name>")
        if len(sys.argv) > 2:
            series_name = sys.argv[2]
            if series_name in db["series"]:
                db["series"][series_name]["completed"] = True
                save_database(db)
                print(f"  Marked as completed: {series_name}")
            else:
                print(f"  Series not found: {series_name}")
        return

    # 对比并更新
    is_first_run = len(db["series"]) == 0

    if force_all:
        print("\n[Force Mode] Scanning ALL series...")
    elif is_first_run:
        print("\n[First Run] Scanning all series...")
    else:
        print(f"\n[Update] Last update: {db['metadata'].get('last_updated', 'N/A')}")
        print("Scanning new/incomplete series...")

    print("-" * 60)

    updated_count = 0
    skipped_count = 0
    new_count = 0

    for config in current_series:
        name = config["name"]

        # 检查是否是新系列
        if name not in db["series"]:
            new_count += 1
            print(f"  [NEW] {name}")

        # 扫描逻辑
        if force_all:
            result = scan_series(config, None, force=True)
        else:
            result = scan_series(config, db if not is_first_run else None, force=is_first_run)

        if result:
            db["series"][result["name"]] = result
            updated_count += 1
        else:
            skipped_count += 1

        # 礼貌延迟
        time.sleep(0.3)

    # 保存数据库
    save_database(db)

    print("-" * 60)
    print(f"Done!")
    print(f"  New series found: {new_count}")
    print(f"  Updated: {updated_count}")
    print(f"  Skipped: {skipped_count}")
    print(f"  Total series: {len(db['series'])}")

    # 统计
    total_albums = sum(len(s.get("albums", [])) for s in db["series"].values())
    total_downloads = sum(
        len(a.get("downloads", []))
        for s in db["series"].values()
        for a in s.get("albums", [])
    )
    print(f"  Total albums: {total_albums}")
    print(f"  Total download links: {total_downloads}")

    # 显示已完结/未完结统计
    completed_count = sum(1 for s in db["series"].values() if s.get("completed"))
    print(f"  Completed: {completed_count} / Ongoing: {len(db['series']) - completed_count}")


if __name__ == "__main__":
    main()
