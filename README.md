# SHINY COLORS 下载同步工具

从 Google Drive 下载 SHINY COLORS Hi-Res 音频文件并同步到 OpenList (WebDAV)。

**流程**: 下载一个 → 上传一个 → 清理本地 → 下一个

## 快速开始 (Windows)

```powershell
# 1. 安装依赖
pip install -r requirements.txt

# 2. 创建配置文件
copy config.yaml.example config.yaml
notepad config.yaml  # 填入 WebDAV 配置

# 3. 预览模式（不实际下载）
python sc_sync.py --dry-run

# 4. 正式运行
python sc_sync.py
```

## 配置文件 (config.yaml)

```yaml
webdav:
  url: https://你的openlist地址/dav
  username: 你的用户名
  password: 你的密码
  base_path: /SHINY_COLORS

download:
  temp_dir: ./downloads  # 临时下载目录
  retry_count: 3

sync:
  formats:  # 格式优先级
    - WAV
    - AIFF
    - ALAC
    - FLAC

database: ./shiny_colors_db.json
```

## 命令参数

| 命令 | 说明 |
|------|------|
| `python sc_sync.py` | 同步待处理的专辑 |
| `python sc_sync.py --dry-run` | 预览模式，不实际下载 |
| `python sc_sync.py --force` | 强制重新下载所有 |
| `python sc_sync.py --series "系列名"` | 只同步指定系列 |
| `python sc_sync.py --test` | 测试 WebDAV 连接 |
| `python sc_sync.py --verify` | 自检：对比 DB 和 WebDAV，修正状态 |

## 工作流程

```
逐个处理专辑:
  ↓
下载 → 获取目录列表检查 → [已存在且大小匹配] → 跳过上传
                              ↓ [不存在]
                         上传 → 获取目录列表验证 → [成功] → 清理本地 → downloaded=false
```

## 自检程序 (sc_verify.py)

独立程序，扫描 WebDAV 目录和数据库，自动修正状态：
- 远程存在但 `uploaded=false` → 修正为 `true`
- 远程不存在但 `uploaded=true` → 修正为 `false`
- `downloaded` 始终修正为 `false`（本地不保留文件）

```powershell
# 测试 WebDAV 连接
python sc_verify.py --test

# 预览修正内容
python sc_verify.py --dry-run

# 执行修正
python sc_verify.py

# 只扫描 WebDAV 目录
python sc_verify.py --scan-only
```

或使用 sc_sync.py 内置的验证功能：
```powershell
python sc_sync.py --verify --dry-run
python sc_sync.py --verify
```

## 数据库管理 (sc_manager.py)

```powershell
# 首次运行，扫描所有系列
python sc_manager.py

# 增量更新 (只扫描未完结系列)
python sc_manager.py

# 强制重新扫描所有
python sc_manager.py --force
```

## 依赖

- Python 3.8+
- gdown (Google Drive 下载)
- webdavclient3 (WebDAV 上传)
- PyYAML (配置解析)
