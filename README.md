# SHINY COLORS 下载同步工具

从 Google Drive 下载 SHINY COLORS Hi-Res 音频文件并同步到 OpenList (WebDAV)。

## 文件说明

| 文件 | 说明 |
|------|------|
| `sc_manager.py` | 数据库管理器，扫描系列页面并维护 JSON 数据库 |
| `sc_sync.py` | 下载同步程序，从 Google Drive 下载并上传到 WebDAV |
| `config.yaml.example` | 配置文件示例 |

## 安装

```bash
# 克隆仓库
git clone https://github.com/YOUR_USERNAME/shiny-colors-sync.git
cd shiny-colors-sync

# 安装依赖
pip install -r requirements.txt

# 创建配置文件
cp config.yaml.example config.yaml
# 编辑 config.yaml 填入 WebDAV 配置
```

## 使用

### 数据库管理 (sc_manager.py)

```bash
# 首次运行，扫描所有系列
python sc_manager.py

# 增量更新 (只扫描未完结系列)
python sc_manager.py

# 强制重新扫描所有
python sc_manager.py --force
```

### 下载同步 (sc_sync.py)

```bash
# 预览模式
python sc_sync.py --dry-run

# 正式同步
python sc_sync.py

# 强制重新下载
python sc_sync.py --force

# 只同步指定系列
python sc_sync.py --series "Song for Prism"

# 测试 WebDAV 连接
python sc_sync.py --test
```

## Systemd 定时任务

```bash
# 安装服务
sudo cp sc-sync.service sc-sync.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable sc-sync.timer
sudo systemctl start sc-sync.timer
```

## 依赖

- Python 3.8+
- gdown (Google Drive 下载)
- webdavclient3 (WebDAV 上传)
- PyYAML (配置解析)
