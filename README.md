# Dango Local Standalone

这是 Dango Local WebUI 的公开、可重新安装版本。下载 ZIP 解压后，在 Windows PowerShell 里运行一次安装脚本，再启动本地页面。

## 快速开始

```powershell
Set-Location D:\Dango-local-standalone
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\setup_windows.ps1
.\start_public.ps1 -OpenBrowser
```

也可以双击 `start.cmd`。页面地址是 `http://127.0.0.1:8765/`。

`start_public.ps1` 会在缺少 `.venv` 时自动调用安装脚本；首次安装需要联网下载 Python 依赖。

## 需要的程序

- Windows 10/11
- Python 3.11.x，并能通过 `py -3.11` 或 `python` 调用
- 首次安装时可访问 Python 包源
- RoxyBrowser 只在使用 Roxy 相关功能时需要；它不包含在公开仓库中
- Node.js/npm 不是启动必需项。只有执行 `setup_windows.ps1 -BuildFrontend` 重建前端时才需要

## 公开版的边界

仓库是全新的运行环境，不包含旧电脑上的账号和运行数据。以下内容明确不发布：

- SQLite 数据库、WAL/SHM、密码、Access/Refresh/Session Token、Cookie、2FA 密钥
- `.env`、DPAPI 提链密钥、提链账本、运行日志和缓存
- RoxyBrowser 安装目录及用户 profile

首次启动会在本机生成新的数据库。要接入 Roxy，请复制 `config-templates\roxy.local.example.json` 和 `config-templates\roxy.settings.example.json`，按你自己的 Roxy 安装填写，然后只把真实配置留在本机。

## 可选的开机启动

安装完成后，如需当前 Windows 用户登录时自动启动，可运行：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\install_task_public.ps1
```

脚本只创建本机计划任务 `DangoLocal-Public-WebUI`，不会注册账号、发送验证码或执行批量业务。

## 说明

- `webui\static` 已随仓库提供，因此不构建前端也能启动。
- `requirements.lock.txt` 固定了本次打包时的 Python 依赖版本；新系统仍需重新创建虚拟环境。
- `PUBLIC_MANIFEST.json` 和 `PUBLIC_MANIFEST.sha256` 用于核对下载内容。
- 该公开仓库适合重新安装软件框架，不是旧电脑的完整数据恢复包。
