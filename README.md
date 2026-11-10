# Dango Local Standalone

**这是一个在 Windows 本机运行的 ChatGPT/OpenAI 账号注册与管理工具。**它把邮箱池、单次注册、批量注册、代理管理、RoxyBrowser 接入和注册后账号操作放在一个本地 WebUI 中。它是第三方独立项目，不是邮箱、短信、代理或 RoxyBrowser 服务本身。

## 注册机包含什么

注册流程由本地 Vue 页面、FastAPI 后端和 Python 注册编排模块组成。使用者在页面选择邮箱来源、注册方式和网络出口后启动任务；后端协调认证流程、邮箱验证码及可选短信或 RoxyBrowser 步骤，并把运行状态、日志和结果显示在页面中。任务结果和账号资料存入本机 SQLite。

它提供单次注册和自动批量循环两种入口。注册可走协议驱动，也可接入本机 RoxyBrowser。邮箱、短信、网络代理和 RoxyBrowser 都由使用者自行配置；公开仓库不附带可直接使用的邮箱账号、接码额度、代理账号或浏览器资料。

## 页面与功能

页面采用 hash 路由，例如 `http://127.0.0.1:8765/#/register`。

| 页面 | 功能 |
|---|---|
| `/#/` | 仪表盘：本机统计与服务状态 |
| `/#/import` | 导入邮箱账户 |
| `/#/register` | 启动单次注册、查看实时日志和任务结果 |
| `/#/auto` | 配置、启动、暂停、恢复或停止自动批量注册 |
| `/#/proxy` | 导入和测试代理；管理普通/固定代理池、711 动态 Session、资格检测代理设置与 ASN 策略；可同步代理到本机 Roxy |
| `/#/pool` | 查看和管理邮箱池 |
| `/#/registered` | 管理注册结果：查看账号、获取 Refresh Token、重新授权、检查账号/Plus 状态、更新凭据、冻结/解冻、导出、重试失败步骤及删除本地记录 |
| `/#/password-reset` | 对选定账号发起密码重置 |
| `/#/momo-check` | 支付方式/资格检测任务、地区与代理设置、批次结果及失败重试 |
| `/#/rebind-pool` | 管理邮箱换绑池 |
| `/#/rebind-results` | 查看换绑任务和结果 |
| `/#/runs` | 查看任务历史、运行状态与日志 |
| `/#/settings/roxy` | 配置本机 RoxyBrowser API 和浏览器任务偏好 |
| `/#/settings/mail` | 配置邮箱 provider |
| `/#/settings/sms` | 配置短信/接码 provider |
| `/#/settings/export` | 配置将结果导出到外部系统 |
| `/#/settings/refine` | 提炼工作台：集成第三方 `upi-zero-link` 项目 |

**注册后管理**不只显示结果，还包含授权续接、密码处理、资格检查、冻结、导出、失败重试和删除等操作。它们可能访问外部认证、邮箱或导出服务；删除会影响本地记录，提交前应核对所选账号。

## 主要代码模块

| 路径 | 作用 |
|---|---|
| `webui/frontend/` | Vue 3 页面、路由、状态管理和前端测试 |
| `webui/static/` | 随仓库提供的生产构建页面；普通启动无需构建前端 |
| `webui/app.py` | FastAPI 应用入口、主要 API、任务管理和静态页面服务 |
| `webui/registrar.py`、`webui/auto_loop.py` | 单次注册编排和自动批量循环 |
| `auth_flow.py`、`sentinel.py`、`sentinel_quickjs.py` | 注册认证与 Sentinel 相关流程实现 |
| `mail_providers/`、`sms_provider.py` | Outlook、iCloud Relay、Cloudflare 临时邮箱适配，邮箱导入和短信/接码服务接入 |
| `webui/db.py` | SQLite schema、邮箱池、账号结果和设置存取 |
| `webui/roxy_*.py`、`roxy-helper/` | RoxyBrowser API 桥接、配置、代理同步和浏览器任务适配；不包含 RoxyBrowser 软件 |
| `webui/qualification_*.py`、`qualification/` | 支付资格检测 API、任务状态、代理策略和 Node Sentinel 依赖 |
| `webui/refine_*.py`、`third_party/upi-zero-link/` | 提炼工作台及随仓库带入的第三方上游代码 |
| `webui/rebind_*.py` | 邮箱换绑页面/API 和任务编排；执行核心不在本仓库 |
| `config-templates/`、`setup_windows.ps1`、`start_public.ps1`、`start.cmd` | 示例配置、Windows 安装和启动入口 |

## 运行流程

1. 在 Windows 10/11 安装 Python 3.11.x，下载并解压 [最新 Release](https://github.com/a865948732-jpg/dango-local-standalone/releases/latest)。
2. 双击 `start.cmd`。首次启动会创建 `.venv`，并按 `requirements.lock.txt` 安装 Python 依赖；安装时需要连接 Python 包源。
3. `start_public.ps1` 启动 `start_webui.py`，FastAPI 默认只监听 `127.0.0.1:8765`，Vue 页面从 `webui/static/` 提供。
4. 通过页面配置邮箱、短信、代理及可选 Roxy 服务，再启动所需的注册或账号管理任务。

基础 WebUI 启动不要求 Node.js 或 RoxyBrowser。注册流程需要 Node.js；支付资格检测另需在 `qualification/` 目录安装锁定的 `jsdom` 依赖；重建前端需要 Node.js/npm。RoxyBrowser 相关功能需要另行安装并运行 RoxyBrowser。各组件的版本和安装细节见[项目指南](docs/PROJECT_GUIDE.md)。

## 外部服务与数据

- 注册、邮箱验证码、短信、代理检测、账号授权、密码重置和自动导出会连接相应的外部服务。该项目不保证这些服务的可用性、地区资格或账号结果。
- 支付资格检测会将 Access Token 和代理 URL 从本地后端发送到 `https://int31.space/public/api/checkout-capabilities`。仓库没有验证该服务的数据留存、访问控制或隐私政策；使用前应自行核对服务条款，并只检查本人拥有或明确获准操作的账号。该检测页面说明它不会确认支付。
- “提炼”集成第三方 `upi-zero-link`，可能访问 OpenAI/Stripe 结账服务并改变外部结账或授权状态。它不是普通的本地查询功能；账号授权、服务条款和外部操作结果需要自行核实。
- 公开包是干净安装快照，不包含旧数据库及 WAL/SHM、账号和真实凭据、`.env`、提炼账本、运行日志、缓存或 RoxyBrowser profile。首次启动会在本机创建新数据库；它不是旧电脑数据恢复包。
- SQLite 可能保存邮箱访问凭据、账号密码、Access/Session/Refresh Token、Cookie、TOTP secret、设置和任务结果。不要假设数据库已加密。
- 浏览器 `localStorage` 还保存工作区选择、主题、注册表单偏好、注册与资格检测代理/ASN 设置、换绑代理与并发、密码重置标记及资格检测/换绑任务 ID；提炼待恢复 request ID 使用 `sessionStorage`。这些不在 SQLite 备份中；代理 URL 可能含用户名和密码。
- WebUI 没有覆盖全站的登录认证层。请保持默认回环地址，不要在没有独立访问控制时向局域网或公网开放。

## 已知限制

- 换绑界面和 API 在仓库内，但实际执行要求外部提供 `rebind_core/pipeline.py`，公开包不含该核心。
- 页面 `/momo-check` 使用 `/api/qualification`。旧 `webui/momo_api.py` 的 `/api/momo` router 当前未挂载，不能据此认为旧接口可用。
- 根目录没有统一的 `LICENSE`。第三方目录按各自上游许可证使用；公开可下载不代表所有根目录代码都采用同一许可证，详见 [NOTICE.md](NOTICE.md)。
- 仓库没有根级统一测试命令；单项测试或本地 readiness 检查不能证明邮箱、注册、Roxy、支付资格或提炼的外部流程已验证。

## 文件与完整说明

- [项目结构、配置、依赖和维护指南](docs/PROJECT_GUIDE.md)
- [安全说明](SECURITY.md)
- [第三方代码和许可证说明](NOTICE.md)
- [公开文件清单](PUBLIC_MANIFEST.json)及其[SHA-256 校验值](PUBLIC_MANIFEST.sha256)
