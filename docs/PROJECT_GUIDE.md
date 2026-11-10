# 项目结构与使用指南

本指南对应 VERSION.json 标记的 2026-11-10 快照。内容以仓库源码、配置模板和脚本为依据；外部网站、账号权限、地区资格、RoxyBrowser 版本兼容性和服务端行为不会因源码存在而自动得到保证。

## 1. 项目用途

Dango Local 是一个在 Windows 本机运行的 FastAPI + Vue WebUI，提供邮箱池、注册任务、运行记录、代理、RoxyBrowser 接入和若干账号管理工作流。它会把运行数据保存在本机 SQLite 数据库，并可连接用户自行配置的邮箱、代理、短信、RoxyBrowser 及外部服务。

公开版是重新安装软件框架的快照，不是旧电脑数据迁移包。它不包含运行数据库、账号或令牌、实际服务凭据、RoxyBrowser 软件和资料，也不包含换绑所需的外部核心仓库。

## 2. 快速启动

### 环境要求

| 用途 | 要求 |
|---|---|
| 基础 WebUI | Windows 10/11、Python 3.11.x；首次安装需要网络访问 Python 包源 |
| 注册、提炼 | 需要可执行的 Node.js；仓库没有固定或验证过的 Node.js 版本 |
| 支付资格检测 | Node.js，以及 qualification 目录锁定的 jsdom npm 依赖；安装脚本不会自动安装这组依赖 |
| 重建前端 | Node.js/npm；正常启动使用仓库内已构建的 webui/static，不需要重建 |
| Roxy 工作流 | 另行安装并运行 RoxyBrowser，且在本机完成 API、工作区和项目配置 |
| 换绑工作流 | 另行取得包含 rebind_core/pipeline.py 的换绑核心并配置路径；该核心不在本仓库内 |

Node 版本没有统一的项目级声明。使用资格检测时，应结合当前 qualification/package-lock.json 的引擎要求和目标机器实测确认兼容版本。

### 启动方式

1. 解压发布 ZIP。
2. 双击 start.cmd；或在 PowerShell 中运行 `.\start_public.ps1 -OpenBrowser`。
3. 首次启动时，若不存在 .venv，start_public.ps1 会调用 setup_windows.ps1。安装脚本查找 Python 3.11，创建虚拟环境、升级 pip、安装 requirements.lock.txt，并在缺少时复制 roxy.settings.example.json 为本机 roxy.settings.json。
4. 服务默认绑定 127.0.0.1:8765，浏览器打开 http://127.0.0.1:8765/。页面使用 hash 路由，例如 /#/proxy。

常用启动参数：

| 入口 | 参数 | 含义 |
|---|---|---|
| start_public.ps1 | -Port 8765 | 设置本地服务端口，默认 8765 |
| start_public.ps1 | -OpenBrowser | 启动后打开浏览器；start.cmd 默认会传入此参数 |
| start_webui.py | --host、--port | 底层监听地址和端口 |
| start_webui.py | --no-browser | 不自动打开浏览器 |
| start_webui.py | --reload | 开发模式代码重载 |

start_webui.py 可以绑定非回环地址，但源码未发现保护整个应用的登录认证层。除非先另行设置可信的访问控制，不要用 --host 0.0.0.0 对局域网或公网开放。

### 可选开机启动

安装依赖后，可运行 install_task_public.ps1 创建 Windows 当前用户登录时启动的计划任务。脚本默认延迟 10 秒，使用受限权限、回环地址和端口 8765，并设置有限次数的失败重启。它只启动 WebUI，不会自行开始注册或其他业务任务。仓库未提供对应的任务卸载脚本；移除前应在 Windows 任务计划程序中检查 DangoLocal-Public-WebUI。

仓库里还保留 install_local_task.ps1、run_webui.ps1、launch_webui.vbs 和 run_hidden.vbs。这些是旧的或兼容入口；普通安装建议使用 start.cmd 和 start_public.ps1。run_webui.ps1 会读取本地 roxy.local.json 并写入当前进程环境变量，标准 start_public.ps1 不读取这个文件。

## 3. 用户界面功能

导航页面在 webui/frontend/src/router/index.js 定义。前端源码位于 webui/frontend/src，已构建资源位于 webui/static。

| 页面路由 | 页面 | 主要用途与边界 |
|---|---|---|
| /#/ | 仪表盘 | 查看本地统计与服务状态；/api/ready 只检查应用可响应，/api/health 还会查询 Roxy 状态和出口容量 |
| /#/import | 导入邮箱 | 按 provider 支持的格式导入邮箱池 |
| /#/register | 单次注册 | 发起一个注册任务；会连接外部认证、邮箱、短信或代理服务 |
| /#/auto | 全自动批量 | 配置和控制注册循环；用户需先完成邮箱和代理等配置 |
| /#/proxy | 代理池 | 手动导入/测试代理、配置固定代理组、711 动态 Session、资格检测并发和 ASN 筛选；可同步已保存代理到本机 Roxy。设置在浏览器 localStorage，代理 URL 可能含凭据；同步可能把凭据交给 Roxy |
| /#/pool | 邮箱列表 | 查看和管理本地邮箱池；其中的邮箱访问凭据属于敏感信息 |
| /#/registered | 注册结果 | 除查看外，还可取 Refresh Token、重新授权、确认候选密码、检查账号/Plus 状态、更新凭据、冻结/解冻、导出、重试失败步骤和删除账号。外部检查/授权会访问服务；删除操作会移除本地记录，执行前核对选择 |
| /#/password-reset | 密码重置 | 对选定账号发起密码恢复；会访问外部认证和邮箱服务 |
| /#/momo-check | 支付资格检测 | 使用 /api/qualification 运行检测任务；需要 Node.js 与单独安装的 jsdom；服务端会把 Access Token 和代理 URL 发给 int31.space |
| /#/rebind-pool | 换绑邮箱池 | 管理换绑邮箱；实际执行依赖仓库外的换绑核心 |
| /#/rebind-results | 换绑结果 | 查看换绑任务结果；页面可载入，但干净安装不能独立执行换绑 |
| /#/runs | 运行记录 | 查看任务状态、日志和历史结果 |
| /#/settings/roxy | RoxyBrowser 配置 | 设置本机 Roxy API 和行为偏好；RoxyBrowser 软件未包含在公开包内 |
| /#/settings/mail | 邮箱配置 | 配置邮箱 provider；密钥和服务账号应只保存在本机数据库 |
| /#/settings/sms | 接码配置 | 配置短信 provider、API key、国家/服务、号码复用和超时 |
| /#/settings/export | 自动导出 | 配置导出目标 URL、API key、分组 ID 和超时 |
| /#/settings/refine | 提炼 | 加载 third_party/upi-zero-link 固定源码；需要 Node.js 和外部账号授权，可能访问 OpenAI/Stripe 并产生支付或授权相关状态变化 |

“支付资格检测”与“提炼”是不同流程。资格检测模块用于检查和归类能力，不应被描述为创建支付结果；提炼则可能执行外部结账及 UPI 委托链路。资格检测客户端会向 `https://int31.space/public/api/checkout-capabilities` 提交 `accessToken` 和 `proxyUrl`，再轮询该服务的任务结果；仓库没有说明或验证该服务的数据留存、访问控制和隐私政策。只有在确认服务条款、数据处理方式且账号授权充分后再使用。资格检测界面说明不会确认支付。提炼流程的外部账号资格和实际结果没有在本指南编写过程中验证。third_party/upi-zero-link/README.md 是随附第三方项目自己的说明，其操作性和效果主张不代表 Dango 的独立验证。

webui/momo_api.py 定义了 /api/momo 路由，但当前主应用 webui/app.py 没有 include 该 router。当前 /momo-check 页面调用的是 /api/qualification，不要把遗留的 MoMo router 当作已挂载 API。

## 4. 源码结构

| 路径 | 内容 |
|---|---|
| auth_flow.py、sentinel.py、sentinel_quickjs.py、openai_sentinel_quickjs.js | 协议认证流程与 Sentinel 辅助逻辑；使用注册流程时需要 Node 可执行文件 |
| fingerprint.py、http_client.py、password_verification.py | 请求/指纹、HTTP 客户端和密码验证相关模块 |
| config.py | 低层注册/重新授权代理解析；依次采用显式代理、Windows 当前用户系统代理和代理环境变量 |
| register_outlook.py、mail_outlook.py、mail_cf.py、sms_provider.py | 较低层的 CLI/邮箱/短信接入模块；WebUI 邮箱 provider 注册表在 mail_providers/ |
| safe_diagnostics.py | 限定并清理日志、SSE 和持久化错误中的诊断信息 |
| standalone_core/momo_extract.py | 旧版 MoMo 检测器使用的 checkout 适配器；当前 /momo-check 页面走 qualification 服务，不调用此适配器 |
| check_roxy_import.py | 本地 Roxy helper 的只读导入预检脚本；需要本机 roxy.local.json，不属于标准启动步骤 |
| mail_providers/ | Outlook、iCloud Relay、Cloudflare 临时邮箱等 provider、导入格式和配置字段 |
| webui/app.py | FastAPI 主入口，挂载 API routers，提供静态页面和任务接口 |
| webui/db.py | SQLite 数据库路径、schema 初始化、邮箱池和结果存储 |
| webui/registrar.py、webui/auto_loop.py | 注册任务编排、自动循环和运行状态 |
| webui/roxy_*.py、webui/roxy_worker.py | Roxy 配置、连接状态、代理同步、浏览器任务桥接 |
| webui/refine_*.py | 提炼 API、输入校验、任务服务、账本保护和对第三方 protocol 的受控加载 |
| webui/qualification_*.py、webui/proxy_screening*.py、webui/asn_performance.py | 资格检测、代理筛查及其状态/性能数据 |
| webui/rebind_*.py | 邮箱换绑编排与 API；核心执行依赖外部 rebind_core |
| webui/frontend/ | Vue 前端源码、路由、package manifest 与测试 |
| webui/static/ | 随发布包提供的构建后页面、脚本和样式 |
| roxy-helper/ | 随包提供的 Roxy 注册/浏览器适配 Python 源码；不等于 RoxyBrowser 应用本体 |
| qualification/ | 资格检测 Python/Node Sentinel 运行代码及 jsdom 锁文件 |
| third_party/upi-zero-link/ | 集成于提炼功能的上游源码，也保留独立 CLI、自己的 README、测试和 MIT License |
| config-templates/ | Roxy 本机配置示例；模板中没有用户真实密钥 |
| setup_windows.ps1、start_public.ps1、start.cmd | 推荐安装和启动入口 |
| install_task_public.ps1 | 可选 Windows 登录启动任务 |
| VERSION.json、PUBLIC_MANIFEST.json、PUBLIC_MANIFEST.sha256 | 发布快照元数据与文件完整性清单 |
| SECURITY.md、NOTICE.md | 安全提示及第三方许可边界 |

## 5. 运行流程与数据

### 启动流程

start.cmd 调用 start_public.ps1 -OpenBrowser。PowerShell 启动脚本检查 .venv；不存在时运行 setup_windows.ps1 安装依赖，然后以固定回环地址启动 start_webui.py。Python 入口运行 webui.app:app，FastAPI 提供 webui/static/index.html 和静态文件。

应用导入/启动时会初始化 SQLite 状态，并对上次进程遗留的运行任务做恢复标记，例如释放超时占用的邮箱、将部分遗留中的注册/换绑任务标为取消、记录中断的资格检测任务。该行为不是业务任务自动重放。

### 健康检查

| URL | 行为 |
|---|---|
| GET /api/ready | 轻量本地可用性检查，返回 {"ok": true}；不表示邮箱、Node、Roxy 或外部服务已经可用 |
| GET /api/health | 返回统计并检查 Roxy profile/出口容量；可能访问本机 Roxy API 或检测出口，不是纯本地探针 |

### 数据存储

- 默认主数据库为 webui/webui.db；设置 GPT_OUTLOOK_WEBUI_DB_PATH 可改变基础路径。
- 应用支持本地工作区 1 和 2。工作区 1 使用基础数据库，工作区 2 使用同目录的 -account-2 文件名。
- SQLite 使用 WAL 模式。停服务备份时应把数据库及同名 -wal、-shm 文件作为一个整体检查；仓库没有统一的数据库备份/恢复脚本。
- 数据库 schema 含邮箱池凭据、账号密码、Access/Session/Refresh Token、Cookie、TOTP secret、服务设置和任务结果等文本字段。不要假设主数据库已由应用加密；把数据库、WAL/SHM、运行日志和导出文件视为敏感数据。
- 浏览器状态保存在当前浏览器 profile 对该站点的 `localStorage`，不在 SQLite 中：工作区选择、主题、注册表单偏好、注册代理池、固定代理/ASN 配置、资格检测代理模板与并发、换绑代理与并发、密码重置恢复标记、资格检测任务 ID 和最近换绑任务 ID。代理 URL 可能含用户名和密码。提炼的待恢复 request ID 保存在 `sessionStorage`，不是账号凭据。
- 浏览器存储与数据库是两份独立数据；数据库备份不会带上这些设置，公开 ZIP 也不包含浏览器 profile。清理浏览器站点数据会移除上述本地设置和恢复标记。
- 提炼账本放在 webui/refine-state/；本地密钥使用 Windows DPAPI 保护，不能据此保证跨用户或跨 Windows 安装迁移可恢复。
- 新安装包会生成空数据库，不会自动导入其他机器的数据。

## 6. 配置参考

### WebUI 页面配置

邮箱、短信和自动导出设置主要通过 WebUI 保存到本地 SQLite。工作区选择、表单偏好和代理相关配置则保存在当前浏览器的 `localStorage`；完整数据边界见第 5 节：

| 页面 | 配置范围 |
|---|---|
| 邮箱配置 | provider 及其动态 config_fields；当前 provider 定义在 mail_providers/outlook.py、icloud_relay.py、cf_temp.py |
| 接码配置 | provider、API key、国家/服务、价格/库存限制、号码复用与超时等 |
| 自动导出 | 目标 URL、API key、分组 ID、超时等 |

服务商字段会随实现变化，当前源码/API 返回的 provider 字段定义是准确来源。读回部分敏感配置时 API 会遮蔽秘密值；遮蔽不代表数据库里没有保存该秘密。

代理池页支持手动代理导入/测试、固定代理组、资格检测代理模式（手动池或 711 动态 Session）、检测并发和 ASN 筛选。它还可把已保存代理同步到本机 Roxy；同步会把代理账号/密码交给 Roxy，Roxy 可能按自身设置同步到其账号云端。同步成功只证明 Roxy 保存结果已核对，不代表代理网络可用。

### RoxyBrowser 设置

setup_windows.ps1 仅在目标文件不存在时从 config-templates/roxy.settings.example.json 创建 roxy.settings.json。字段和发布模板默认值如下：

| 字段 | 模板值 | 用途/限制 |
|---|---|---|
| api_base | http://127.0.0.1:50000 | Roxy 本机 HTTP API；只接受 loopback 地址 |
| workspace_id、project_id | "1"、"1" | Roxy 工作区和项目正整数 ID |
| profile_id | 空字符串 | 固定 profile ID；一账号一环境开启时必须留空 |
| workspace_path、open_path、close_path、delete_path | /browser/workspace、/browser/open、/browser/close、/browser/delete | API 路径，只允许本机绝对路径格式 |
| max_windows | 2 | 同时窗口数，范围 1–5 |
| headless、keep_browser_open | false、false | 无头模式与任务后保留窗口 |
| one_profile_per_account、delete_after_run | true、false | 每账号独立 profile；任务后的删除行为 |
| random_os、os_choices | false、"Windows,macOS" | 创建 profile 时可选的系统类型 |
| random_fingerprint | false | 是否请求 Roxy 随机指纹 |
| native_fingerprint_only | true | 当前 worker 的固定支持要求，不能设为 false |
| follow_proxy_ip | false | 是否按出口 IP 派生语言、时区和位置 |
| random_name、name_prefix | false、"rb" | profile 命名选项 |
| use_proxy_pool | false | 是否使用 Roxy 内置代理池 |
| proxy_check_channel | "IPRust.io" | 代理检测渠道 |
| codex_callback_timeout | 180 | 回调超时秒数，范围 10–600 |
| otp_timeout、require_2fa | 180、true | 当前注册约束：180 秒及必须 2FA，不可更改 |

配置校验还要求 workspace/project ID 是正整数文本、路径符合本地绝对路径格式，且 one_profile_per_account=true 时 profile_id 为空。模板值和 Pydantic 模型默认值个别不同；新安装实际复制的是上述模板。

### Roxy 本机路径配置

config-templates/roxy.local.example.json 示范以下本机变量：

| 字段 | 含义 |
|---|---|
| ROXY_API_BASE | Roxy 本地 API 地址 |
| ROXY_WORKSPACE_ID、ROXY_PROJECT_ID | Roxy 工作区和项目 ID |
| REPO0810_ROXY_LEGACY_ROOT | 随包 roxy-helper 代码目录 |
| REPO0810_ROXY_PYTHON | Roxy helper 使用的 Python 可执行文件 |

注意：run_webui.ps1 会读取本机 roxy.local.json；标准公开启动链 start.cmd → start_public.ps1 不读取该文件。标准链会尝试从当前 Windows 用户环境继承相关 Roxy 环境变量。复制模板本身不等于 Roxy 已连接。

### 常用环境变量

| 变量 | 用途 | 备注 |
|---|---|---|
| GPT_OUTLOOK_WEBUI_DB_PATH | 覆盖基础 SQLite 路径 | 需妥善保护目标文件及 WAL/SHM |
| REPO0810_ROXY_SETTINGS_PATH | 指定 Roxy 偏好 JSON 路径 | 默认为项目根目录下 roxy.settings.json |
| ROXY_API_BASE、ROXY_WORKSPACE_ID、ROXY_PROJECT_ID | Roxy 本地 API/工作区/项目 | API 地址仅允许 loopback HTTP |
| REPO0810_ROXY_LEGACY_ROOT、REPO0810_ROXY_PYTHON | Roxy helper 路径和 Python | 与 roxy.local.json 示例字段对应 |
| REPO0810_ROXY_MAX_WINDOWS | Roxy 最大窗口覆盖值 | 仅高级运行时覆盖项 |
| OPENAI_SENTINEL_NODE_PATH | 指定注册 Sentinel 使用的 Node 可执行文件 | 默认查找命令 node |
| REBIND_STANDALONE_ROOT | 指向换绑核心根目录 | 必须含 rebind_core/pipeline.py；该仓库未随包提供 |
| REBIND_LEGACY_DB_ARCHIVE | 指定旧数据库归档读取位置 | 可选，不是换绑核心 |
| MOMO_CHECKOUT_SOURCE_ROOT | 覆盖旧 MoMo checker 使用的本机源码目录 | 只影响 webui/momo_api.py 的未挂载路由；不影响当前 /momo-check 页面 |

认证、代理、短信、调试追踪和个别 provider 还读取其他模块级环境变量。它们不是一个集中、稳定的公共配置清单；请从对应模块查证，不要把内部测试/诊断变量当成普通用户选项。不要把真实密钥写入公开仓库、命令历史或 Issue。

## 7. 依赖与构建

| 场景 | 权威文件 | 安装/构建方式 |
|---|---|---|
| WebUI Python 运行依赖 | requirements.lock.txt | setup_windows.ps1 创建 venv 并按此文件安装 |
| 未锁定的 Python 依赖约束 | requirements.txt | 当前公开启动脚本不使用它作为锁文件 |
| 前端源码 | webui/frontend/package.json、package-lock.json | 仅重建时在 webui/frontend 执行 npm ci、npm run build；也可运行 setup_windows.ps1 -BuildFrontend |
| 资格检测 Sentinel | qualification/package.json、package-lock.json | 除 Node.js 外，首次使用前需在 qualification 目录执行 npm ci 安装 jsdom |
| 提炼集成 | third_party/upi-zero-link/pyproject.toml、requirements.txt、源码与 LICENSE | 上游项目声明 Python ≥3.10、curl_cffi、requests；通过 WebUI adapter 调用时也不要把其独立 CLI 安装和主 WebUI 安装混为一谈 |
| Roxy 驱动 | 根 requirements.lock.txt、roxy-helper/requirements.txt | 还需要外部 RoxyBrowser 客户端及正确的本机 API 配置；若 helper 使用单独的 REPO0810_ROXY_PYTHON，应检查该解释器是否安装 helper 依赖 |

Python 运行版本由安装脚本限定为 3.11.x。requirements.lock.txt 固定了包版本，但没有逐包哈希；安装脚本会先升级 pip，而 pip 版本本身未固定，因此它不是完全可重放的供应链锁。前端与资格检测的 npm 锁文件也分别管理，根安装脚本不会为资格检测执行 npm ci。

主 Python 环境的主要运行库包括 FastAPI、Uvicorn、Pydantic、requests、curl_cffi、Selenium、pyotp 和 PyYAML；完整直接及传递依赖版本以 requirements.lock.txt 为准。前端使用 Vue 3、Vue Router、Pinia、Element Plus、Axios 和 Vite，完整版本解析以 package-lock.json 为准。资格检测单独使用 Node.js/jsdom；注册 Sentinel 使用 Node 可执行文件，不代表注册和资格检测共用同一套 Node 依赖。

前端已构建资源随仓库提供。不要为了普通启动运行前端构建，也不要把 webui/frontend 的开发服务器误当成后端 API 服务。

## 8. 外部请求、权限与隐私

- 源码含注册、邮箱验证码、短信、账号恢复/换绑、资格检测、代理探测、自动导出及提炼工作流。这些操作会请求外部系统；公开安装和本地 readiness 检查不证明真实账号工作流已验证。
- 资格检测会把 Access Token 和代理 URL 从本地服务端发送到 `int31.space`；仓库未确认该第三方的留存或隐私处理方式。先核对服务方条款，并只使用本人拥有或明确获准检查的账号。
- 提炼会读取本地账号凭据并经第三方 protocol 访问外部结账服务，可能改变外部账户或支付流程状态。仅对本人拥有或明确授权的账号操作；提交前核对服务条款、价格/授权范围和结果。不要仅凭返回 URL 就认定支付链路安全或有效。
- 核心 SQLite schema 有令牌、密码、Cookie 和 2FA 字段。请限制本机访问，定期用可信的加密介质做备份；不要上传数据库、日志或 profile。
- 未发现全局 WebUI 登录认证层；启动时保持默认 loopback 绑定。不要在未配置独立认证/访问控制时暴露端口。
- /api/ready 可作本机启动探针；调用 /api/health 可能触发 Roxy API/出口容量检查。
- RoxyBrowser 与邮箱、短信、代理和导出目标均是外部依赖。配置错误、配额、地区策略和上游接口变化都可能令具体任务失败。

## 9. 测试、核验与已知缺口

### 仓库内测试入口

- webui/frontend/tests/ 有多个前端测试文件；webui/frontend/package.json 当前只定义 npm run test:momo，该命令运行其中 4 个指定测试。
- third_party/upi-zero-link/tests/test_offline.py 是第三方目录内的一项测试。
- 仓库没有根级统一测试命令，也未发现根级后端测试套件或 CI workflow。不要把单项前端测试当作全仓库验证。
- 对本机依赖的 Node、RoxyBrowser、邮箱、短信、代理、OpenAI、Stripe 和换绑核心，需要另做相应集成测试。本指南编写时没有执行这些外网或真实账号操作。

### 已确认的限制

1. 换绑 UI 和 API 在，但换绑核心 rebind_core/pipeline.py 不在公开包。要运行换绑，必须取得可信外部核心并设置 REBIND_STANDALONE_ROOT。
2. webui/momo_api.py 的 /api/momo router 未由当前主应用挂载；现有 /momo-check 页面走 /api/qualification。
3. roxy.local.json 仅由旧兼容入口 run_webui.ps1 读取；标准 start_public.ps1 不读取它。
4. 没有根目录统一 LICENSE；third_party/upi-zero-link/LICENSE 只覆盖其适用的第三方项目。根目录其他源码的授权方式无法从当前仓库确认。NOTICE.md 要求使用者自行核对上游许可。
5. 仓库没有随附数据库迁移/恢复手册、自动更新器或计划任务卸载脚本。

## 10. 主要维护入口

| 变更类型 | 优先检查 |
|---|---|
| 页面、路由和前端请求 | webui/frontend/src/router/index.js、src/views/、src/api/ |
| 后端主 API 和启动逻辑 | webui/app.py |
| 邮箱 provider 或导入格式 | mail_providers/ 与 webui/app.py 的邮件配置 API |
| 注册流程 | webui/registrar.py、auth_flow.py、sentinel.py |
| 本地数据 schema/迁移 | webui/db.py |
| Roxy 设置/运行 | webui/roxy_settings.py、roxy_config.py、roxy_bridge.py、roxy_worker.py |
| 资格检测 | webui/qualification_api.py、qualification/ |
| 提炼集成 | webui/refine_api.py、refine_service.py、refine_upstream.py、third_party/upi-zero-link/ |
| 换绑 | webui/rebind_service.py、rebind_mail_provider.py，以及仓库外的换绑核心 |
| 发布文件与完整性 | VERSION.json、PUBLIC_MANIFEST.json、PUBLIC_MANIFEST.sha256、NOTICE.md |

文档或源码变更后，先确认引用路径仍存在，再按受影响模块运行专项检查。任何没有在当前环境实际执行的检查或外部流程都应标为未验证。
