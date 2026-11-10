# upi-zero-link

印度 **₹0 UPI Autopay 委托链**提取器 —— 纯协议实现，不用浏览器。

给它一个 ChatGPT 账号的 `access_token` 和一条印度出口代理，它会把 OpenAI / Stripe
的结账流程走完，产出**可直接交付的 UPI 委托链接 + 二维码**，并在交付前做一次核验，
确保发出去的不是「Stripe 拒绝时同样会返回」的废链。

```
$ upi-zero-link --token eyJhbGciOi... --email you@example.com --proxy socks5h://user:pass@in-host:port
12:03:41 you@example.com 第 1/4 轮（出口 in-host:port）
12:03:41 stage checkout
12:03:44 stage stripe_init
12:03:47 stage tax_update
12:03:48   acc=you@example.com due=0 pmc=always
12:03:48 stage payment_method
12:03:50 stage stripe_confirm
12:03:53 stage approve
12:03:55 stage instructions
12:03:56   link 核验通过 state=requires_action fam=1.00

###### ★ ₹0 UPI link (verified) ######
account : you@example.com
url     : https://payments.stripe.com/upi/instructions/CDQQARoX...
qr      : https://qr.stripe.com/live_....png
due     : 0   exit: in-host:port
expires : 12:08:56 (290 seconds left)
######################################
```

## 安装

```bash
git clone <this repo> upi-zero-link
cd upi-zero-link
python -m pip install -e .
# 或者不装，直接： python -m upi_zero_link --help
```

依赖：Python ≥ 3.10、`curl_cffi`、`requests`。

## 用法

```bash
# 单账号
upi-zero-link --token <access_token> --email you@example.com \
              --proxy socks5h://user:pass@in-exit:port

# 批量（JSON 文件），出链即停
upi-zero-link --accounts accounts.json \
              --proxy socks5h://user:pass@in-exit-1:port \
              --proxy socks5h://user:pass@in-exit-2:port \
              --rounds 4 --notify --out links.json
```

| 参数 | 说明 |
|---|---|
| `--token` / `--accounts` | 账号 access_token，或账号 JSON 文件（见 `accounts.example.json`） |
| `--email` | 用于 Stripe `billing_details` 的邮箱 |
| `--proxy` | 印度出口，**可重复**；不传则取环境变量 `UPI_PROXY`（默认 `socks5h://127.0.0.1:1080`） |
| `--rounds` | 每个号最多换几条出口（默认 4）。同一个号换出口重试是**有效**的，实测出现过「第一条出口 `nonzero_due`、换一条就出链」 |
| `--tries` | 同一会话里 confirm 重试次数（1 或 2，默认 2） |
| `--notify` | 出链时响铃 / 弹窗（Windows 用托盘气泡，其他平台终端响铃） |
| `--out` | 结果落盘路径（默认 `links.json`） |
| `--all` | 出链后继续跑完剩下的账号 |
| `--quiet` | 只打结论 |

## 出口代理（关键前提）

提链要**连续十几个请求复用同一条隧道**，普通轮换代理会在中途换 IP，流程直接崩。
所以必须自己准备**印度住宅出口**，要求：

1. 出口 IP 在印度（Stripe 侧会算印度税区，ChatGPT 侧走印度定价）；
2. 支持长连接、单会话内不换出口；
3. 代理 URL 形如 `socks5h://user:pass@host:port`（`http://` 也可）。

`--proxy` 给多条时按轮次轮换，用来对冲单条出口偶发的断连（curl 56/97/28）。

## 它到底做了什么

```
1. POST chatgpt.com/backend-api/payments/checkout    带 promo plus-1-month-free
   → 只有带 promo 才是 SetupIntent 路线（payment_method_collection=always），
     才可能签出 ₹0 委托；不带 promo 走 PaymentIntent，必定 ₹1999
2. POST api.stripe.com/v1/payment_pages/{cs}/init
3. POST api.stripe.com/v1/payment_pages/{cs}         更新印度税区
   → 闸门：total_summary.due 必须为 0，且 payment_method_types 含 upi
4. POST api.stripe.com/v1/payment_methods            type=upi（不要传 upi[vpa]）
5. POST api.stripe.com/v1/payment_pages/{cs}/confirm expected_amount=0
   → 从这里开始消耗该号的零元资格，所以每号有效尝试次数极少
6. POST chatgpt.com/backend-api/payments/checkout/approve
   → 循环到 result == "approved"（幂等，断线原地重放即可）
7. GET  api.stripe.com/v1/payment_pages/{cs}?key={pk}
   → setup_intent.next_action.upi_handle_redirect_or_display_qr_code
       .hosted_instructions_url / .qr_code.image_url_png / .qr_code.expires_at
8. 核验指引页（见下）
```

### ★ 为什么必须有第 8 步

`hosted_instructions_url` 在 setup_intent **被拒** 时**照样会返回**。只看「有没有 URL」
就会把废链交出去 —— 用户打开看到的是 ₹1999 付款页。核验判据（两个都要满足）：

| 判据 | 通过 | 废链 |
|---|---|---|
| `intent_state` | `requires_action` / `processing` | `requires_payment_method`、`canceled` |
| UPI URI 里的 `fam` | 不是 `1999.00` | `1999.00`（₹1999 付款链） |

读法：`GET <hosted_instructions_url>`（公网可直连，不必走印度出口），页面里
`<meta id="payload" data-message="<base64url>">` 解开就是判据来源。
`am=1999.00` 是**授权上限**（`amrule=MAX`），不是本次扣款额。

交付物形态：

```
upi://mandate?ver=01&pa=openaillc.cfp@cashfreensdlpb&pn=OpenAI
&am=1999.00&cu=INR&amrule=MAX&mode=04&recur=ASPRESENTED
&txnType=CREATE&tn=OPENAI%20UPI%20Autopay&fam=1.00
```

## 结果字段

成功：

```json
{
  "email": "you@example.com",
  "url": "https://payments.stripe.com/upi/instructions/...",
  "qr_png": "https://qr.stripe.com/live_....png",
  "expires_at": "1790416701",
  "seconds_left": 290,
  "due": 0,
  "exit": "in-exit:port",
  "issued_at": 1790416411,
  "intent_state": "verified"
}
```

失败（`{"ok": false, "error": ...}`）：

| error | 含义 | 还能重试吗 |
|---|---|---|
| `nonzero_due` | 税区更新后应付 ≠ 0（promo 没生效），confirm 前就停 | 换会话可再试 |
| `upi_unavailable` | 该会话不支持 UPI | 否 |
| `tax_unverified` | 税区金额没读到 | 否 |
| `declined` | Stripe 明确拒绝建委托（`generic_decline`） | 否，该号零元资格已耗尽 |
| `link_unverified` / `no_link` | 读不到 / 核验不过指引页 | 视情况 |
| `checkout_http_4xx` | 结账接口拒绝（401 = token 失效） | 换 token |
| `NetworkDown`（异常） | 传输层断线，发生在 confirm 之前 | **可以**，换出口重来 |

日志里的 `due=… pmc=…` 是每轮的体检结果：

- `pmc=always` + `due=0` → 促销生效、走了 SetupIntent 路线，才有机会出 ₹0 委托；
- `pmc=if_required` + `due=199900` → 这一轮的结账单**没带上促销**，已经不可能出零元链，
  直接换一轮/换出口重开结账单即可（这一步不会消耗资格）。

核验读不到指引页时会自动重试 3 次；仍然失败返回 `unreachable` / `http_5xx`，
这属于「没结论」而不是「链是假的」，可以换个时间再核一次。

### 可选环境变量

| 变量 | 作用 |
|---|---|
| `UPI_PROXY` | 不传 `--proxy` 时用的默认出口 |
| `UPI_SENTINEL_TOKEN` | 手动注入 Sentinel 令牌 JSON（跳过 Node 桥，约 9 分钟有效） |
| `UPI_SENTINEL=0` | 关闭 Sentinel 生成（建单按无风控证明直连） |
| `UPI_ATTESTATION` | 手动注入 `webDeploymentAttestation`（约 1 小时有效） |
| `SENTINEL_NODE` | 指定 node 可执行文件路径 |

## 账号要求

- 账号是 **Free** 套餐，且持有该区（印度）的零元/试用促销资格（`plus-1-month-free`）；
- `access_token` 未过期（过期会 `checkout_http_401`）；
- 账号有没有资格**没法从账号资料上看出来**（实测：出过链的号和被拒的号在邮箱域、注册时间、
  promo 摘要、试用活动、2FA 状态等全部字段上完全重合）。所以能不能出链只能实际去撞，
  一个号的有效尝试次数极少。

## 免责声明

仅供**你拥有的账号**或已获得明确授权的测试使用。请遵守 OpenAI、Stripe 与所在地区的
相关条款与法律。作者不对任何滥用或由此产生的后果负责。

## 目录结构

```
upi_zero_link/
  cli.py           命令行入口
  protocol.py      8 步提链流程
  verify.py        指引页核验（intent_state + fam）
  identity.py      账号指纹 / 请求头
  addresses.py     印度真实地址池
  data/            印度邮政 PIN 数据（真实邮局名 / 县 / 邦）
  _vendor/         curl_cffi 会话、ChatGPT 通用头、风控头、Sentinel 桥
```

`_vendor/sentinel_assets/` 是 OpenAI Sentinel SDK 的抓取副本，用于生成结账风控证明；
如果上游更新导致建单被拒，换一份新的 `sentinel_sdk.js` 即可。
