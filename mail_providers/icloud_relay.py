"""iCloud 隐藏邮箱 + HTML 中转取件 provider。

主人手上的形态：
    邮箱      example-alias@icloud.com    （iCloud「隐藏我的邮件」生成的别名）
    中转链接  https://mail.ai1998.xyz/messages/<token>/<email>

中转站是第三方部署的 HTML 页面，**没有 JSON 接口**（试过 ?format=json，
还是吐 HTML），所以取码只能从 HTML 里抠。

⚠️ 中转站不止一家，取件方式各写各的（实测已遇到 3 家）。主人买号是一批一批买的，
   不同批次可能来自不同中转商，所以这里**几种形态都要认**，自动判别，不能写死一种。

   先分两大类：**JSON 接口式**（形态 C）和 **HTML 页面式**（版式 A/B）。
   判据是链接里有没有 `#email=...&key=...`，见 `_parse_pickup_credentials`。
   下面三种，靠特征标签 / 链接形状自动判别：

   版式 A（mail.ai1998.xyz）—— 纯文本正文，本地时区时间
       <article class="mail-card">
         <span class="subject">New sign-in to your OpenAI account</span>
         <span class="date">2026-08-04 09:19:36</span>
         <div class="meta">发件人：noreply_at_tm_openai_com_...@icloud.com</div>
         <pre class="body">正文……</pre>
       </article>

   版式 B（icloud-api.top）—— 正文是**整封原始 HTML**，RFC2822 UTC 时间
       <div class="card">
         <div class="fr">ChatGPT &lt;otp_at_tm1_openai_com_...@icloud.com&gt;</div>
         <div class="su">ChatGPT の一時的な認証コード</div>
         <div class="dt">Tue, 04 Aug 2026 06:29:52 +0000</div>
         <div class="bd"><html>…整封邮件…</html></div>
       </div>

   A / B 默认都只给最新一封，要全部得带参数：A 用 ?all=1，B 用 ?n=10。
   实测两家都容忍对方的参数（多余的会被忽略），所以两个一起带，
   不用先探测是哪家。

   形态 C（flysms.xyz）—— **纯 JSON 接口，没有 HTML 可抠**（2026-08-07 新增）
       链接长这样，注意参数在 `#` 后面：
           https://flysms.xyz/icloud/pickup#email=xxx%40icloud.com&key=tok_xxx

       `#` 后面的内容**浏览器不会发给服务器**，所以直接 GET 这个地址只拿得到
       一个 339 字节的 React 空壳，一封信都没有 —— A / B / 兜底三个解析器
       全都扫不到东西（主人 2026-08-07 遇到的就是这个）。真正取信的是页面里
       JS 自己发的那个请求，协议是从它的 bundle 里挖出来的：

           GET  <base>/api/pickup/messages?limit=20
           Accept:          application/json
           Authorization:   Bearer <key>
           X-Mailbox-Email: <email>

       返回 {"email","scope","revision","messages":[…],"nextCursor"}，
       每封信有 uid / from / to / date / subject / preview / hasAttachments。

       ✅ 这条路比抠 HTML 稳得多：
          · `uid` 是**真正的邮件 ID**。A / B 只能拿「时间+主题」凑指纹，
            而 OpenAI 连发几封验证码时这两项几乎一模一样，最容易撞车。
          · `date` 是带 Z 的 ISO8601 **绝对时间**，防旧码的时间窗从此可靠
            （版式 A 那个「本机时区墙上时间」的坑在这里不存在）。
          · `from` 是**真实发件人** noreply@tm.openai.com，
            不是中转站改写过的 noreply_at_tm_openai_com_xxx@icloud.com。

       ⚠️ **uid 顺序和时间顺序对不上**（实测 uid …116 比 …118 还新）。
          所以 uid 只能当指纹，排序和时间窗一律认 `date`。
       ⚠️ 正文只有 `preview`（截断的纯文本），没有取全文的接口。OpenAI 的
          验证码都在正文开头，实测日/英两种模板都取得到；哪天模板把码挪到
          很靠后，这里要另想办法。

能力：pooled=True     一批号导进号池，一个一个 claim（每个号自带取件链接）
      ephemeral=False 地址固定不变 ⚠️

⚠️ ephemeral=False 的实际表现（实测 2026-08-04）：
   同一个地址第二次跑时，OpenAI 认出它是老号，流程走
   `检测到已有账号 → passwordless_login`。好消息是它**不要密码**，
   发邮件验证码就能过，所以能拿到 token；但这意味着这类号是
   「登录已有账号」而不是「注册新账号」。
   （base.py docstring 第 30 行原本担心会走 login_password 要密码
     导致 401 —— 实测没有，走的是 passwordless_login。）

   ⚠️ 因此 registrar 里 classify_error 把「已有账号」判为 account 类
   失败是不适用于本 provider 的 —— 见下面 accepts_existing_account。
"""
from __future__ import annotations

import hashlib
import html as _html
import http.cookiejar
import json
import logging
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from safe_diagnostics import network_error_kind, safe_public_error, safe_transport_error
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from html.parser import HTMLParser
from typing import Optional

from .base import (
    ConfigField,
    MailProvider,
    MailProviderError,
    extract_otp,
    register,
    validate_email,
)

logger = logging.getLogger(__name__)


_DIRECT_OPENER = None


def _relay_urlopen(req, timeout):
    """取件请求的统一出口：默认直连，绕开系统代理。

    ── 为什么取件要直连 ──
    接码中转站（ic-mail.tibosb.cloud / api.tibosb.cloud / flysms.xyz /
    ai100.my / mail.antsgo.xyz 等）都是国内可直连的第三方取件页，不需要
    翻墙。但本机系统代理（如 127.0.0.1:61378）会对这些站点偶发 HTTP 502 /
    SSL UNEXPECTED_EOF 掐断，且故障窗口能持续数分钟（2026-09-26 实测：
    走代理 502/TLS 掐断，直连同站 200）。而注册机这里用的是裸 urllib，
    默认跟随系统代理，于是 otp_wait 整窗一封邮件都拉不到，最终超时并被
    打成 failure_cause=relay_sync_unavailable。

    urllib 的 urlopen 默认读系统代理；这里改用显式装 ProxyHandler({})
    的直连 opener 绕开本机代理。opener 做成模块级单例复用，避免每 3 秒
    一轮轮询都重建。若某家接码站确实需要走代理，设环境变量
    ICLOUD_RELAY_USE_PROXY=1 即可回退到系统代理。

    单独抽成函数（而不是直接调 urlopen）是为了给测试留一个可 patch 的
    接缝：测试 patch ``mail_providers.icloud_relay._relay_urlopen`` 就能
    挡住真实网络，不影响项目里其他模块对 urllib.request.urlopen 的使用。
    """
    if os.environ.get("ICLOUD_RELAY_USE_PROXY") == "1":
        return urllib.request.urlopen(req, timeout=timeout)
    global _DIRECT_OPENER
    if _DIRECT_OPENER is None:
        _DIRECT_OPENER = urllib.request.build_opener(
            urllib.request.ProxyHandler({})
        )
    return _DIRECT_OPENER.open(req, timeout=timeout)


STRICT_ISSUED_AFTER_SKEW_SECONDS = 10
STRICT_SNAPSHOT_FALLBACK_GRACE_SECONDS = 15
STRICT_SNAPSHOT_FALLBACK_MAX_AGE_SECONDS = 30

# 只认这些发件人（中转站会把发件人改写成 noreply_at_tm_openai_com_xxx@icloud.com，
# 所以匹配的是下划线形态，不是正常域名）
_FROM_HINTS = (
    "openai", "tm_openai", "chatgpt", "auth0", "tm.openai", "chatgpt.com",
)

# ──────────────────────── HTML 解析 ────────────────────────
#
# 不引 bs4（项目没这个依赖，不想为一个 provider 加）。中转站页面是
# 版式 B 使用 HTMLParser 隔离卡片及嵌套正文；未知版式停止收码。

# ── 版式 A：mail.ai1998.xyz ──
_A_CARD = re.compile(r'<article class="mail-card">(.*?)</article>', re.S)
_A_SUBJECT = re.compile(r'<span class="subject">(.*?)</span>', re.S)
_A_DATE = re.compile(r'<span class="date">(.*?)</span>', re.S)
_A_META = re.compile(r'<div class="meta">(.*?)</div>', re.S)
_A_BODY = re.compile(r'<pre class="body">(.*?)</pre>', re.S)

# ── 版式 B：icloud-api.top ──
#
class _LayoutBParser(HTMLParser):
    """Collect each card's fields without crossing its closing element."""

    _VOID_TAGS = frozenset({'area', 'base', 'br', 'col', 'embed', 'hr', 'img',
                            'input', 'link', 'meta', 'param', 'source', 'track', 'wbr'})
    _FIELDS = frozenset({'fr', 'su', 'dt', 'bd'})

    def __init__(self):
        super().__init__(convert_charrefs=False)
        self.stack: list[str] = []
        self.current: Optional[dict] = None
        self.field: Optional[str] = None
        self.field_depth = -1
        self.cards: list[dict] = []
        self.recognized = False
        self.invalid = False

    def handle_starttag(self, tag: str, attrs) -> None:
        classes = set((dict(attrs).get('class') or '').split())
        if self.current is None:
            if tag != 'div' or 'card' not in classes:
                return
            self.recognized = True
            self.current = {}
            self.stack = ['div']
            return
        fields = classes & self._FIELDS if tag == 'div' else set()
        if self.field is None and fields:
            if len(fields) != 1 or next(iter(fields)) in self.current:
                self.invalid = True
            self.field = sorted(fields)[0]
            self.field_depth = len(self.stack)
            self.current[self.field] = []
        elif self.field is not None:
            # A second relay header inside bd indicates a broken card boundary.
            if fields & {'fr', 'su', 'dt'}:
                self.invalid = True
            self.current[self.field].append(self.get_starttag_text())
        if tag not in self._VOID_TAGS:
            self.stack.append(tag)

    def handle_startendtag(self, tag: str, attrs) -> None:
        self.handle_starttag(tag, attrs)
        if tag not in self._VOID_TAGS:
            self.handle_endtag(tag)

    def handle_endtag(self, tag: str) -> None:
        if self.current is None or tag not in self.stack:
            return
        index = len(self.stack) - 1 - self.stack[::-1].index(tag)
        if self.field is not None:
            if index <= self.field_depth:
                self.field = None
                self.field_depth = -1
            else:
                self.current[self.field].append(f'</{tag}>')
        del self.stack[index:]
        if not self.stack:
            if self._FIELDS.issubset(self.current):
                self.cards.append({k: ''.join(v) for k, v in self.current.items()})
            else:
                self.invalid = True
            self.current = None

    def handle_data(self, data: str) -> None:
        if self.current is not None and self.field is not None:
            self.current[self.field].append(data)

    def handle_entityref(self, name: str) -> None:
        self.handle_data(f'&{name};')

    def handle_charref(self, name: str) -> None:
        self.handle_data(f'&#{name};')

    def handle_comment(self, data: str) -> None:
        self.handle_data(f'<!--{data}-->')

# ── 版式 C：mail.antsgo.xyz/pick-mail ──
# 页面直出当前最新邮件，mail/code 凭证只存在 URL query 中。
_ANTSGO_MAILBOX = re.compile(
    r'<section\b[^>]*class=["\'][^"\']*\bmailbox\b[^"\']*["\'][^>]*>',
    re.S | re.I,
)
_ANTSGO_MAIL = re.compile(
    r'<section\b[^>]*class=["\'][^"\']*\bmail\b[^"\']*["\'][^>]*>(.*?)</section>',
    re.S | re.I,
)
_ANTSGO_BODY = re.compile(
    r'<section\b[^>]*class=["\'][^"\']*\bbody\b[^"\']*["\'][^>]*>(.*?)</section>',
    re.S | re.I,
)
_ANTSGO_SUBJECT = re.compile(
    r'<(?:p|div)\b[^>]*class=["\'][^"\']*\bsubject\b[^"\']*["\'][^>]*>(.*?)</(?:p|div)>',
    re.S | re.I,
)
_ANTSGO_META_PAIR = re.compile(
    r'<dt\b[^>]*>(.*?)</dt>\s*<dd\b[^>]*>(.*?)</dd>',
    re.S | re.I,
)
_ANTSGO_PRE = re.compile(r'<pre\b[^>]*>(.*?)</pre>', re.S | re.I)

_RE_TAG = re.compile(r"<[^>]+>")
# 版式 B 正文是整封 HTML，<style>/<script>/条件注释里全是数字（字号、色值、
# 行高），不清掉会被 extract_otp 当成验证码。
_RE_STYLE = re.compile(r"<style[^>]*>.*?</style>", re.S | re.I)
_RE_SCRIPT = re.compile(r"<script[^>]*>.*?</script>", re.S | re.I)
_RE_COMMENT = re.compile(r"<!--.*?-->", re.S)
_RE_HEAD = re.compile(r"<head[^>]*>.*?</head>", re.S | re.I)


# 版式 B 的发件人写成 `ChatGPT <otp_at_tm1_openai_com_xxx@icloud.com>`，
# 尖括号是**没转义的裸字符**，去标签时会被当成 HTML 标签整段吃掉，
# 只剩下 "ChatGPT" —— 而发件人正是 _looks_like_openai 的判据。先摘出来。
_RE_ANGLE_ADDR = re.compile(r"<([^<>\s]*@[^<>\s]*)>")


def _strip_tags(s: str) -> str:
    """去标签 + 反转义 HTML 实体（&amp; &#39; 之类）。

    尖括号里的邮箱地址先脱掉括号保下来，再去标签。
    """
    s = _RE_ANGLE_ADDR.sub(r" \1 ", s or "")
    return _html.unescape(_RE_TAG.sub(" ", s)).strip()


class _RoundcubeLoginFormParser(HTMLParser):
    """Extract the auto-submitted Roundcube login form without running JS."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.active = False
        self.action = ""
        self.method = ""
        self.fields: dict[str, str] = {}

    def handle_starttag(self, tag: str, attrs) -> None:
        values = {str(name).lower(): str(value or "") for name, value in attrs}
        if tag.lower() == "form" and values.get("id", "").lower() == "rc":
            self.active = True
            self.action = values.get("action", "")
            self.method = values.get("method", "get").lower()
            return
        if self.active and tag.lower() == "input":
            name = values.get("name", "")
            if name:
                self.fields[name] = values.get("value", "")

    def handle_endtag(self, tag: str) -> None:
        if self.active and tag.lower() == "form":
            self.active = False


class _RoundcubeMessageBodyParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.depth = 0
        self.parts: list[str] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        values = {str(name).lower(): str(value or "") for name, value in attrs}
        if self.depth:
            self.depth += 1
        elif values.get("id", "").lower() == "messagebody":
            self.depth = 1

    def handle_endtag(self, tag: str) -> None:
        if self.depth:
            self.depth -= 1

    def handle_data(self, data: str) -> None:
        if self.depth and data.strip():
            self.parts.append(data.strip())


def _parse_roundcube_message_body(text: str) -> str:
    parser = _RoundcubeMessageBodyParser()
    try:
        parser.feed(text or "")
    except Exception:
        return ""
    return "\n".join(parser.parts)


def _parse_roundcube_login_form(text: str, relay_url: str) -> Optional[dict]:
    parser = _RoundcubeLoginFormParser()
    try:
        parser.feed(text or "")
    except Exception:
        return None
    if not parser.action or not {"_user", "_pass"}.issubset(parser.fields):
        return None
    action_url = urllib.parse.urljoin(relay_url, parser.action)
    relay_parts = urllib.parse.urlsplit(relay_url)
    action_parts = urllib.parse.urlsplit(action_url)
    if (
        action_parts.scheme.lower() not in {"http", "https"}
        or action_parts.hostname != relay_parts.hostname
    ):
        raise MailProviderError(
            "Roundcube 自动登录地址与中转链接主机不一致，已拒绝提交邮箱凭证",
            fatal=True,
            kind="icloud_relay",
        )
    if parser.method != "post":
        raise MailProviderError(
            "Roundcube 自动登录表单不是 POST，页面协议可能已经变化",
            fatal=True,
            kind="icloud_relay",
        )
    return {"action_url": action_url, "fields": dict(parser.fields)}


def _parse_roundcube_message_rows(text: str) -> list[dict]:
    """Parse Roundcube's server-rendered ``add_message_row`` calls."""
    prefix = "rcmail.add_message_row("
    decoder = json.JSONDecoder()
    out: list[dict] = []
    cursor = 0
    while True:
        call_at = (text or "").find(prefix, cursor)
        if call_at < 0:
            break
        pos = call_at + len(prefix)
        values = []
        try:
            for _ in range(3):
                while pos < len(text) and (text[pos].isspace() or text[pos] == ","):
                    pos += 1
                value, consumed = decoder.raw_decode(text[pos:])
                values.append(value)
                pos += consumed
        except (json.JSONDecodeError, ValueError, TypeError):
            cursor = call_at + len(prefix)
            continue
        cursor = pos
        uid, _flags, columns = values
        if not isinstance(columns, dict):
            continue
        subject = _strip_tags(str(columns.get("subject") or ""))
        sender = _strip_tags(str(columns.get("fromto") or ""))
        date_str = _strip_tags(str(columns.get("date") or ""))
        otp = extract_otp(subject) or ""
        out.append({
            "subject": subject,
            "sender": sender,
            "body": otp,
            "date_str": date_str,
            "ts": _parse_date(date_str),
            "layout": "roundcube",
            "uid": f"roundcube:{uid}",
            "roundcube_uid": str(uid),
        })
    return out


def _html_to_text(s: str) -> str:
    """把整封 HTML 正文压成纯文本，保留换行结构。

    版式 B 的正文是原封不动的邮件 HTML。先砍掉 head/style/script/条件注释
    —— 里面 `font-size: 24px` `#F3F3F3` `line-height: 28px` 这类数字一大堆，
    留着的话 extract_otp 会从 CSS 里挖出一个假验证码。
    """
    s = _RE_HEAD.sub(" ", s or "")
    s = _RE_STYLE.sub(" ", s)
    s = _RE_SCRIPT.sub(" ", s)
    s = _RE_COMMENT.sub(" ", s)          # <!--[if mso]> 把验证码夹在中间
    s = re.sub(r"<(br|/p|/div|/tr|/td|/h[1-6])[^>]*>", "\n", s, flags=re.I)
    s = _RE_TAG.sub(" ", s)
    s = _html.unescape(s)
    # 逐行去空白并丢掉空行：extract_otp 靠行结构防误判，一行一个字段最干净
    lines = [ln.strip() for ln in s.splitlines()]
    return "\n".join(ln for ln in lines if ln)


def _parse_date(s: str) -> Optional[float]:
    """把中转页的时间字符串解析成 epoch 秒，两种版式都认。

    版式 A '2026-08-04 09:19:36' —— 没写时区，实测是**本机时区**的墙上时间
        （页面 09:19:36 对应邮件正文里的 EDT 9:19 PM，差 12h，
          说明它就是按服务器本地时区渲染的），按 naive 本地时间解析。

    版式 B 'Tue, 04 Aug 2026 06:29:52 +0000' —— 标准 RFC2822，**带时区**，
        用 email.utils 解析，直接得到正确的绝对时间。有的还带
        ' (UTC)' 后缀，parsedate_to_datetime 处理不了，先削掉。

    解析不出来返回 None —— 调用方会退化成"不做时间过滤"，
    宁可多读一封也不要因为解析失败漏掉验证码。
    """
    s = (s or "").strip()
    if not s:
        return None

    # 版式 B：有星期几或月份缩写 → 走 RFC2822
    if "," in s or re.search(r"\b[A-Z][a-z]{2}\b", s):
        cleaned = re.sub(r"\s*\([A-Za-z]+\)\s*$", "", s)     # 去掉 ' (UTC)'
        try:
            dt = parsedate_to_datetime(cleaned)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.timestamp()
        except (TypeError, ValueError):
            pass

    # 版式 A：naive 本地时间
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y/%m/%d %H:%M:%S"):
        try:
            return datetime.strptime(s, fmt).timestamp()
        except ValueError:
            continue
    return None


# ──────────────────── 形态 C：JSON 接口 ────────────────────


def _parse_iso8601(s: str) -> Optional[float]:
    """'2026-08-07T01:38:25.000Z' -> epoch 秒。

    带 Z 的绝对时间，不用猜时区 —— 这是 JSON 接口相对 HTML 版式最大的好处。
    解析不出来退回通用的 _parse_date，别为一个格式微调就把时间窗整个丢掉。
    """
    s = (s or "").strip()
    if not s:
        return None
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00").replace("z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except ValueError:
        return _parse_date(s)


def _parse_pickup_credentials(url: str) -> Optional[dict]:
    """认不认得出这是「JSON 接口式」链接？认得就返回调接口要的三件套。

    判据：`#` 后面同时有 email 和 key（实测就放这儿）。顺带也看 query，
    是给以后别家留的后路。**认不出来返回 None**，调用方继续走 HTML 版式，
    所以这个改动对 A / B 两家零影响。

    接口地址从页面路径推出来，对应 bundle 里那句
    `${'/icloud/'.replace(/\\/$/,'')}/api/pickup/messages`：
        https://flysms.xyz/icloud/pickup -> https://flysms.xyz/icloud/api/pickup/messages
    不写死域名，换个中转商只要形状一样就还能用。
    """
    parts = urllib.parse.urlsplit(url or "")
    for blob in (parts.fragment, parts.query):
        q = dict(urllib.parse.parse_qsl(blob or ""))
        email = (q.get("email") or "").strip()
        token = (q.get("key") or q.get("token") or "").strip()
        if email and token:
            path = parts.path.rstrip("/")
            if path.endswith("/pickup"):
                path = path[: -len("/pickup")]
            api = urllib.parse.urlunsplit(
                (parts.scheme, parts.netloc, f"{path}/api/pickup/messages", "", "")
            )
            return {"api_url": api, "email": email.lower(), "token": token}
    return None


def _is_mailbox_code_api_url(url: str) -> bool:
    """识别 iCloud Privacy Mail 的单验证码 JSON 接口链接。"""
    parts = urllib.parse.urlsplit(url or "")
    path = urllib.parse.unquote(parts.path or "").rstrip("/").lower()
    query = dict(urllib.parse.parse_qsl(parts.query or ""))
    keyed_mailbox_api = (
        path.endswith("/code")
        and ("/api/v1/mailboxes/" in path or "/api/mailboxes/" in path)
        and bool((query.get("key") or "").strip())
    )
    tibosb_access_api = (
        (parts.hostname or "").lower() == "ic-mail.tibosb.cloud"
        and re.fullmatch(
            r"/api/v1/access/[a-z0-9_-]+/mailboxes/[^/]+/code",
            path,
        ) is not None
    )
    return keyed_mailbox_api or tibosb_access_api


def _parse_ai100_code_url(url: str) -> Optional[dict]:
    """识别 ai100 ``/mail/code/<token>`` 单验证码 JSON 接口。"""
    parts = urllib.parse.urlsplit(url or "")
    if (parts.hostname or "").lower() not in {"ai100.my", "www.ai100.my"}:
        return None
    path = urllib.parse.unquote(parts.path or "").rstrip("/")
    match = re.fullmatch(r"/mail/code/([A-Za-z0-9_-]+)", path)
    if not match:
        return None
    return {"url": url, "token": match.group(1)}


def _parse_mz253_short_link(url: str) -> Optional[dict]:
    """识别 mz-253 的 ``/m/<code>`` 短链接并生成实际 API 地址。"""
    parts = urllib.parse.urlsplit(url or "")
    if (parts.hostname or "").lower() != "mz-253.pages.dev":
        return None
    match = re.fullmatch(r"/m/([^/]+)", parts.path.rstrip("/"))
    if not match:
        return None
    code = urllib.parse.unquote(match.group(1)).strip()
    if not code:
        return None
    api_base = "https://mzemail.fengshuieon.com"
    return {
        "code": code,
        "resolve_url": f"{api_base}/open_api/short_access/{urllib.parse.quote(code, safe='')}",
        "mails_url": f"{api_base}/api/mails",
    }


def _parse_tibosb_share_url(url: str) -> Optional[dict]:
    """识别 tibosb 分享链接并生成其正式公开收件箱 API 地址。"""
    parts = urllib.parse.urlsplit(url or "")
    path = urllib.parse.unquote(parts.path or "").rstrip("/")
    if (parts.hostname or "").lower() != "api.tibosb.cloud":
        return None
    match = re.fullmatch(r"/share/([A-Za-z0-9_-]+)", path)
    if not match:
        return None
    token = match.group(1)
    api_base = "https://api.tibosb.cloud/api/public/share"
    return {
        "inbox_url": f"{api_base}/{token}/inbox?limit=30&days=7",
    }


def _parse_mz253_json(payload: dict) -> list[dict]:
    """把 mz-253 邮件列表映射成 provider 的统一邮件结构。"""
    out: list[dict] = []
    for message in (payload or {}).get("results") or []:
        if not isinstance(message, dict):
            continue
        date_str = str(message.get("created_at") or "")
        ts = None
        if date_str:
            try:
                ts = datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S").replace(
                    tzinfo=timezone.utc
                ).timestamp()
            except ValueError:
                ts = _parse_iso8601(date_str)
        out.append({
            "subject": str(message.get("subject") or ""),
            "sender": str(message.get("source") or ""),
            "body": str(message.get("raw") or message.get("text") or ""),
            "date_str": date_str,
            "ts": ts,
            "layout": "mz253",
            "uid": message.get("id") or message.get("message_id"),
        })
    return out


def _parse_pickup_json(payload: dict) -> list[dict]:
    """把接口返回的 messages 映射成和 HTML 版式**完全一样**的字典结构。

    统一形状是故意的：wait_for_otp 里那套时间窗 / 发件人校验 / _seen 去重
    一行都不用改，两条取件路径直接共用。多出来的 uid 只有 _fp 会用。
    """
    out: list[dict] = []
    for m in (payload or {}).get("messages") or []:
        if not isinstance(m, dict):
            continue
        date_str = str(m.get("date") or "")
        out.append({
            "subject": str(m.get("subject") or ""),
            "sender": str(m.get("from") or ""),
            "body": str(m.get("preview") or ""),
            "date_str": date_str,
            "ts": _parse_iso8601(date_str),
            "layout": "json",
            "uid": m.get("uid"),
        })
    return out


def _parse_layout_a(text: str) -> list[dict]:
    """<article class="mail-card"> + span.subject/span.date/pre.body"""
    def grab(rx, block, *, raw=False):
        m = rx.search(block)
        if not m:
            return ""
        # 正文要保留换行（extract_otp 依赖行结构做防误判），只反转义不去标签
        return _html.unescape(m.group(1)) if raw else _strip_tags(m.group(1))

    out: list[dict] = []
    for block in _A_CARD.findall(text):
        date_str = grab(_A_DATE, block)
        out.append({
            "subject": grab(_A_SUBJECT, block),
            "sender": grab(_A_META, block),
            "body": grab(_A_BODY, block, raw=True),
            "date_str": date_str,
            "ts": _parse_date(date_str),
            "layout": "A",
        })
    return out


def _looks_like_antsgo_layout(text: str) -> bool:
    """识别蚂蚁快跑 pick-mail 页面，包括当前暂时没有邮件的空收件箱。"""
    text = text or ""
    return bool(
        _ANTSGO_MAILBOX.search(text)
        and (
            _ANTSGO_MAIL.search(text)
            or "/history?" in text
            or "蚂蚁快跑" in text
        )
    )


def _parse_layout_antsgo(text: str) -> list[dict]:
    """解析 mail.antsgo.xyz/pick-mail 的当前邮件页面。"""
    mail_match = _ANTSGO_MAIL.search(text or "")
    if not mail_match:
        # 接码地址有效但尚未收信时，页面只有 mailbox/empty 区域。
        return []

    mail_block = mail_match.group(1)
    subject_match = _ANTSGO_SUBJECT.search(mail_block)
    subject = _strip_tags(subject_match.group(1)) if subject_match else ""

    metadata = {
        _strip_tags(label): _strip_tags(value)
        for label, value in _ANTSGO_META_PAIR.findall(mail_block)
    }
    sender = next(
        (value for label, value in metadata.items() if "发件人" in label),
        "",
    )
    date_str = next(
        (value for label, value in metadata.items() if "时间" in label),
        "",
    )

    body = ""
    body_match = _ANTSGO_BODY.search(text or "")
    if body_match:
        pre_match = _ANTSGO_PRE.search(body_match.group(1))
        body = _html.unescape(pre_match.group(1)).strip() if pre_match else _html_to_text(body_match.group(1))

    if not any((subject, sender, date_str, body)):
        return []
    return [{
        "subject": subject,
        "sender": sender,
        "body": body,
        "date_str": date_str,
        "ts": _parse_date(date_str),
        "layout": "antsgo",
    }]


def _parse_layout_b(text: str) -> list[dict]:
    """<div class="card"> + div.fr/div.su/div.dt/div.bd（正文是整封 HTML）"""
    parser = _LayoutBParser()
    parser.feed(text or '')
    parser.close()
    if parser.invalid or parser.current is not None:
        raise _unsupported_layout_error()
    out: list[dict] = []
    for card in parser.cards:
        date_str = _strip_tags(card['dt'])
        out.append({
            "subject": _strip_tags(card['su']),
            "sender": _strip_tags(card['fr']),
            "body": _html_to_text(card['bd']),
            "date_str": date_str,
            "ts": _parse_date(date_str),
            "layout": "B",
        })
    return out


def _unsupported_layout_error() -> MailProviderError:
    error = MailProviderError(
        '接码页版式不受支持，无法安全识别邮件字段',
        fatal=True, kind='icloud_relay',
    )
    error.failure_cause = 'relay_layout_unsupported'
    error.failure_phase = 'relay_parse'
    error.safe_message = '接码页版式不受支持；请检查中转站页面，保留账号进度后修复适配'
    return error


class _LayoutBEmptyParser(HTMLParser):
    """Recognize the waiting view, excluding scripts and explicit hiding."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack: list[str] = []
        self.hidden_stack: list[bool] = []
        self.capture = ''
        self.parts: list[str] = []
        self.waiting_paragraph = False
        self.has_card = False

    def handle_starttag(self, tag: str, attrs) -> None:
        values = dict(attrs)
        self.has_card |= bool({'card', 'mail-card'} & set((values.get('class') or '').split()))
        hidden = ('hidden' in values or (values.get('aria-hidden') or '').lower() == 'true')
        for declaration in (values.get('style') or '').split(';'):
            name, _, value = declaration.partition(':')
            value = value.lower().replace('!important', '').strip()
            hidden |= (name.strip().lower() == 'display' and value == 'none') or (
                name.strip().lower() == 'visibility' and value in {'hidden', 'collapse'}
            )
        hidden |= any(self.hidden_stack)
        if (tag == 'p' and not hidden
                and not set(self.stack) & {'head', 'script', 'style', 'template'}):
            self.capture = tag
            self.parts = []
        if tag not in _LayoutBParser._VOID_TAGS:
            self.stack.append(tag)
            self.hidden_stack.append(hidden)

    def handle_startendtag(self, tag: str, attrs) -> None:
        self.handle_starttag(tag, attrs)
        if tag not in _LayoutBParser._VOID_TAGS:
            self.handle_endtag(tag)

    def handle_data(self, data: str) -> None:
        if (self.capture and not any(self.hidden_stack)
                and not set(self.stack) & {'head', 'script', 'style', 'template'}):
            self.parts.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == self.capture:
            visible = re.sub(r'\s+', ' ', ''.join(self.parts)).strip()
            self.waiting_paragraph |= visible.rstrip(' .\u2026') == '等待接收邮件'
            self.capture = ''
        if tag in self.stack:
            index = len(self.stack) - 1 - self.stack[::-1].index(tag)
            del self.stack[index:]
            del self.hidden_stack[index:]


def _looks_like_layout_b_empty(text: str) -> bool:
    parser = _LayoutBEmptyParser()
    parser.feed(text or '')
    parser.close()
    return parser.waiting_paragraph and not parser.has_card


def parse_relay_html(text: str) -> list[dict]:
    """把中转页 HTML 解析成邮件列表，自动判别版式。

    返回 [{"subject", "sender", "body", "date_str", "ts", "layout"}, ...]，
    顺序保持页面原序（中转站都是新邮件在前）。

    未识别页面不能证明为空，也不能作为一封邮件进入快照或验证码提取。
    """
    text = text or ""
    if _looks_like_antsgo_layout(text):
        # 空收件箱也是已识别的正常状态，不应掉进整页扫描兜底。
        return _parse_layout_antsgo(text)
    if "mail-card" in text:
        msgs = _parse_layout_a(text)
    else:
        msgs = _parse_layout_b(text)

    if not msgs:
        if _looks_like_layout_b_empty(text):
            return []
        raise _unsupported_layout_error()
    return msgs


@register
class ICloudRelayProvider(MailProvider):
    """iCloud 隐藏邮箱（第三方 HTML 中转取件）。

    使用方式：
        mail = ICloudRelayProvider(
            email="example-alias@icloud.com",
            relay_url="https://mail.ai1998.xyz/messages/<token>/<email>",
        )
    """

    kind = "icloud_relay"
    display_name = "iCloud 隐藏邮箱（中转）"
    pooled = True           # 一批号导进号池，每个号自带自己的取件链接
    ephemeral = False       # 固定地址 ⚠️ 见模块 docstring

    # 2 段格式：email----relay_url
    # 每个号的中转链接都不一样（token 和地址都嵌在 URL 里），
    # 所以链接必须跟着号走，不能放全局配置。
    line_segments = 2
    import_hint = "邮箱----接码地址"
    import_placeholder = (
        "name@example.com----https://mail.antsgo.xyz/pick-mail?"
        "mail=name%40example.com&code=TOKEN"
    )

    # 号池型 provider 不需要全局配置 —— 凭证全在每一行导入数据里。
    # 空列表会让「邮箱配置」页只显示能力说明和"去导入页"的提示。
    config_fields = []

    # 本类邮箱天生就是老号：中转站卖的号大多已经注册过 ChatGPT，
    # OpenAI 走 passwordless_login 照样能拿 token，不该当失败处理。
    # registrar.classify_error 会读这个标志（默认 False，不影响其他 provider）。
    accepts_existing_account = True

    def __init__(self, email: str, relay_url: str, timeout: int = 20):
        email = (email or "").strip().lower()
        relay_url = (relay_url or "").strip()
        if not email:
            raise ValueError("iCloud 邮箱地址不能为空")
        validate_email(email)
        if not relay_url.lower().startswith(("http://", "https://")):
            raise ValueError("中转链接必须是 http(s):// 开头的完整地址")

        self.email = email
        self.relay_url = relay_url
        self.http_timeout = timeout
        self._dead = False
        self.last_persona = None

        # 取件方式自动分流：链接里带 #email=&key= 就是 JSON 接口式（形态 C），
        # 否则按老路子拉 HTML 页面（版式 A/B/兜底）。在这里判一次就够，
        # 省得每轮轮询（3 秒一次）都重新解析一遍 URL。
        self._pickup = _parse_pickup_credentials(relay_url)
        self._code_api = _is_mailbox_code_api_url(relay_url)
        self._ai100_code = _parse_ai100_code_url(relay_url)
        self._mz253 = _parse_mz253_short_link(relay_url)
        self._mz253_jwt: Optional[str] = None
        self._tibosb_share = _parse_tibosb_share_url(relay_url)
        if self._pickup:
            if self._pickup["email"] != email:
                # 号池那一行的邮箱和链接里的对不上 —— 多半是导入时粘串行了。
                # 以链接里的为准（key 是按它签的，用错必然 401），但要吼一声。
                logger.warning(
                    "[icloud_relay] 号池邮箱 %s 与链接里的 %s 不一致，"
                    "按链接里的取件（key 是跟着链接走的）",
                    email, self._pickup["email"],
                )
            logger.debug("[icloud_relay] %s 走 JSON 接口取件", email)
        elif self._code_api:
            logger.debug("[icloud_relay] %s 走单验证码 JSON 接口取件", email)
        elif self._ai100_code:
            logger.debug("[icloud_relay] %s 走 ai100 单验证码 JSON 接口取件", email)
        elif self._mz253:
            logger.debug("[icloud_relay] %s 走 mz-253 短链接 JSON 接口取件", email)
        elif self._tibosb_share:
            logger.debug("[icloud_relay] %s 走 tibosb 分享链接 JSON 接口取件", email)

        # 已消费过的邮件指纹（主题+时间），避免同一封被读两遍
        self._seen: set[str] = set()
        # 起始快照只做一次 —— 见 wait_for_otp 里的说明
        self._snapshot_done = False
        self._otp_snapshot_messages: list[dict] = []
        self._roundcube_opener = None
        self._roundcube_inbox_url = ""
        self._last_poll_error: Optional[str] = None
        self._current_poll_error: Optional[str] = None
        self._current_network_error_kind = ''
        self._successful_poll_count = 0
        self._otp_wait_diagnostics = None
        # 本轮等待窗口内连续拉取失败次数：用于日志降噪与轮询退避，
        # 也用于超时时判断「接码站持续故障」这一根因。
        self._consecutive_poll_failures = 0

    # ──────────────────────── 构造入口 ────────────────────────

    @classmethod
    def from_config(cls, settings: dict, account: Optional[dict] = None):
        """从号池记录构造 —— 每个号的邮箱和中转链接都在自己那一行里。

        没有全局配置回退：中转链接一号一条（token 嵌在 URL 里），
        放全局只能存一条，跑完就没了。缺 account 直接报错，
        比"悄悄用了上一个号的链接"要好排查得多。
        """
        if not account:
            raise MailProviderError(
                "iCloud 中转邮箱是号池型：请先去「导入邮箱」页导入号，"
                "格式 邮箱----接码地址",
                fatal=False, kind=cls.kind,
            )
        email = (account.get("email") or "").strip()
        relay = (account.get("relay_url") or "").strip()
        if not relay:
            raise MailProviderError(
                f"号池里的 {email} 没有中转链接 —— 可能是用旧格式导入的，"
                f"请按 邮箱----接码地址 重新导入",
                fatal=True, kind=cls.kind,
            )
        try:
            return cls(email=email, relay_url=relay)
        except ValueError as e:
            raise MailProviderError(str(e), fatal=True, kind=cls.kind) from e

    # ──────────────────────── HTTP ────────────────────────

    def _fetch(
        self,
        code_after: Optional[float] = None,
        wait_ms: Optional[int] = None,
    ) -> str:
        """拉中转页 HTML。

        两家中转的"看全部"参数不一样（A 用 all=1，B 用 n=N），默认都只给
        最新一封。实测两家都会忽略自己不认识的那个参数，所以两个一起带，
        省掉一次探测请求。
        """
        parts = urllib.parse.urlsplit(self.relay_url)
        q = dict(urllib.parse.parse_qsl(parts.query))
        if self._code_api:
            if code_after is not None:
                after = datetime.fromtimestamp(float(code_after), timezone.utc)
                q["after"] = after.isoformat(timespec="seconds").replace("+00:00", "Z")
            q["keyword"] = "ChatGPT"
            if wait_ms is not None:
                # ⚠️ 上限必须压在 Cloudflare 边缘超时（实测 ~5s）以内：
                # 2026-09-26 实测该域名 wait_ms=12000 的长轮询 5.0s 整被 CF
                # 掐成 502（短请求 200 正常），表现为「接码站故障」假象。
                q["wait_ms"] = str(max(1, min(int(wait_ms), 5000)))
        else:
            q["all"] = "1"
            q.setdefault("n", "20")
        url = urllib.parse.urlunsplit(
            (parts.scheme, parts.netloc, parts.path,
             urllib.parse.urlencode(q), parts.fragment)
        )
        req = urllib.request.Request(url, headers={
            "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                           "AppleWebKit/537.36 (KHTML, like Gecko) "
                           "Chrome/136.0.0.0 Safari/537.36"),
            "Accept": (
                "application/json"
                if self._code_api
                else "text/html,application/xhtml+xml,*/*;q=0.8"
            ),
            "Cache-Control": "no-cache",
        })
        try:
            with _relay_urlopen(req, timeout=self.http_timeout) as r:
                return r.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            # antsgo 的 pick-mail 在第一封邮件到达前用 404 表示“暂无邮件”，
            # 不是邮箱失效。按空收件箱处理，注册流程才能继续发送并轮询验证码。
            if (
                e.code == 404
                and (parts.hostname or "").lower() == "mail.antsgo.xyz"
                and parts.path.rstrip("/") == "/pick-mail"
            ):
                # 返回可识别的空 antsgo 页面，避免通用解析器把空响应误报为未知版式。
                return '<title>蚂蚁快跑</title><section class="mailbox"></section>'
            if e.code in (404, 410):
                error = MailProviderError(
                    f"接码地址对应邮箱不存在或已失效（HTTP {e.code}）",
                    fatal=True, kind=self.kind,
                )
                error.failure_cause = "relay_mailbox_missing"
                raise error from e
            if e.code in (401, 403):
                error = MailProviderError(
                    f"接码地址访问凭证无效或已过期（HTTP {e.code}）",
                    fatal=True, kind=self.kind,
                )
                error.failure_cause = "relay_link_unauthorized"
                raise error from e
            raise

    # ──────────────────────── 公共 API ────────────────────────

    def create_mailbox(self) -> str:
        """地址是配置里填死的，直接返回，不造新地址。"""
        return self.email

    def _fetch_json(self, limit: int = 20) -> list[dict]:
        """形态 C：直接调 JSON 接口取信。

        认证是 `Authorization: Bearer` + `X-Mailbox-Email` 两件套，少一个都是 401。
        """
        p = self._pickup
        url = f"{p['api_url']}?{urllib.parse.urlencode({'limit': limit})}"
        req = urllib.request.Request(url, headers={
            "Accept": "application/json",
            "Authorization": f"Bearer {p['token']}",
            "X-Mailbox-Email": p["email"],
            "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                           "AppleWebKit/537.36 (KHTML, like Gecko) "
                           "Chrome/136.0.0.0 Safari/537.36"),
            "Cache-Control": "no-cache",
        })
        try:
            with _relay_urlopen(req, timeout=self.http_timeout) as r:
                payload = json.loads(r.read().decode("utf-8", errors="replace"))
        except urllib.error.HTTPError as e:
            if e.code in (401, 403, 404, 410):
                raise MailProviderError(
                    f"取件接口拒绝（HTTP {e.code}）—— key 可能过期，或邮箱和链接对不上",
                    fatal=True, kind=self.kind,
                ) from e
            raise

        if not isinstance(payload, dict) or payload.get("messages") is None:
            logger.warning("[icloud_relay] 接口返回里没有 messages 字段，结构可能有变动")
            return []
        return _parse_pickup_json(payload)

    def _fetch_mz253_json(self, limit: int = 20) -> list[dict]:
        """mz-253：先用短码换 JWT，再带 JWT 拉邮件列表。"""
        headers = {
            "Accept": "application/json",
            "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                           "AppleWebKit/537.36 (KHTML, like Gecko) "
                           "Chrome/136.0.0.0 Safari/537.36"),
            "Cache-Control": "no-cache",
        }
        try:
            if not self._mz253_jwt:
                req = urllib.request.Request(self._mz253["resolve_url"], headers=headers)
                with _relay_urlopen(req, timeout=self.http_timeout) as response:
                    resolved = json.loads(
                        response.read().decode("utf-8", errors="replace")
                    )
                token = resolved.get("jwt") if isinstance(resolved, dict) else None
                if not isinstance(token, str) or not token.strip():
                    raise MailProviderError(
                        "mz-253 短链接没有返回有效取件凭证",
                        fatal=True, kind=self.kind,
                    )
                self._mz253_jwt = token.strip()

            url = f"{self._mz253['mails_url']}?{urllib.parse.urlencode({'limit': limit, 'offset': 0})}"
            req = urllib.request.Request(url, headers={
                **headers,
                "Authorization": f"Bearer {self._mz253_jwt}",
            })
            with _relay_urlopen(req, timeout=self.http_timeout) as response:
                payload = json.loads(
                    response.read().decode("utf-8", errors="replace")
                )
        except urllib.error.HTTPError as e:
            if e.code in (401, 403, 404, 410):
                raise MailProviderError(
                    f"mz-253 接码地址无效或已过期（HTTP {e.code}）",
                    fatal=True, kind=self.kind,
                ) from e
            raise
        except json.JSONDecodeError as e:
            raise MailProviderError(
                "mz-253 接口没有返回有效 JSON",
                fatal=True, kind=self.kind,
            ) from e

        if not isinstance(payload, dict) or payload.get("results") is None:
            logger.warning("[icloud_relay] mz-253 接口返回里没有 results 字段")
            return []
        return _parse_mz253_json(payload)

    def _fetch_ai100_json(self) -> list[dict]:
        """ai100：读取 ``{email, code, mail}`` 单验证码 JSON。"""
        request = urllib.request.Request(self._ai100_code["url"], headers={
            "Accept": "application/json",
            "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                           "AppleWebKit/537.36 (KHTML, like Gecko) "
                           "Chrome/136.0.0.0 Safari/537.36"),
            "Cache-Control": "no-cache",
        })
        try:
            with _relay_urlopen(request, timeout=self.http_timeout) as response:
                payload = json.loads(
                    response.read().decode("utf-8", errors="replace")
                )
        except urllib.error.HTTPError as e:
            if e.code in (401, 403, 404, 410):
                raise MailProviderError(
                    f"ai100 接码地址无效或已过期（HTTP {e.code}）",
                    fatal=True, kind=self.kind,
                ) from e
            raise
        except json.JSONDecodeError as e:
            raise MailProviderError(
                "ai100 接口没有返回有效 JSON",
                fatal=True, kind=self.kind,
            ) from e

        if not isinstance(payload, dict):
            raise MailProviderError(
                "ai100 接口返回格式错误（应为 JSON 对象）",
                fatal=True, kind=self.kind,
            )

        response_email = str(payload.get("email") or "").strip().lower()
        if response_email and response_email != self.email:
            raise MailProviderError(
                "ai100 接码地址返回的邮箱与号池邮箱不一致",
                fatal=True, kind=self.kind,
            )

        mail = payload.get("mail")
        mail_data = mail if isinstance(mail, dict) else {}
        code = extract_otp(str(payload.get("code") or ""))
        if not code and mail not in (None, ""):
            if isinstance(mail, dict):
                blob = " ".join(
                    str(mail.get(key) or "")
                    for key in (
                        "code", "otp", "subject", "title", "content", "body",
                        "text", "html", "message", "preview", "snippet",
                    )
                )
            else:
                blob = str(mail)
            code = extract_otp(blob)
        if not code:
            return []

        date_value = next(
            (
                mail_data.get(key)
                for key in (
                    "received_at", "created_at", "date", "time", "timestamp", "ts"
                )
                if mail_data.get(key) not in (None, "")
            ),
            None,
        )
        ts: Optional[float] = None
        date_str = ""
        if isinstance(date_value, (int, float)) or (
            isinstance(date_value, str) and date_value.strip().isdigit()
        ):
            ts = float(date_value)
            if ts > 1_000_000_000_000:
                ts /= 1000.0
            date_str = datetime.fromtimestamp(ts, timezone.utc).isoformat(
                timespec="seconds"
            ).replace("+00:00", "Z")
        elif date_value not in (None, ""):
            date_str = str(date_value)
            ts = _parse_iso8601(date_str)
        if ts is None:
            ts = time.time()
            date_str = datetime.fromtimestamp(ts, timezone.utc).isoformat(
                timespec="seconds"
            ).replace("+00:00", "Z")

        subject = str(
            mail_data.get("subject") or mail_data.get("title")
            or "ChatGPT verification code"
        )
        sender = str(
            mail_data.get("from") or mail_data.get("sender") or "openai"
        )
        body = str(
            mail_data.get("body") or mail_data.get("text")
            or mail_data.get("content") or mail_data.get("html")
            or mail_data.get("message") or mail_data.get("preview")
            or mail_data.get("snippet") or code
        )
        if not extract_otp(f"{subject}\n{body}"):
            body = f"{body}\n{code}" if body else code
        uid = (
            mail_data.get("id") or mail_data.get("uid")
            or mail_data.get("message_id") or payload.get("message_id")
        )
        if uid in (None, ""):
            digest = hashlib.sha256(
                f"{response_email or self.email}|{code}|{date_str}".encode("utf-8")
            ).hexdigest()[:24]
            uid = f"ai100:{digest}"
        return [{
            "subject": subject,
            "sender": sender,
            "body": body,
            "date_str": date_str,
            "ts": ts,
            "layout": "ai100_code",
            "uid": uid,
        }]

    def _fetch_tibosb_json(self) -> list[dict]:
        """tibosb 分享接口直接返回最近邮件中的验证码。"""
        request = urllib.request.Request(self._tibosb_share["inbox_url"], headers={
            "Accept": "application/json",
            "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                           "AppleWebKit/537.36 (KHTML, like Gecko) "
                           "Chrome/136.0.0.0 Safari/537.36"),
            "Cache-Control": "no-cache",
        })
        try:
            with _relay_urlopen(request, timeout=self.http_timeout) as response:
                payload = json.loads(
                    response.read().decode("utf-8", errors="replace")
                )
        except urllib.error.HTTPError as e:
            if e.code in (401, 403, 404, 410):
                raise MailProviderError(
                    f"tibosb 接码地址无效或已过期（HTTP {e.code}）",
                    fatal=True, kind=self.kind,
                ) from e
            raise
        except json.JSONDecodeError as e:
            raise MailProviderError(
                "tibosb 接口没有返回有效 JSON",
                fatal=True, kind=self.kind,
            ) from e

        if not isinstance(payload, dict):
            raise MailProviderError(
                "tibosb 接口返回格式错误（应为 JSON 对象）",
                fatal=True, kind=self.kind,
            )

        # 正式 inbox API 使用 {success, data} 包装；旧的单码接口则直接
        # 返回 {code, message}。两种都保留兼容，避免中转商切换后再漏码。
        if payload.get("success") is True:
            data = payload.get("data")
            if not isinstance(data, dict):
                raise MailProviderError(
                    "tibosb 接口返回格式错误（data 应为 JSON 对象）",
                    fatal=True, kind=self.kind,
                )
            payload = data
        elif payload.get("success") is False:
            raise MailProviderError(
                "tibosb 邮件同步暂时失败",
                fatal=False, kind=self.kind,
            )

        messages = payload.get("messages")
        if isinstance(messages, list):
            out: list[dict] = []
            for message in messages:
                if not isinstance(message, dict):
                    continue
                date_str = str(
                    message.get("date")
                    or message.get("created_at")
                    or message.get("received_at")
                    or ""
                )
                out.append({
                    "subject": str(message.get("subject") or ""),
                    "sender": str(
                        message.get("from") or message.get("sender") or ""
                    ),
                    "body": str(
                        message.get("body")
                        or message.get("preview")
                        or message.get("snippet")
                        or message.get("code")
                        or ""
                    ),
                    "date_str": date_str,
                    "ts": _parse_iso8601(date_str),
                    "layout": "tibosb_share",
                    "uid": message.get("id") or message.get("uid"),
                })
            return out

        raw_code = payload.get("code")
        if raw_code in (None, ""):
            return []
        code = str(raw_code).strip()
        if not re.fullmatch(r"\d{4,8}", code):
            raise MailProviderError(
                "tibosb 接口返回了无法识别的验证码格式",
                fatal=False, kind=self.kind,
            )
        now = time.time()
        date_str = datetime.fromtimestamp(now, timezone.utc).isoformat(
            timespec="seconds"
        ).replace("+00:00", "Z")
        return [{
            "subject": "ChatGPT verification code",
            "sender": "openai",
            "body": code,
            "date_str": date_str,
            "ts": now,
            "layout": "tibosb_share",
            "uid": f"tibosb:{code}",
        }]

    @staticmethod
    def _roundcube_headers() -> dict[str, str]:
        return {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/136.0.0.0 Safari/537.36"
            ),
            "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
            "Cache-Control": "no-cache",
        }

    def _roundcube_request(
        self,
        url: str,
        *,
        data: Optional[bytes] = None,
    ) -> tuple[str, str]:
        headers = self._roundcube_headers()
        if data is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        request = urllib.request.Request(url, data=data, headers=headers)
        with self._roundcube_opener.open(request, timeout=self.http_timeout) as response:
            charset = response.headers.get_content_charset() or "utf-8"
            body = response.read().decode(charset, errors="replace")
            final_url = response.geturl()
        return body, final_url

    def _load_roundcube(self) -> list[dict]:
        if self._roundcube_opener is None:
            self._roundcube_opener = urllib.request.build_opener(
                urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
                urllib.request.ProxyHandler({}),
            )
            login_page, login_url = self._roundcube_request(self.relay_url)
            form = _parse_roundcube_login_form(login_page, login_url)
            if not form:
                self._roundcube_opener = None
                raise MailProviderError(
                    "Roundcube 中转页没有可用的自动登录表单，页面协议可能已经变化",
                    fatal=True,
                    kind=self.kind,
                )
            payload = urllib.parse.urlencode(form["fields"]).encode("utf-8")
            inbox_page, inbox_url = self._roundcube_request(
                form["action_url"],
                data=payload,
            )
            if "rcmail.set_env(" not in inbox_page:
                self._roundcube_opener = None
                raise MailProviderError(
                    "Roundcube 自动登录失败，未进入收件箱",
                    fatal=True,
                    kind=self.kind,
                )
            self._roundcube_inbox_url = inbox_url
        else:
            inbox_page, inbox_url = self._roundcube_request(self._roundcube_inbox_url)
            self._roundcube_inbox_url = inbox_url
        messages = _parse_roundcube_message_rows(inbox_page)
        for message in messages:
            if message.get("body") or not self._looks_like_openai(message):
                continue
            if self._fp(message) in self._seen:
                continue
            parts = urllib.parse.urlsplit(self._roundcube_inbox_url)
            show_url = urllib.parse.urlunsplit((
                parts.scheme,
                parts.netloc,
                parts.path,
                urllib.parse.urlencode({
                    "_task": "mail",
                    "_action": "show",
                    "_uid": message.get("roundcube_uid", ""),
                    "_mbox": "INBOX",
                }),
                "",
            ))
            message_page, _ = self._roundcube_request(show_url)
            body = _parse_roundcube_message_body(message_page)
            message["body"] = extract_otp(body) or body
        return messages

    def _load(
        self,
        code_after: Optional[float] = None,
        wait_ms: Optional[int] = None,
    ) -> list[dict]:
        """拉一次并解析（异常原样往上抛）。两种取件方式在这里分流。"""
        if self._pickup:
            return self._fetch_json()
        if self._ai100_code:
            return self._fetch_ai100_json()
        if self._mz253:
            return self._fetch_mz253_json()
        if self._tibosb_share:
            return self._fetch_tibosb_json()
        if self._roundcube_opener is not None:
            return self._load_roundcube()
        text = self._fetch(code_after=code_after, wait_ms=wait_ms)
        if not self._code_api:
            if _parse_roundcube_login_form(text, self.relay_url):
                return self._load_roundcube()
            return parse_relay_html(text)

        try:
            payload = json.loads(text)
        except json.JSONDecodeError as e:
            raise MailProviderError(
                "中转取码接口没有返回有效 JSON，接口版本可能已经变化",
                fatal=True, kind=self.kind,
            ) from e
        if not isinstance(payload, dict):
            raise MailProviderError(
                "中转取码接口返回格式错误（应为 JSON 对象）",
                fatal=True, kind=self.kind,
            )
        if payload.get("success") is not True:
            if payload.get("code") == "no_code" and payload.get("retryable") is True:
                return []
            if payload.get("retryable") is True:
                raise MailProviderError(
                    "中转取码接口同步暂时不可用",
                    fatal=False, kind=self.kind,
                )
            raise MailProviderError(
                "中转取码接口拒绝请求",
                fatal=True, kind=self.kind,
            )

        otp = str(payload.get("code") or "").strip()
        date_str = str(payload.get("received_at") or "")
        if not otp:
            raise MailProviderError(
                "中转取码接口返回成功但没有验证码",
                fatal=True, kind=self.kind,
            )
        return [{
            "subject": str(payload.get("subject") or "OpenAI verification code"),
            "sender": "openai",
            "body": otp,
            "date_str": date_str,
            "ts": _parse_iso8601(date_str),
            "layout": "code_api",
            "uid": payload.get("message_id"),
        }]

    def _note_poll_failure(self, e: Exception, operation: str) -> None:
        """记录一次拉取失败：更新连续失败计数，并按节奏降噪打日志。

        接码站故障期每次 502 都打 warning 会把 UI 日志刷成瀑布（实测一次
        超时刷了 30 条），高频重试对故障中的站点也雪上加霜 —— 前 3 次
        每次都报，之后每 5 次报一次并带上累计数。
        """
        self._consecutive_poll_failures += 1
        if self._otp_wait_diagnostics is not None:
            self._otp_wait_diagnostics['polls_failed'] += 1
        self._last_poll_error = safe_transport_error(e, operation)
        self._current_poll_error = self._last_poll_error
        self._current_network_error_kind = network_error_kind(e)
        if self._otp_wait_diagnostics is not None:
            kinds = self._otp_wait_diagnostics.setdefault('network_error_kinds', [])
            if self._current_network_error_kind and self._current_network_error_kind not in kinds:
                kinds.append(self._current_network_error_kind)
        if self._consecutive_poll_failures <= 3 or self._consecutive_poll_failures % 5 == 0:
            logger.warning(
                "[icloud_relay] 中转同步暂时不可用（连续 %d 次，本轮继续等待）: %s",
                self._consecutive_poll_failures,
                self._last_poll_error,
            )

    def _messages(
        self,
        code_after: Optional[float] = None,
        wait_ms: Optional[int] = None,
    ) -> list[dict]:
        """给轮询用的包装：异常吞掉返回空列表（不该因一次网络抖动就崩）。"""
        try:
            messages = self._load(code_after=code_after, wait_ms=wait_ms)
        except MailProviderError as e:
            if e.fatal:
                raise                  # 配置/凭证错误不能伪装成暂时没邮件
            self._note_poll_failure(e, "iCloud relay fetch")
            return []
        except Exception as e:
            self._note_poll_failure(e, "iCloud relay fetch")
            return []
        # 成功拉取（哪怕没有新邮件）都算通道恢复，退避和计数归零。
        self._consecutive_poll_failures = 0
        self._current_poll_error = None
        self._current_network_error_kind = ''
        self._successful_poll_count += 1
        if self._otp_wait_diagnostics is not None:
            self._otp_wait_diagnostics['polls_ok'] += 1
            if not messages:
                self._otp_wait_diagnostics['empty_polls'] += 1
        return messages

    @staticmethod
    def _fp(m: dict) -> str:
        """邮件指纹，防同一封被读两遍。

        JSON 接口给了真的 uid，直接用。HTML 版式没有 message id，只能拿
        时间+主题 凑 —— 而 OpenAI 连发几封验证码时这两项几乎一模一样
        （实测 3 封里 2 封同主题、时间差 20 秒），撞车了就会漏读新码。
        又一个该优先走接口的理由。
        """
        uid = m.get("uid")
        if uid not in (None, ""):
            return f"uid:{uid}"
        return f"{m.get('date_str','')}|{m.get('subject','')[:80]}"

    def _looks_like_openai(self, m: dict) -> bool:
        blob = f"{m.get('sender','')} {m.get('subject','')}".lower()
        return any(h in blob for h in _FROM_HINTS)

    def _raise_if_cancelled(self, wait_cancel_event=None) -> None:
        cancel_event = getattr(self, "_cancel_event", None)
        if (
            (cancel_event is not None and cancel_event.is_set())
            or (wait_cancel_event is not None and wait_cancel_event.is_set())
        ):
            raise RuntimeError("任务已取消")

    def prepare_for_otp(self) -> int:
        """Mark messages that existed before requesting a new OTP as seen."""
        self._raise_if_cancelled()
        if self._code_api or self._ai100_code or self._tibosb_share:
            # The single-code endpoint is consumptive: a read returns the current
            # code once and then clears it. A pre-delivery snapshot would therefore
            # eat the very code that the formal wait must verify.
            return 0
        messages = self._messages()
        added = 0
        for message in messages:
            fingerprint = self._fp(message)
            if fingerprint not in self._seen:
                self._seen.add(fingerprint)
                added += 1
        self._snapshot_done = True
        logger.info(
            "[icloud_relay] recorded %d existing messages before OTP delivery",
            added,
        )
        return added

    def wait_for_otp(
        self,
        email_addr: str,
        timeout: int = 120,
        issued_after: Optional[float] = None,
        strict_issued_after: bool = False,
        allow_recent_snapshot_fallback: bool = False,
        cancel_event=None,
    ) -> str:
        """轮询中转页等 OTP。

        issued_after 是防串号时间窗：中转页会一直留着历史邮件（主人这个
        邮箱里已经躺着一封旧的 OpenAI 登录通知），不按时间过滤会直接
        普通流程留 90 秒宽容度以兼容邮件延迟；严格模式留 10 秒用于
        邮件服务器时间取整/时钟偏差，避免把上一授权阶段的旧码当成当前验证码。
        """
        self._raise_if_cancelled(cancel_event)
        # Each wait window owns its delivery diagnosis.  Do not let a
        # transient outage from an earlier resend make a later, healthy wait
        # look like a relay failure.
        self._last_poll_error = None
        self._current_poll_error = None
        self._current_network_error_kind = ''
        self._successful_poll_count = 0
        self._consecutive_poll_failures = 0
        stats = {
            'polls_ok': 0,
            'polls_failed': 0,
            'empty_polls': 0,
            'messages': 0,
            'skipped_seen': 0,
            'rejected_missing_time': 0,
            'rejected_old': 0,
            'rejected_sender': 0,
            'rejected_no_otp': 0,
            'network_error_kinds': [],
        }
        self._otp_wait_diagnostics = None
        # Callers may deliberately pass a short window (for example, the
        # first OTP wait before a single resend).  Keep the configured value
        # intact; normal registration still passes its 120s total budget.
        timeout = max(int(timeout), 1)
        # Keep the current wall-clock sample in a local variable instead of
        # calling time.time() in the loop condition.  Besides avoiding a
        # redundant system call on every poll, this keeps the polling state
        # isolated from logging handlers that may use the same time module
        # (and from deterministic clocks used by callers/tests).
        now = time.time()
        deadline = now + timeout
        cutoff_slack = (
            STRICT_ISSUED_AFTER_SKEW_SECONDS
            if strict_issued_after
            else 90
        )
        cutoff = (issued_after - cutoff_slack) if issued_after is not None else None
        if allow_recent_snapshot_fallback:
            logger.warning(
                "[icloud_relay] 已忽略旧版验证码快照回退开关；"
                "只接受发码时间之后的新邮件记录"
            )
        logger.info(
            f"[icloud_relay] 等待 OTP -> {email_addr} "
            f"(timeout={timeout}s, cutoff={cutoff}, strict={strict_issued_after})"
        )

        # 起始快照：把开跑前页面上就有的邮件标记为已见。
        #
        # ⚠️ 只在**第一次**调用时做。auth_flow 的 resend 重试链路会拿同一个
        #    provider 实例反复调本方法（超时 → resend → 再等），如果每次进来
        #    都重做快照，第 1 轮等待期间刚到的那封新验证码会在第 2 轮开头被
        #    标记成"已见"，然后被永远跳过 —— 表现为"明明收到了却一直超时"。
        #    时间窗 cutoff 才是防旧码的正解，_seen 只负责防同一封重复处理。
        # 单验证码 API 自己按 message_id 防重复，并且只返回一条。若在这里做
        # 初始快照，验证码恰好先到一步时会被当成基线消费掉，之后永远读不到。
        if self._code_api or self._ai100_code or self._tibosb_share:
            self._snapshot_done = True
        if not self._snapshot_done:
            try:
                for m in self._messages():
                    self._seen.add(self._fp(m))
                self._snapshot_done = True
                logger.debug(f"[icloud_relay] 初始已有 {len(self._seen)} 封，跳过")
            except MailProviderError:
                raise
            except Exception as e:
                logger.warning(safe_public_error(e, "iCloud relay initial snapshot"))

        # Snapshot retrieval is excluded from the OTP polling counters.
        self._otp_wait_diagnostics = stats
        while now < deadline:
            self._raise_if_cancelled(cancel_event)
            message_kwargs = (
                {
                    "code_after": cutoff,
                    # 服务端长轮询时长。必须是 CF 边缘超时（~5s）以内的安全值：
                    # 曾用 12000，源站 hold 12s 超过 CF 超时 → 每次拉取必 502，
                    # 整个 otp_wait 窗口一封邮件都读不到（2026-09-26 实测）。
                    # 2500ms 让取码延迟仍接近实时，又稳稳留在超时线内。
                    "wait_ms": 2500,
                }
                if self._code_api
                else {}
            )
            for m in self._messages(**message_kwargs):
                stats['messages'] += 1
                fp = self._fp(m)
                if fp in self._seen:
                    stats['skipped_seen'] += 1
                    continue

                if strict_issued_after and issued_after is not None and m.get("ts") is None:
                    stats['rejected_missing_time'] += 1
                    logger.debug("[icloud_relay] 严格模式跳过无时间戳邮件")
                    continue
                if cutoff and m.get("ts") and m["ts"] < cutoff:
                    stats['rejected_old'] += 1
                    logger.debug("[icloud_relay] 跳过发码时间窗之前的邮件")
                    continue
                if not self._looks_like_openai(m):
                    stats['rejected_sender'] += 1
                    logger.debug("[icloud_relay] 跳过非 OpenAI 邮件")
                    continue

                otp = extract_otp(f"{m.get('subject','')}\r\n\r\n{m.get('body','')}")
                if otp:
                    self._seen.add(fp)
                    logger.info('[icloud_relay] 收到 OTP（值与标题已脱敏）')
                    return otp
                stats['rejected_no_otp'] += 1
                logger.debug("[icloud_relay] 该邮件无 OTP（标题已脱敏）")
            task_cancel_event = getattr(self, "_cancel_event", None)
            now = time.time()
            remaining = max(0.0, deadline - now)
            # 拉取连续失败时逐步退避（3s → 最高 10s）：故障中的站点高频重试
            # 只会雪上加霜；成功后计数清零，自动回到正常节奏。
            delay = min(3.0 + 1.0 * self._consecutive_poll_failures, 10.0, remaining)
            wake_event = cancel_event or task_cancel_event
            if wake_event is not None:
                if wake_event.wait(delay):
                    self._raise_if_cancelled(cancel_event)
            elif delay:
                time.sleep(delay)
            now = time.time()

        message = (
            f"iCloud 中转 OTP 超时 {timeout}s（{email_addr}）—— "
            f"确认中转站能收到这个邮箱的信"
        )
        if self._current_poll_error:
            message += (
                "；failure_cause=relay_sync_unavailable；"
                "中转同步仍不可用，最后一次错误已脱敏"
            )
        error = TimeoutError(message)
        error.failure_phase = 'otp_wait'
        error.otp_wait_diagnostics = dict(
            stats,
            state=(
                'unavailable' if self._current_poll_error
                else 'degraded' if stats['polls_failed']
                else 'rejected' if stats['messages'] else 'empty'
            ),
        )
        if stats['polls_failed']:
            error.failure_cause = (
                "relay_sync_unavailable" if self._current_poll_error
                else "relay_sync_degraded"
            )
            error.relay_network_error_kind = (
                self._current_network_error_kind
                or (stats.get('network_error_kinds') or [''])[-1]
            )
            if self._consecutive_poll_failures >= 5:
                error.safe_message = (
                    f"接码站在 OTP 等待期内持续不可用（连续 {self._consecutive_poll_failures} 次拉取失败），"
                    "疑似接码站故障而非邮箱问题；账号进度已保存，等站点恢复、在邮箱配置页测通后续接重跑即可"
                )
        logger.warning(safe_public_error(error, 'OTP wait'))
        raise error

    # ──────────────────────── 导入格式 ────────────────────────

    @classmethod
    def parse_line(cls, line: str) -> dict:
        """email----relay_url

        pooled=False 时用不到，但先写好：主人以后有一批中转链接，
        把 pooled 改成 True 就能直接走号池导入。
        """
        parts = [p.strip() for p in (line or "").split("----")]
        if len(parts) != 2:
            raise ValueError(
                f"需要 2 段（邮箱----接码地址），实际 {len(parts)} 段"
            )
        email, relay = parts
        validate_email(email)
        if not relay.lower().startswith(("http://", "https://")):
            raise ValueError("第 2 段必须是 http(s):// 开头的接码地址")
        return {
            "email": email.lower(),
            "kind": cls.kind,
            "relay_url": relay,
        }

    # ──────────────────────── 自检 ────────────────────────

    def self_test(self) -> dict:
        """WebUI「测试连通性」：拉一次，报告用的哪种取件方式、看到几封信。

        把方式也报出来，是为了让主人一眼看出这个链接被判成了哪一类 ——
        万一新链接没被认成 JSON 接口式，这里会直接显示「HTML 中转页」，
        比等注册跑挂了再翻日志快得多。
        """
        way = (
            "ai100 JSON 接口"
            if self._ai100_code
            else "mz-253 JSON 接口"
            if self._mz253
            else "tibosb JSON 接口"
            if self._tibosb_share
            else "JSON 接口" if self._pickup or self._code_api else "HTML 中转页"
        )
        try:
            msgs = self._load()
        except MailProviderError as e:
            cause = getattr(e, 'failure_cause', '')
            if cause in {'relay_layout_unsupported', 'relay_mailbox_missing', 'relay_link_unauthorized'}:
                return {'ok': False, 'message': f'[{way}] {safe_public_error(e, "relay preflight")}',
                        'failure_cause': cause}
            return {'ok': False, 'message': f'[{way}] {safe_transport_error(e, "relay preflight")}',
                    'failure_cause': 'relay_sync_unavailable',
                    'relay_network_error_kind': network_error_kind(e)}
        except Exception as e:
            return {'ok': False, 'message': f'[{way}] {safe_transport_error(e, "relay preflight")}',
                    'failure_cause': 'relay_sync_unavailable',
                    'relay_network_error_kind': network_error_kind(e)}

        if not msgs:
            return {
                "ok": True,
                "message": (
                    f"[{way}] 链接可访问，但当前收件箱是空的（{self.email}）。"
                    "建议先发一封测试邮件确认能收到。"
                ),
            }
        newest = msgs[0]
        return {
            "ok": True,
            "message": (
                f"[{way}] 连接成功，{self.email} 当前有 {len(msgs)} 封邮件，"
                f"版式：{newest.get('layout', '未知')}（邮件内容已脱敏）"
            ),
        }
