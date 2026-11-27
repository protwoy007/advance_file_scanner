import argparse
import atexit
import bisect
import bz2
import concurrent.futures
import gzip
import io
import json
import lzma
import math
import multiprocessing
import os
import re
import secrets
import shutil
import signal
import struct
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import urllib.parse
import webbrowser
import zipfile
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

APP = "Zip Scanner"
AUTHOR = "Khaled"
YEAR = "2026"
CREDIT = AUTHOR + " " + YEAR
HOST = "127.0.0.1"
PORTS = range(8765, 8785)
PORT = 0
TOKEN = secrets.token_urlsafe(24)
WORKDIR = os.path.join(tempfile.gettempdir(), "zipscanner-" + secrets.token_hex(4))

MAX_UPLOAD = 8 * 1024 ** 3
CHUNK = 8 * 1024 ** 2
OVERLAP = 8192
SPOOL_MEM = 96 * 1024 ** 2
PDF_CAP = 256 * 1024 ** 2
PACK_CAP = 512 * 1024 ** 2
READ_CAP = 1024 ** 3
MAX_TOTAL = 40 * 1024 ** 3
NESTED_BUDGET = 16 * 1024 ** 3
MAX_ENTRIES = 1000000
MAX_DEPTH = 8
MAX_FINDINGS = 60000
MAX_ITEMS = 400
MAX_LIST = 3000
MAX_VENDOR = 300
PER_TYPE = 25
PER_FILE = 300
GITHUB_HARD = 100 * 1024 ** 2
GITHUB_WARN = 50 * 1024 ** 2
INLINE_BYTES = 24 * 1024 ** 2
INLINE_FILES = 400
TASK_BYTES = 48 * 1024 ** 2
TASK_FILES = 300
MAX_JOBS = 6

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
IMAGE_EXT = {".png", ".jpg", ".jpeg", ".jfif", ".gif", ".bmp", ".webp", ".tif", ".tiff", ".heic", ".heif", ".ico"}
ARCHIVES = ("zip", "tar", "gz", "bz2", "xz")
OFFICE = re.compile(r"(?:^|/)(?:word|xl|ppt)/.+\.xml$|(?:^|/)content\.xml$")
TAGS = re.compile(rb"<[^>]*>")
BN = re.compile(b"\xe0\xa7[\xa6-\xaf]")
BN_TABLE = {0x9E6 + i: 48 + i for i in range(10)}
BREAK = re.compile(rb"[^\x00\x09\x20-\x7e]")
STRINGS = re.compile(rb"[\x09\x20-\x7e]{6,}|(?:[\x20-\x7e]\x00){6,}")
GIT_LOOSE = re.compile(r"(?:^|/)\.git/objects/[0-9a-f]{2}/[0-9a-f]{38}$")
GIT_PACK = re.compile(r"(?:^|/)\.git/objects/pack/[^/]+\.pack$")
PDF_KERN = re.compile(rb"\)\s*-?\d+(?:\.\d+)?\s*\(")
PDF_STR = re.compile(rb"\(((?:\\.|[^\\()])*)\)", re.S)
PDF_ESC = re.compile(rb"\\([()\\])")
LOCAL_REV = re.compile(rb"[A-Za-z0-9._%+\-]+")
DOMAIN = re.compile(rb"[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)*\.[A-Za-z]{2,24}")
URL_AUTH = re.compile(rb"://[^\s/@]*:$")
NONPRINT = re.compile("[\x00-\x08\x0e-\x1f\x7f\ufffd]")


def mask(s):
    s = s.strip()
    if len(s) <= 3:
        return "*" * len(s)
    if len(s) <= 8:
        return s[:2] + "*" * (len(s) - 2)
    return s[:4] + "*" * min(len(s) - 6, 12) + s[-2:]


def entropy(s):
    if not s:
        return 0.0
    n = len(s)
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def luhn(d):
    nums = [int(c) for c in d][::-1]
    return (sum(nums[0::2]) + sum(sum(divmod(x * 2, 10)) for x in nums[1::2])) % 10 == 0


PLACEHOLDER = re.compile(
    r"(?i)^(?:(?:your|my)[_ -]|example|sample|changeme|change_me|placeholder|dummy|xxx+|\*+|<.*>|"
    r"\$\{.*\}|\{\{.*\}\}|%.*%|none$|null$|true$|false$|undefined|todo|password|secret|string$|"
    r"required|empty|enter|insert|replace)")
ENVREF = re.compile(r"^(?:\$[A-Za-z_{(]|%\w+%$|\{\{|<)")
VARLIKE = re.compile(r"^[A-Za-z_][A-Za-z_.]*(?:\(\))?$")
CALLISH = re.compile(r"^[A-Za-z_][\w.]*[(\[]")
CAMEL = re.compile(r"^[a-z]+(?:[A-Z][a-z]+)+$")
CODEY = ("process.env", "getenv", "environ", "config.", "input(", "getpass", "request.", "args.", "params[", "self.", "this.")
BAD_PASS = {"password", "pass", "pwd", "secret", "xxx", "xxxx", "user", "username", "changeme", "yourpassword",
            "your_password", "pw", "passwd", "token", "apikey"}
BAD_TLD = {"png", "jpg", "jpeg", "gif", "svg", "webp", "css", "js", "map", "woff", "woff2", "ttf", "eot", "ico",
           "bmp", "local", "internal"}
BAD_MAIL = ("@example.com", "@example.org", "@example.net", "@test.com", "@localhost", "@domain.com",
            "@email.com", "@yourdomain.com")
GENERIC_USERS = {
    "public", "default", "default user", "all users", "administrator", "admin", "user", "users", "username", "name",
    "your-name", "yourname", "your_name", "you", "me", "example", "root", "runner", "runneradmin", "vsts", "travis",
    "circleci", "ubuntu", "debian", "docker", "app", "node", "build", "builder", "jenkins", "vagrant", "pi",
    "ec2-user", "azureuser", "guest", "shared", "www-data", "git", "gitpod", "codespace", "vscode", "dev",
    "developer", "test", "tester", "localuser", "wdagutilityaccount", "defaultuser0", "desktop", "documents",
    "downloads"}
GENERIC_AUTHORS = {
    "python-docx", "openpyxl", "microsoft office user", "administrator", "admin", "user", "unknown", "windows user",
    "author", "owner", "anonymous", "libreoffice", "microsoft", "word", "excel", "powerpoint", "adobe", "canva",
    "pptx", "default", "none", "n/a"}
WELL_KNOWN_IPS = {"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112", "208.67.222.222",
                  "208.67.220.220", "4.4.4.4"}


def generic_secret(v):
    if PLACEHOLDER.match(v) or ENVREF.match(v):
        return None
    if v[-1] in "[({" or v.startswith(("/", "./", "../")) or "://" in v or CALLISH.match(v):
        return None
    low = v.lower()
    if any(t in low for t in CODEY):
        return None
    if VARLIKE.match(v) and ("_" in v or "." in v or v.endswith("()") or CAMEL.match(v)):
        return None
    if len(set(v)) <= 2:
        return None
    return "high" if len(v) >= 16 and entropy(v) >= 3.3 else "medium"


def api_tail(v):
    tail = v[3:]
    return any(c.isdigit() for c in tail) and any(c.isalpha() for c in tail) and entropy(tail) >= 3.2


def url_password(v):
    low = v.lower()
    if low in BAD_PASS or set(low) <= {"*", "x"}:
        return False
    return not (v.startswith(("$", "{", "<", "%", "[")) or "${" in v)


def email_ok(v):
    low = v.lower()
    if low.rsplit(".", 1)[-1] in BAD_TLD or low.endswith(BAD_MAIL):
        return False
    return "noreply" not in low and "no-reply" not in low


def card_ok(v):
    d = re.sub(r"\D", "", v)
    n = len(d)
    if not 13 <= n <= 19 or len(set(d)) < 4 or d[0] not in "3456" or not luhn(d):
        return False
    brand = ((d[0] == "4" and n in (13, 16, 19)) or (d[:2] in ("51", "52", "53", "54", "55") and n == 16)
             or (d[:2] in ("34", "37") and n == 15) or (d[:4] == "6011" and n == 16)
             or (d[:2] in ("35", "65") and n == 16) or (d[:2] == "62" and 16 <= n <= 19))
    return "high" if brand else "medium"


def intl_phone(v):
    return 9 <= len(re.sub(r"\D", "", v)) <= 15


def id_digits(v):
    return len(set(re.sub(r"\D", "", v))) > 3


def user_name(v):
    n = v.strip().lower()
    if not n or n in GENERIC_USERS or n.startswith("."):
        return False
    return not any(c in n for c in "%${}<>[]*")


def commit_ok(v):
    low = v.lower()
    return "noreply" not in low and "[bot]" not in low


def author_ok(v):
    n = v.strip().lower()
    return len(n) >= 3 and n not in GENERIC_AUTHORS and not n.startswith(("microsoft", "adobe", "libreoffice", "canva", "python", "wps"))


def address_ok(v):
    v = v.strip()
    if len(v.split()) < 3 and "," not in v:
        return False
    if re.match(r"^(?:0x[0-9a-fA-F]+|[\d.:]+)$", v):
        return False
    return not any(t in v.lower() for t in ("process.env", "getenv", "request.", "self.", "this.", "{{", "${", "<%"))


def public_ip(v):
    try:
        p = [int(x) for x in v.split(".")]
    except ValueError:
        return False
    if len(p) != 4 or any(x > 255 for x in p) or v in WELL_KNOWN_IPS:
        return False
    a, b, c = p[0], p[1], p[2]
    if a in (0, 10, 127) or a >= 224 or max(p) < 32:
        return False
    if (a, b) in ((169, 254), (192, 168)) or (a == 172 and 16 <= b <= 31) or (a == 100 and 64 <= b <= 127):
        return False
    return (a, b, c) not in ((192, 0, 2), (198, 51, 100), (203, 0, 113))


def find_emails(buf, limit):
    i = buf.find(b"@")
    while i != -1 and i < limit:
        m1 = LOCAL_REV.match(buf[max(0, i - 64):i][::-1])
        if m1:
            m2 = DOMAIN.match(buf, i + 1, min(len(buf), i + 260))
            if m2:
                s = i - m1.end()
                if not URL_AUTH.search(buf[max(0, s - 80):s]):
                    yield s, m2.end(), buf[s:m2.end()]
        i = buf.find(b"@", i + 1)


NUMRUN = re.compile(rb"[0-9][0-9 .\-()]{5,200}[0-9]")
BD_HINT = re.compile(rb"01|88")


CARD_HINT = re.compile(rb"[3-6][0-9]{12}|[3-6][0-9]{3}[ -][0-9]{4}[ -][0-9]{4}")


def gate_card(c, buf, s, e):
    return len(c) >= 13 and CARD_HINT.search(c) is not None


def gate_bd(c, buf, s, e):
    return len(c) >= 10 and BD_HINT.search(c) is not None


def gate_intl(c, buf, s, e):
    return s > 0 and buf[s - 1] == 43 and len(c) >= 8


def gate_id(c, buf, s, e):
    return len(c) >= 10 and c.count(b"-") >= 2


def gate_ip(c, buf, s, e):
    return len(c) >= 7 and c.count(b".") >= 3


def gate_tg(c, buf, s, e):
    return len(c) >= 8 and buf[e:e + 1] == b":"


def before_not(chars):
    bad = frozenset(chars)

    def edge(buf, s, e, rec):
        return s == 0 or buf[s - 1] not in bad
    return edge


DIGITS = b"0123456789"
WORDCH = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_"
LETTERS = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
NO_NUM = before_not(DIGITS + b".")
NO_CARD = before_not(WORDCH + b".")
NO_NUMDASH = before_not(DIGITS + LETTERS + b"-")
NO_PHONE = before_not(DIGITS + LETTERS + b"+")
NO_WORD = before_not(WORDCH)
NO_WORDPLUS = before_not(WORDCH + b"+")
IDENT = re.compile(rb"[A-Za-z][A-Za-z0-9]*$")


TYPED_EXT = (".ts", ".tsx", ".kt", ".kts", ".swift", ".java", ".cs", ".dart", ".scala", ".go", ".rs")


def secret_ctx(buf, s, e, rec):
    if s > 0 and buf[s - 1] in (34, 39):
        return True
    if not rec.chain[-1].lower().endswith(TYPED_EXT):
        return True
    v = buf[s:e]
    if IDENT.match(v):
        caps = sum(1 for c in v if 65 <= c <= 90)
        if caps >= 2 or not any(48 <= c <= 57 for c in v):
            return False
    return True


class Rule:
    __slots__ = ("label", "sev", "cat", "needles", "rx", "group", "check", "mask", "finder", "edge", "back", "fwd",
                 "num")

    def __init__(self, label, sev, cat, needles, rx, group=0, check=None, show=False, finder=None, edge=None,
                 back=48, fwd=330, num=None):
        self.label = label
        self.sev = sev
        self.cat = cat
        self.needles = needles
        self.rx = re.compile(rx) if rx else None
        self.group = group
        self.check = check
        self.mask = not show
        self.finder = finder
        self.edge = edge
        self.back = back
        self.fwd = fwd
        self.num = num


RULES = [
    Rule("Private key", "critical", "secret", (b"private key",),
         rb"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----", show=True),
    Rule("PuTTY private key", "critical", "secret", (b"putty-user-key-file",),
         rb"PuTTY-User-Key-File-\d", show=True),
    Rule("AWS access key ID", "critical", "secret", (b"akia", b"asia"),
         rb"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    Rule("AWS secret key", "critical", "secret", (b"aws",),
         rb"(?i)aws[\w .-]{0,30}(?:secret|sk)[\w .-]{0,30}[\"'=:\s]{1,6}([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])", 1),
    Rule("GitHub token", "critical", "secret", (b"ghp_", b"gho_", b"ghu_", b"ghs_", b"ghr_", b"github_pat_"),
         rb"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{50,255})\b"),
    Rule("GitLab token", "critical", "secret", (b"glpat-",), rb"\bglpat-[A-Za-z0-9_-]{20,}"),
    Rule("Hugging Face token", "high", "secret", (b"hf_",), rb"\bhf_[A-Za-z0-9]{34,}\b"),
    Rule("OpenAI or Anthropic key", "critical", "secret", (b"sk-",),
         rb"\bsk-(?:ant-|proj-|svcacct-|admin-)?[A-Za-z0-9_-]{32,}", 0, api_tail),
    Rule("Stripe live key", "critical", "secret", (b"_live_",), rb"\b[sr]k_live_[0-9a-zA-Z]{20,}\b"),
    Rule("Google API key", "high", "secret", (b"aiza",), rb"\bAIza[0-9A-Za-z_\-]{35}\b"),
    Rule("Google OAuth secret", "high", "secret", (b"gocspx-",), rb"\bGOCSPX-[A-Za-z0-9_-]{20,}"),
    Rule("Google access token", "high", "secret", (b"ya29.",), rb"\bya29\.[A-Za-z0-9_-]{30,}"),
    Rule("Service-account JSON", "critical", "secret", (b"service_account",),
         rb"\"type\"\s*:\s*\"service_account\"", show=True),
    Rule("Slack token", "high", "secret", (b"xox",), rb"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    Rule("Slack webhook", "high", "secret", (b"hooks.slack.com",),
         rb"https://hooks\.slack\.com/services/[A-Za-z0-9/]+"),
    Rule("Discord webhook", "high", "secret", (b"discord",),
         rb"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[\w-]+"),
    Rule("Discord bot token", "high", "secret", (),
         rb"[MNO][A-Za-z\d_-]{23,25}\.[A-Za-z\d_-]{6}\.[A-Za-z\d_-]{27,}", edge=NO_WORD),
    Rule("Telegram bot token", "high", "secret", (),
         rb"(?<!\d)\d{8,10}:[A-Za-z0-9_-]{35}(?![A-Za-z0-9_-])", fwd=48, num=gate_tg),
    Rule("SendGrid key", "high", "secret", (b"sg.",), rb"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b"),
    Rule("Mailgun key", "high", "secret", (b"key-",), rb"\bkey-[0-9a-f]{32}\b"),
    Rule("npm token", "high", "secret", (b"npm_",), rb"\bnpm_[A-Za-z0-9]{36}\b"),
    Rule("PyPI token", "high", "secret", (b"pypi-",), rb"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}"),
    Rule("Shopify token", "high", "secret", (b"shp",), rb"\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b"),
    Rule("DigitalOcean token", "high", "secret", (b"_v1_",), rb"\bdo[por]_v1_[a-f0-9]{64}\b"),
    Rule("Azure storage key", "critical", "secret", (b"accountkey=",),
         rb"(?i)AccountKey=([A-Za-z0-9+/]{40,}={0,2})", 1),
    Rule("Kubernetes client key", "critical", "secret", (b"client-key-data",),
         rb"client-key-data:[ \t]*([A-Za-z0-9+/=]{40,})", 1),
    Rule("Database URL with password", "critical", "secret", (b"://",),
         rb"\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|mariadb|redis|rediss|amqps?|mssql|sqlserver)://"
         rb"[^\s:/@\"'<>]+:([^\s@/\"'<>]+)@[^\s\"'<>]+", 1, url_password),
    Rule("URL with embedded login", "high", "secret", (b"://",),
         rb"\b(?:https?|ftps?|sftp|ssh|git)://[^\s:/@\"'<>]{1,64}:([^\s@/\"'<>]{3,})@[A-Za-z0-9.-]+", 1, url_password),
    Rule("JWT", "high", "secret", (b"eyj",),
         rb"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    Rule("Bearer token", "high", "secret", (b"bearer",),
         rb"(?i)authorization[\"']?[ \t]*[:=][ \t]*[\"']?bearer[ \t]+([A-Za-z0-9._~+/=-]{20,})", 1),
    Rule("Basic auth header", "high", "secret", (b"basic",),
         rb"(?i)authorization[\"']?[ \t]*[:=][ \t]*[\"']?basic[ \t]+([A-Za-z0-9+/=]{12,})", 1),
    Rule("Docker registry login", "high", "secret", (b"\"auth\"",),
         rb"\"auth\"\s*:\s*\"([A-Za-z0-9+/=]{16,})\"", 1),
    Rule("Hard-coded password or secret", "medium", "secret",
         (b"password", b"passwd", b"pwd", b"passphrase", b"secret", b"api_key", b"api-key", b"apikey",
          b"access_key", b"access-key", b"accesskey", b"access_token", b"access-token", b"accesstoken",
          b"auth_token", b"auth-token", b"authtoken", b"private_key", b"private-key", b"privatekey"),
         rb"(?i)(?:password|passwd|pwd|passphrase|secret|api[_-]?key|access[_-]?key|access[_-]?token|"
         rb"auth[_-]?token|private[_-]?key|client[_-]?secret)s?[\"']?[ \t]*[:=]{1,2}>?[ \t]*[\"']?"
         rb"([^\s\"',;#`<>)]{6,200})", 1, generic_secret, edge=secret_ctx, back=24, fwd=280),
    Rule("National ID number", "high", "personal", (b"nid", b"national"),
         rb"(?i)\b(?:nid|national[\s_-]*id(?:entity)?)(?:[\s_-]*(?:no|number|card|num))?\D{0,15}"
         rb"(\d{10}|\d{13}|\d{17})\b", 1),
    Rule("Birth registration number", "high", "personal", (b"birth",),
         rb"(?i)birth[\s_-]*(?:reg\w*[\s_-]*)?(?:no|number|num|id)\b\D{0,15}(\d{17}|\d{13})\b", 1),
    Rule("Passport number", "high", "personal", (b"passport",),
         rb"(?i)passport[\s_-]*(?:no|number|num|#)?\.?\W{0,6}([A-Z]{1,2}\d{6,9})\b", 1),
    Rule("Tax ID (TIN)", "medium", "personal", (b"tin",),
         rb"(?i)\b(?:e-?tin|tin)(?:[\s_-]*(?:no|number|num))?\b\D{0,10}(\d{12})\b", 1),
    Rule("Bank account number", "medium", "personal", (b"account", b"a/c"),
         rb"(?i)\b(?:account|a/c)[\s_.-]*(?:(?:no|number|num)\b|#)\.?\D{0,10}(\d{10,16})\b", 1),
    Rule("Credit card number", "medium", "personal", (),
         rb"(?:\d{13,}|\d{4}[ -]\d{4}[ -]\d{4}[ -]\d{1,7}|\d{4}[ -]\d{6}[ -]\d{4,5})(?![A-Za-z0-9_]|\.\d)",
         0, card_ok, edge=NO_CARD, fwd=6, num=gate_card),
    Rule("Phone number (Bangladesh)", "medium", "personal", (),
         rb"(?:\+?880[ -]?|\+?88[ -]?0|0)1[3-9]\d{2}[ -]?\d{3}[ -]?\d{3}(?![0-9A-Za-z])", edge=NO_PHONE, fwd=6,
         num=gate_bd),
    Rule("Phone number (international)", "medium", "personal", (),
         rb"\+(?!88[ -]?0)[1-9]\d{0,2}[ .-]?\(?\d{2,4}\)?[ .-]?\d{3,4}[ .-]?\d{3,4}(?![0-9A-Za-z])",
         0, intl_phone, edge=NO_WORDPLUS, fwd=6, num=gate_intl),
    Rule("Date of birth", "medium", "personal", (b"birth", b"dob", b"born"),
         rb"(?i)(?:date[\s_-]*of[\s_-]*birth|birth[\s_-]*date|birthday|\bdob\b|\bborn(?:[ \t]+on)?\b)\W{0,8}"
         rb"(\d{1,4}[-/. ]\d{1,2}[-/. ]\d{1,4}|\d{1,2}(?:st|nd|rd|th)?[ \t]+[A-Za-z]{3,9}\.?,?[ \t]+\d{4})", 1),
    Rule("Home address", "low", "personal", (b"address",),
         rb"(?i)\b(?:home|present|permanent|current|mailing|residential|postal)[\s_-]*address[ \t]*[:=][ \t]*"
         rb"[\"']?([^\n\"']{12,140})", 1, address_ok),
    Rule("ID number pattern (###-##-####)", "low", "personal", (),
         rb"\d{3}-\d{2}-\d{3,5}(?![0-9A-Za-z-])", 0, id_digits, edge=NO_NUMDASH, fwd=6, num=gate_id),
    Rule("Your user name in a folder path", "medium", "personal", (b"users", b"home"),
         rb"(?i)\b[A-Z]:(?:\\{1,4}|/)Users(?:\\{1,4}|/)([^\\/:*?\"<>|\r\n]{1,40}?)(?:\\|/)", 1, user_name),
    Rule("Your user name in a folder path", "medium", "personal", (b"/users/",),
         rb"/Users/([^/\s\"'<>\\]{1,40})/", 1, user_name),
    Rule("Your user name in a folder path", "medium", "personal", (b"/home/",),
         rb"/home/([^/\s\"'<>\\]{1,40})/", 1, user_name),
    Rule("Git commit identity", "medium", "personal", (b"author ", b"committer "),
         rb"(?m)^(?:author|committer) [^<\r\n]{1,80} <([^>\r\n]{3,100})> \d{9,11} [+-]\d{4}", 1, commit_ok),
    Rule("Author name in document", "low", "personal",
         (b"creator>", b"lastmodifiedby>", b"<company>", b"<manager>"),
         rb"(?i)<(?:dc:creator|cp:lastModifiedBy|meta:initial-creator|Company|Manager)>([^<]{2,100})</",
         1, author_ok),
    Rule("Author name in PDF", "low", "personal", (b"/author",), rb"/Author[ \t]*\(([^)]{2,100})\)", 1, author_ok),
    Rule("Public IP address", "low", "personal", (),
         rb"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?!\d|\.\d)", 0, public_ip, edge=NO_NUM, fwd=6, num=gate_ip),
    Rule("Email address", "low", "personal", (b"@",), None, 0, email_ok, False, find_emails),
]

NUM_RULES = [r for r in RULES if r.num is not None]

FILE_RULES = [
    (r"(^|/)id_(rsa|dsa|ecdsa|ed25519)$", "critical", "SSH private key file", "id_*", None),
    (r"(^|/)\.aws/credentials$", "critical", "AWS credentials file", ".aws/", None),
    (r"(^|/)\.git-credentials$", "critical", "Git credentials file", ".git-credentials", None),
    (r"(^|/)application_default_credentials\.json$", "critical", "Google Cloud credentials file", "@name", None),
    (r"(^|/)\.env(\.[^/]+)?$", "high", ".env file", ".env",
     lambda p: not p.endswith((".example", ".sample", ".template", ".dist", ".defaults"))),
    (r"\.(pem|key|p12|pfx|jks|keystore|ppk|p8)$", "high", "Key or certificate file", "@ext", None),
    (r"(^|/)(credentials?|secrets?)\.(json|ya?ml|txt|xml|ini|toml|properties)$", "high", "Credentials file", "@name", None),
    (r"(^|/)(\.npmrc|\.pypirc|\.netrc|_netrc|\.htpasswd|wp-config\.php|\.dockercfg)$", "high",
     "Config file with credentials", "@name", None),
    (r"(^|/)\.docker/config\.json$", "high", "Docker login file", ".docker/", None),
    (r"(^|/)(passwords?|logins?)\.(txt|csv|xlsx?|json|docx?)$", "high", "Password list", "@name", None),
    (r"(^|/)(\.bash_history|\.zsh_history|\.python_history|\.psql_history|\.mysql_history|\.node_repl_history|"
     r"consolehost_history\.txt)$", "high", "Shell history file", "@name", None),
    (r"(^|/)(login data|cookies|web data|key4\.db|logins\.json|cookies\.sqlite)$", "high",
     "Browser password or cookie store", "@name", None),
    (r"(^|/)(keystore|signing|secrets?)\.properties$", "high", "Android signing or secrets file", "@name", None),
    (r"(^|/)local\.properties$", "medium", "Android local.properties (holds your SDK path and user name)",
     "local.properties", None),
    (r"\.tfstate(\.backup)?$", "high", "Terraform state (contains secrets)", "*.tfstate*", None),
    (r"\.tfvars$", "medium", "Terraform variables", "*.tfvars", None),
    (r"(^|/)\.kube/config$|(^|/)kubeconfig$", "high", "Kubernetes config", "@name", None),
    (r"\.kdbx?$|(^|/)wallet\.dat$|\.wallet$", "high", "Password manager or wallet file", "@name", None),
    (r"(^|/)(nid|passport|national[-_ ]?id|driving[-_ ]?licen[sc]e|birth[-_ ]?cert\w*|ssn|tax[-_ ]?return|"
     r"bank[-_ ]?statement|payslip)[^/]*\.(jpe?g|png|pdf|heic|docx?)$", "high", "Possible ID document", "@name", None),
    (r"(^|[/ ._-])(cv|resume|curriculum[-_ ]vitae)([ ._-][^/]*)?\.(pdf|docx?|odt|txt)$", "medium",
     "CV or resume (phone, email, address)", "@name", None),
    (r"(google-services\.json|googleservice-info\.plist)$", "medium", "Firebase config", "@name", None),
    (r"\.(sqlite3?|db|sql|bak|dump|mdb|accdb)$", "medium", "Database or backup file", "@ext", None),
    (r"(^|/)\.ssh/", "medium", ".ssh folder", ".ssh/", None),
    (r"\.(ovpn|rdp)$", "medium", "VPN or remote desktop config", "@ext", None),
    (r"\.lnk$", "low", "Windows shortcut (reveals local paths)", "*.lnk", None),
    (r"\.log$", "low", "Log file (may hold personal data)", "*.log", None),
    (r"(^|/)(thumbs\.db|desktop\.ini|\.ds_store)$", "low", "System junk file", "@name", None),
]
FILE_COMPILED = [(re.compile(rx), s, lbl, ign, v) for rx, s, lbl, ign, v in FILE_RULES]

JUNK = {
    "node_modules": "node_modules/", "__pycache__": "__pycache__/", ".venv": ".venv/", "venv": "venv/",
    ".idea": ".idea/", ".vs": ".vs/", ".gradle": ".gradle/", ".pytest_cache": ".pytest_cache/",
    ".mypy_cache": ".mypy_cache/", ".next": ".next/", ".nuxt": ".nuxt/", ".cache": ".cache/",
    ".ipynb_checkpoints": ".ipynb_checkpoints/", ".git": ".git/",
}

SEP = r"[\s._\-]*"


def term_pattern(t):
    t = t.translate(BN_TABLE)
    digits = re.sub(r"\D", "", t)
    if len(digits) >= 7 and re.fullmatch(r"[+\d\s().\-]+", t):
        if len(digits) == 13 and digits.startswith("880"):
            digits = digits[3:]
        elif len(digits) == 11 and digits.startswith("01"):
            digits = digits[1:]
        return r"[\s.\-]?".join(digits) + r"(?!\d)", None, len(digits) == 10 and digits[0] == "1"
    toks = t.split()
    core = re.escape(t) if "@" in t else SEP.join(re.escape(x) for x in toks)
    anchor = t if "@" in t else max(toks, key=len)
    if len(re.sub(r"\W", "", t)) < 5:
        core = r"(?<![A-Za-z0-9])" + core + r"(?![A-Za-z0-9])"
    return core, anchor.encode("utf-8").lower(), False


PHONE_LEAD = re.compile(rb"(?:\+?880[ .\-]{0,2}|\+?88[ .\-]{0,2}0|0)$")


class Term:
    __slots__ = ("label", "anchor", "span", "rx", "lead")

    def __init__(self, label, pattern, anchor, span, lead=False):
        self.label = label
        self.anchor = anchor
        self.span = span
        self.lead = lead
        self.rx = re.compile(pattern.encode("utf-8"), re.I)

    def hits(self, buf, low, limit):
        if self.anchor is None:
            for m in self.rx.finditer(buf):
                st = m.start()
                if st >= limit:
                    return
                if self.lead and st:
                    pm = PHONE_LEAD.search(buf, max(0, st - 8), st)
                    if pm:
                        st = pm.start()
                yield st, m.end()
            return
        n = len(buf)
        seen = set()
        i = low.find(self.anchor)
        while i != -1 and i < limit + self.span:
            lo = i - self.span if i > self.span else 0
            hi = i + self.span if i + self.span < n else n
            for m in self.rx.finditer(buf, lo, hi):
                st = m.start()
                if st >= limit:
                    break
                if st in seen:
                    continue
                seen.add(st)
                yield st, m.end()
            i = low.find(self.anchor, i + 1)


class Terms:
    def __init__(self, terms):
        self.items = []
        pieces = []
        done = set()
        for t in terms[:60]:
            t = t.strip()
            if len(t) < 3:
                continue
            pat, anchor, lead = term_pattern(t)
            if pat in done:
                continue
            try:
                re.compile(pat, re.I)
                item = Term("Your info: " + mask(t), pat, anchor, len(t) * 2 + 16, lead)
            except re.error:
                continue
            done.add(pat)
            self.items.append(item)
            pieces.append("(?:" + pat + ")")
        self.name_rx = re.compile("|".join(pieces), re.I) if pieces else None


def make(sev, cat, label, chain, line, off, prev, hist=False, **kw):
    d = {"sev": sev, "cat": cat, "type": label, "chain": list(chain), "line": line, "off": off, "prev": prev}
    if hist:
        d["hist"] = True
    d.update(kw)
    return d


class Names:
    def __init__(self, terms):
        self.terms = terms
        self.junk = {}
        self.ignore = set()

    def note(self, ign, name):
        if ign == "@name":
            self.ignore.add(name.rsplit("/", 1)[-1])
        elif ign == "@ext":
            ext = os.path.splitext(name)[1]
            if ext:
                self.ignore.add("*" + ext)
        elif ign:
            self.ignore.add(ign)

    def check(self, chain, size):
        out = []
        name = chain[-1].replace("\\", "/")
        low = name.lower()
        for rx, sev, label, ign, valid in FILE_COMPILED:
            if rx.search(low) and (valid is None or valid(low)):
                out.append(make(sev, "file", label, chain, None, None, "The file name matches a sensitive pattern"))
                self.note(ign, name)
                break
        if size is not None:
            if size > GITHUB_HARD:
                out.append(make("high", "repo", "Over GitHub's 100 MB limit", chain, None, None,
                                "%d MB. GitHub rejects files this large. Leave it out or use Git LFS." % (size // 1048576)))
            elif size > GITHUB_WARN:
                out.append(make("low", "repo", "Over GitHub's 50 MB warning size", chain, None, None,
                                "%d MB. GitHub warns about files this large." % (size // 1048576)))
        parts = name.split("/")
        for i in range(len(parts) - 1):
            p = parts[i].lower()
            if p in JUNK:
                key = (tuple(chain[:-1]), "/".join(parts[:i + 1]))
                self.junk[key] = self.junk.get(key, 0) + 1
                if p != ".git":
                    self.ignore.add(JUNK[p])
                break
        if self.terms.name_rx is not None:
            m = self.terms.name_rx.search(name)
            if m:
                out.append(make("high", "custom", "Your info in the file name", chain, None, None,
                                "Matched " + mask(m.group())))
        return out

    def finish(self):
        out = []
        for (prefix, folder), n in self.junk.items():
            chain = list(prefix) + [folder]
            if folder.rsplit("/", 1)[-1].lower() == ".git":
                out.append(make("medium", "repo", ".git folder included", chain, None, None,
                                "Holds your full commit history, including anything you deleted later (%d files)" % n,
                                isdir=True))
            else:
                out.append(make("low", "repo", "Folder that should not be uploaded", chain, None, None,
                                "%d files inside. It is generated or specific to your machine." % n, isdir=True))
        self.junk = {}
        return out


class Rec:
    def __init__(self, chain, hist=False):
        self.chain = chain
        self.hist = hist
        self.counts = {}
        self.more = {}
        self.dead = set()
        self.seen = set()
        self.total = 0
        self.line_base = 0
        self.base = 0


class Acc:
    def __init__(self, opts):
        self.terms = Terms(opts.get("terms") or [])
        self.names = Names(self.terms)
        self.budget = opts.get("budget", NESTED_BUDGET)
        self.findings = []
        self.skipped = []
        self.manual = []
        self.keys = set()
        self.files = 0
        self.bytes = 0
        self.entries = 0
        self.truncated = False

    def add(self, f):
        if len(self.findings) >= MAX_FINDINGS:
            self.truncated = True
            return
        k = (f["type"], tuple(f["chain"]), f["line"], f["off"], f["prev"])
        if k in self.keys:
            return
        self.keys.add(k)
        self.findings.append(f)

    def skip(self, chain, reason):
        if len(self.skipped) < MAX_LIST:
            self.skipped.append({"chain": list(chain), "reason": reason})

    def review(self, chain, reason):
        if len(self.manual) < MAX_LIST:
            self.manual.append({"chain": list(chain), "reason": reason})

    def export(self):
        for f in self.names.finish():
            self.add(f)
        return {"findings": self.findings, "skipped": self.skipped, "manual": self.manual,
                "ignore": sorted(self.names.ignore), "files": self.files, "bytes": self.bytes,
                "entries": self.entries, "truncated": self.truncated}


def no_offset(p):
    return None


class Mapper:
    def __init__(self, buf, limit, base):
        self.buf = buf
        self.limit = limit
        self.base = base
        self.starts = None
        self.offs = None

    def __call__(self, p):
        if self.starts is None:
            self.starts, self.offs = [], []
            n = 0
            for m in STRINGS.finditer(self.buf, 0, self.limit):
                self.starts.append(n)
                self.offs.append(m.start())
                ln = m.end() - m.start()
                n += (ln // 2 if m.group()[1:2] == b"\x00" else ln) + 1
        i = bisect.bisect_right(self.starts, p) - 1
        if i < 0:
            i = 0
        return self.base + self.offs[i] + (p - self.starts[i])


def bn_ascii(buf):
    return BN.sub(lambda m: bytes((m.group()[2] - 0xA6 + 48,)), buf)


def strings_view(buf, limit):
    runs = STRINGS.findall(buf, 0, limit)
    return b"\n".join([b[::2] if b[1:2] == b"\x00" else b for b in runs])


def snippet(buf, s, e, shown):
    lo = max(0, s - 60)
    a = buf.rfind(b"\n", lo, s)
    a = a + 1 if a != -1 else lo
    b = buf.find(b"\n", e, e + 60)
    if b == -1:
        b = min(len(buf), e + 60)
    out = buf[a:s].decode("utf-8", "replace") + shown + buf[e:b].decode("utf-8", "replace")
    return NONPRINT.sub(".", " ".join(out.split()))[:200]


def iter_rx(r, buf, limit):
    g = r.group
    for m in r.rx.finditer(buf):
        if m.start() >= limit:
            return
        yield m.start(g), m.end(g), m.group(g)


def iter_anchored(r, buf, low, limit):
    g = r.group
    n = len(buf)
    seen = set()
    for a in r.needles:
        i = low.find(a)
        while i != -1 and i < limit + r.back:
            lo = i - r.back if i > r.back else 0
            hi = i + r.fwd if i + r.fwd < n else n
            for m in r.rx.finditer(buf, lo, hi):
                st = m.start()
                if st >= limit:
                    break
                if st in seen:
                    continue
                seen.add(st)
                yield m.start(g), m.end(g), m.group(g)
            i = low.find(a, i + 1)


def numeric_hits(buf, limit, rec):
    rules = [r for r in NUM_RULES if r.label not in rec.dead]
    out = {}
    if not rules:
        return out
    n = len(buf)
    seen = set()
    for m in NUMRUN.finditer(buf):
        s, e = m.span()
        if s >= limit:
            break
        c = buf[s:e]
        for r in rules:
            if not r.num(c, buf, s, e):
                continue
            for mm in r.rx.finditer(buf, s - 12 if s > 12 else 0, min(n, e + r.fwd)):
                st = mm.start()
                if st >= limit or (r.label, st) in seen:
                    continue
                seen.add((r.label, st))
                out.setdefault(r, []).append((mm.start(r.group), mm.end(r.group), mm.group(r.group)))
    return out


def bump(rec, label, sev, cat):
    n = rec.more.get(label, (0,))[0]
    rec.more[label] = (n + 1, sev, cat)


def flush_more(acc, rec):
    for label, (n, sev, cat) in rec.more.items():
        acc.add(make(sev, cat, label, rec.chain, None, None, "%d more of this type in this file, not listed" % n,
                     hist=rec.hist))
    rec.more = {}


def scan_buf(acc, rec, buf, limit, mapper=None, only_new=False):
    low = buf.lower()
    hits = []
    claimed = {"secret": [], "personal": []}
    nums = numeric_hits(buf, limit, rec)
    for r in RULES:
        if r.label in rec.dead:
            continue
        if r.num is not None:
            it = nums.get(r, ())
        elif r.finder:
            if r.needles and not any(n in low for n in r.needles):
                continue
            it = r.finder(buf, limit)
        elif r.needles:
            it = iter_anchored(r, buf, low, limit)
        else:
            it = iter_rx(r, buf, limit)
        spans = claimed[r.cat]
        for s, e, raw in it:
            if r.edge is not None and not r.edge(buf, s, e, rec):
                continue
            val = raw.decode("utf-8", "replace")
            sev = r.sev
            if r.check:
                res = r.check(val)
                if not res:
                    continue
                if isinstance(res, str):
                    sev = res
            if spans and any(s < ce and e > cs for cs, ce in spans):
                continue
            shown = mask(val) if r.mask else val
            if only_new and (r.label, shown) in rec.seen:
                continue
            n = rec.counts.get(r.label, 0) + 1
            rec.counts[r.label] = n
            if n > PER_TYPE * 40:
                rec.dead.add(r.label)
                break
            if n > PER_TYPE or rec.total >= PER_FILE:
                bump(rec, r.label, sev, r.cat)
                continue
            rec.total += 1
            rec.seen.add((r.label, shown))
            spans.append((s, e))
            hits.append((s, e, r.label, sev, r.cat, shown))
    for t in acc.terms.items:
        label = t.label
        for s, e in t.hits(buf, low, limit):
            shown = mask(buf[s:e].decode("utf-8", "replace"))
            if only_new and (label, shown) in rec.seen:
                continue
            n = rec.counts.get(label, 0) + 1
            rec.counts[label] = n
            if n > PER_TYPE * 40:
                break
            if n > PER_TYPE or rec.total >= PER_FILE:
                bump(rec, label, "high", "custom")
                continue
            rec.total += 1
            rec.seen.add((label, shown))
            hits.append((s, e, label, "high", "custom", shown))
    hits.sort(key=lambda h: h[0])
    pos = 0
    line = rec.line_base + 1
    for s, e, label, sev, cat, shown in hits:
        if mapper is None:
            line += buf.count(b"\n", pos, s)
            pos = s
            ln, off = line, None
        else:
            ln, off = None, mapper(s)
        acc.add(make(sev, cat, label, rec.chain, ln, off, snippet(buf, s, e, shown), rec.hist))
    if mapper is None:
        rec.line_base += buf.count(b"\n", 0, limit)


def read_full(f, n):
    out = f.read(n)
    if not out or len(out) >= n:
        return out
    parts = [out]
    left = n - len(out)
    while left > 0:
        b = f.read(left)
        if not b:
            break
        parts.append(b)
        left -= len(b)
    return b"".join(parts)


def spool(stream, first):
    sp = io.BytesIO()
    sp.write(first)
    disk = False
    while True:
        b = stream.read(1 << 20)
        if not b:
            break
        sp.write(b)
        if not disk and sp.tell() > SPOOL_MEM:
            d = tempfile.TemporaryFile()
            d.write(sp.getvalue())
            sp = d
            disk = True
    total = sp.tell()
    sp.seek(0)
    return sp, total


def sniff(head):
    if head[:4] in (b"PK\x03\x04", b"PK\x05\x06"):
        return "zip"
    if head[:2] == b"\x1f\x8b":
        return "gz"
    if head[:3] == b"BZh" and head[3:4] in (b"1", b"2", b"3", b"4", b"5", b"6", b"7", b"8", b"9"):
        return "bz2"
    if head[:6] == b"\xfd7zXZ\x00":
        return "xz"
    if head[257:262] == b"ustar":
        return "tar"
    if head[:5] == b"%PDF-":
        return "pdf"
    if head[:3] == b"\xff\xd8\xff":
        return "jpeg"
    return None


def reason_of(e):
    if isinstance(e, zipfile.BadZipFile):
        return "damaged data (%s)" % e
    if isinstance(e, NotImplementedError):
        return "unsupported compression method"
    if isinstance(e, RuntimeError) and "encrypted" in str(e).lower():
        return "password-protected, cannot be read"
    if isinstance(e, (zlib.error, EOFError, lzma.LZMAError)) or type(e).__name__ == "BadGzipFile":
        return "damaged or truncated compressed data"
    if isinstance(e, OSError) and e.strerror:
        return "cannot read: %s" % e.strerror
    return "unreadable (%s)" % type(e).__name__


def tiff_gps(t):
    if len(t) < 8 or t[:2] not in (b"II", b"MM"):
        return None
    e = "<" if t[:2] == b"II" else ">"
    try:
        ifd = struct.unpack_from(e + "I", t, 4)[0]
        gps = None
        for k in range(struct.unpack_from(e + "H", t, ifd)[0]):
            o = ifd + 2 + 12 * k
            if struct.unpack_from(e + "H", t, o)[0] == 0x8825:
                gps = struct.unpack_from(e + "I", t, o + 8)[0]
                break
        if gps is None:
            return None
        vals = {}
        for k in range(struct.unpack_from(e + "H", t, gps)[0]):
            o = gps + 2 + 12 * k
            tag = struct.unpack_from(e + "H", t, o)[0]
            if tag in (1, 3):
                vals[tag] = t[o + 8:o + 9].decode("ascii", "replace")
            elif tag in (2, 4):
                p = struct.unpack_from(e + "I", t, o + 8)[0]
                d = [struct.unpack_from(e + "I", t, p + 8 * j)[0] / max(struct.unpack_from(e + "I", t, p + 8 * j + 4)[0], 1)
                     for j in range(3)]
                vals[tag] = d[0] + d[1] / 60 + d[2] / 3600
        if 2 in vals and 4 in vals:
            return (vals[2] * (-1 if vals.get(1) == "S" else 1), vals[4] * (-1 if vals.get(3) == "W" else 1))
    except struct.error:
        return None
    return None


def jpeg_gps(buf):
    n = len(buf)
    i = 2
    while i + 4 <= n and buf[i] == 0xFF:
        mk = buf[i + 1]
        if mk in (0xDA, 0xD9):
            return None
        ln = (buf[i + 2] << 8) | buf[i + 3]
        if ln < 2:
            return None
        if mk == 0xE1 and buf[i + 4:i + 10] == b"Exif\x00\x00":
            return tiff_gps(buf[i + 10:i + 2 + ln])
        i += 2 + ln
    return None


def inflate(data, cap=1 << 26):
    try:
        return zlib.decompressobj().decompress(data, cap)
    except zlib.error:
        return None


def pdf_text(s):
    if b"(" not in s:
        return b""
    s = PDF_KERN.sub(b"", s)
    return b"\n".join(PDF_ESC.sub(rb"\1", m.group(1)) for m in PDF_STR.finditer(s))


def scan_pdf(acc, chain, data):
    if b"/Encrypt" in data[-4096:] or b"/Encrypt" in data[:4096]:
        acc.review(chain, "Encrypted PDF. Its text cannot be read automatically.")
        return
    parts = []
    total = 0
    pos = 0
    images = 0
    while True:
        i = data.find(b"stream", pos)
        if i < 0:
            break
        pos = i + 6
        if data[max(0, i - 3):i] == b"end":
            continue
        j = i + 6
        if data[j:j + 2] == b"\r\n":
            j += 2
        elif data[j:j + 1] in (b"\n", b"\r"):
            j += 1
        else:
            continue
        k = data.find(b"endstream", j)
        if k < 0:
            break
        pos = k + 9
        o = data.rfind(b"obj", max(0, i - 3000), i)
        head = data[o if o >= 0 else max(0, i - 400):i]
        if b"/Image" in head:
            images += 1
            continue
        if b"FlateDecode" not in head:
            continue
        out = inflate(data[j:k], 1 << 25)
        if not out:
            continue
        t = pdf_text(out)
        if t:
            parts.append(t)
            total += len(t)
            if total > 64 * 1024 ** 2:
                break
    if parts:
        buf = b"\n".join(parts)
        rec = Rec(chain)
        scan_buf(acc, rec, buf, len(buf) + 1, no_offset)
        flush_more(acc, rec)
    if images:
        acc.review(chain, "PDF with %d picture%s. Text inside pictures (scanned pages, ID photos) cannot be read automatically."
                   % (images, "" if images == 1 else "s"))
    elif not parts:
        acc.review(chain, "PDF without readable text (special fonts or scanned pages).")


def flush_pack(acc, rec, parts):
    if parts:
        buf = b"\n".join(parts)
        scan_buf(acc, rec, buf, len(buf) + 1, no_offset)


def scan_git_pack(acc, chain, data):
    if data[:4] != b"PACK" or len(data) < 32:
        return False
    count = struct.unpack(">I", data[8:12])[0]
    mv = memoryview(data)
    n = len(data)
    pos = 12
    rec = Rec(chain, True)
    parts = []
    size = 0
    for _ in range(count):
        if pos >= n - 20:
            break
        c = data[pos]
        typ = (c >> 4) & 7
        pos += 1
        while c & 0x80 and pos < n:
            c = data[pos]
            pos += 1
        if typ == 6:
            c = data[pos]
            pos += 1
            while c & 0x80 and pos < n:
                c = data[pos]
                pos += 1
        elif typ == 7:
            pos += 20
        d = zlib.decompressobj()
        fed = 0
        got = []
        total = 0
        try:
            while not d.eof and pos + fed < n:
                piece = bytes(mv[pos + fed:pos + fed + 65536])
                fed += len(piece)
                pending = piece
                while pending and not d.eof:
                    out = d.decompress(pending, 1 << 24)
                    total += len(out)
                    got.append(out)
                    pending = d.unconsumed_tail
                    if total > 1 << 28:
                        raise zlib.error("object too large")
        except zlib.error:
            break
        if not d.eof:
            break
        pos += fed - len(d.unused_data)
        if typ == 2:
            continue
        body = b"".join(got)
        if b"\x00" in body[:8192]:
            body = strings_view(body, len(body))
        if body:
            parts.append(body)
            size += len(body)
        if size >= 4 * 1024 ** 2:
            flush_pack(acc, rec, parts)
            parts = []
            size = 0
    flush_pack(acc, rec, parts)
    flush_more(acc, rec)
    return True


def scan_git_loose(acc, chain, data):
    out = inflate(data)
    if not out:
        return False
    nul = out.find(b"\x00")
    if nul < 0:
        return False
    if out[:nul].split(b" ")[0] == b"tree":
        return True
    body = out[nul + 1:]
    scan_content(acc, Rec(chain, True), io.BytesIO(body[CHUNK:]), body[:CHUNK])
    return True


def scan_content(acc, rec, stream, first):
    data = first
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        rest = read_full(stream, PDF_CAP)
        if len(rest) < PDF_CAP:
            data = (data + rest).decode("utf-16", "replace").encode("utf-8")
            stream = io.BytesIO()
        else:
            stream = io.BytesIO(rest)
    binary = b"\x00" in data[:8192]
    whole = None
    more = len(data) >= CHUNK
    started = False
    while True:
        nxt = read_full(stream, CHUNK) if more else b""
        final = not nxt
        if final and not started:
            whole = data
        if not binary and b"\xe0\xa7" in data:
            data = bn_ascii(data)
        limit = len(data) if final else max(1, len(data) - OVERLAP)
        if binary:
            if not final:
                m = BREAK.search(data, limit)
                limit = m.start() if m else len(data)
            view = strings_view(data, limit)
            if view:
                scan_buf(acc, rec, view, len(view) + 1, Mapper(data, limit, rec.base))
        else:
            scan_buf(acc, rec, data, limit)
        if final:
            break
        acc.bytes += len(nxt)
        if acc.bytes >= acc.budget:
            acc.skip(rec.chain, "size budget reached, rest of this file not read (zip-bomb protection)")
            break
        rec.base += limit
        data = data[limit:] + nxt
        more = len(nxt) >= CHUNK
        started = True
    flush_more(acc, rec)
    if whole is not None and not binary and OFFICE.search(rec.chain[-1].lower().replace("\\", "/")):
        stripped = TAGS.sub(b"", whole)
        scan_buf(acc, rec, stripped, len(stripped) + 1, no_offset, True)
        flush_more(acc, rec)


def scan_tar_members(acc, tf, chain, depth):
    for m in tf:
        if m.isdir():
            continue
        sub = chain + [m.name]
        if not m.isfile():
            acc.skip(sub, "link or device entry, not read")
            continue
        if acc.entries >= MAX_ENTRIES:
            acc.skip(chain, "entry limit reached (%d)" % MAX_ENTRIES)
            return
        acc.entries += 1
        try:
            scan_member(acc, tf.extractfile(m), m.size, sub, depth, True)
        except Exception as e:
            acc.skip(sub, reason_of(e))


def scan_zip_members(acc, zf, chain, depth, idxs=None, check=True):
    infos = zf.infolist()
    for i in (range(len(infos)) if idxs is None else idxs):
        info = infos[i]
        if info.is_dir():
            continue
        if acc.entries >= MAX_ENTRIES:
            acc.skip(chain or ["(archive)"], "entry limit reached (%d)" % MAX_ENTRIES)
            return
        acc.entries += 1
        sub = chain + [info.filename]
        if info.flag_bits & 1:
            if check:
                for f in acc.names.check(sub, info.file_size):
                    acc.add(f)
            acc.skip(sub, "password-protected, cannot be read")
            continue
        try:
            with zf.open(info) as f:
                scan_member(acc, f, info.file_size, sub, depth, check)
        except Exception as e:
            acc.skip(sub, reason_of(e))


def open_nested(acc, sp, kind, chain, depth):
    if kind == "zip":
        try:
            zf = zipfile.ZipFile(sp)
        except zipfile.BadZipFile:
            return False
        with zf:
            scan_zip_members(acc, zf, chain, depth + 1, None, True)
        return True
    try:
        tf = tarfile.open(fileobj=sp, mode="r:*")
    except (tarfile.TarError, OSError, EOFError, lzma.LZMAError, zlib.error, ValueError):
        tf = None
    if tf is not None:
        with tf:
            scan_tar_members(acc, tf, chain, depth + 1)
        return True
    if kind == "tar":
        return False
    sp.seek(0)
    if kind == "gz":
        z = gzip.GzipFile(fileobj=sp, mode="rb")
    elif kind == "bz2":
        z = bz2.BZ2File(sp)
    else:
        z = lzma.LZMAFile(sp)
    leaf = chain[-1]
    inner = leaf[:-(len(kind) + 1)] if leaf.lower().endswith("." + kind) and len(leaf) > len(kind) + 1 else leaf + "~content"
    with z:
        scan_member(acc, z, None, chain + [inner], depth + 1, True)
    return True


def scan_member(acc, stream, size, chain, depth, check=True):
    if acc.bytes >= acc.budget:
        acc.skip(chain, "size budget reached, not read (zip-bomb protection)")
        return
    if check:
        for f in acc.names.check(chain, size):
            acc.add(f)
    first = read_full(stream, CHUNK)
    acc.files += 1
    if not first:
        return
    acc.bytes += len(first)
    name = chain[-1].replace("\\", "/")
    ext = os.path.splitext(name.lower())[1]
    kind = sniff(first[:600])
    if kind in ARCHIVES:
        if depth >= MAX_DEPTH:
            acc.skip(chain, "archive nested too deep, scanned as raw data only")
        else:
            sp, total = spool(stream, first)
            acc.bytes += total - len(first)
            if open_nested(acc, sp, kind, chain, depth):
                sp.close()
                return
            sp.seek(0)
            stream = sp
            first = read_full(stream, CHUNK)
    if GIT_LOOSE.search(name):
        if scan_git_loose(acc, chain, first):
            return
    elif GIT_PACK.search(name):
        sp, total = spool(stream, first)
        acc.bytes += total - len(first)
        if total <= PACK_CAP and scan_git_pack(acc, chain, sp.read()):
            sp.close()
            return
        sp.seek(0)
        stream = sp
        first = read_full(stream, CHUNK)
    if kind == "pdf":
        sp, total = spool(stream, first)
        acc.bytes += total - len(first)
        if total <= PDF_CAP:
            scan_pdf(acc, chain, sp.read())
        sp.seek(0)
        stream = sp
        first = read_full(stream, CHUNK)
    if kind == "jpeg":
        gps = jpeg_gps(first)
        if gps:
            acc.add(make("high", "personal", "GPS location inside photo", chain, None, None,
                         "The photo records where it was taken (about %.1f, %.1f)" % gps))
    if ext in IMAGE_EXT or kind == "jpeg":
        acc.review(chain, "Picture. Text inside images (screenshots, ID photos) cannot be read automatically.")
    scan_content(acc, Rec(chain), stream, first)


def scan_disk(acc, root, rel):
    full = os.path.join(root, *rel.split("/"))
    try:
        size = os.path.getsize(full)
        with open(full, "rb") as f:
            scan_member(acc, f, size, [rel], 0, False)
    except Exception as e:
        acc.skip([rel], reason_of(e))


ZIPS = {}


def open_zip(root):
    key = (root, threading.get_ident())
    z = ZIPS.get(key)
    if z is None:
        z = ZIPS[key] = zipfile.ZipFile(root)
    return z


def close_zips(root):
    for key in [k for k in ZIPS if k[0] == root]:
        try:
            ZIPS.pop(key).close()
        except Exception:
            pass


def scan_task(task):
    kind, root, keys, opts = task
    acc = Acc(opts)
    try:
        if kind == "zip":
            scan_zip_members(acc, open_zip(root), [], 0, keys, False)
        else:
            for rel in keys:
                scan_disk(acc, root, rel)
    except Exception as e:
        acc.skip(["(batch of files)"], "scan error: %s" % reason_of(e))
    return acc.export()


class Job:
    def __init__(self, jid, kind, root, label, uploaded, terms, source):
        self.id = jid
        self.kind = kind
        self.root = root
        self.label = label
        self.uploaded = uploaded
        self.terms = terms
        self.state = "queued"
        self.phase = "Starting"
        self.error = None
        self.total = 0
        self.done = 0
        self.bytes_total = 0
        self.bytes_done = 0
        self.found = 0
        self.result = None
        self.cancel = threading.Event()
        self.lock = threading.Lock()
        self.files = []
        self.fidx = {}
        self.sizes = {}
        self.copies = 0
        self.started = time.time()
        self.bases = []
        if kind == "zip":
            cands = [source]
            if not uploaded:
                zdir = os.path.dirname(root)
                cands += [zdir, os.path.join(zdir, os.path.splitext(os.path.basename(root))[0])]
            self.bases = [b for b in cands if b and os.path.isdir(b)]

    def advance(self, n, b, f):
        with self.lock:
            self.done += n
            self.bytes_done += b
            self.found += f

    def snapshot(self):
        return {"state": self.state, "phase": self.phase, "total": self.total, "done": self.done,
                "bytes_total": self.bytes_total, "bytes_done": self.bytes_done, "found": self.found,
                "elapsed": round(time.time() - self.started, 1), "error": self.error}

    def register(self, chain, isdir=False, real=None, outer=None):
        key = tuple(chain)
        fid = self.fidx.get(key)
        if fid is None:
            fid = len(self.files)
            self.fidx[key] = fid
            self.files.append({"chain": list(chain), "isdir": isdir, "real": real, "outer": outer})
        return fid


def plan_zip(zf, acc, job):
    entries = []
    total = 0
    for i, info in enumerate(zf.infolist()):
        if job.cancel.is_set():
            break
        if info.is_dir():
            continue
        if acc.entries >= MAX_ENTRIES:
            acc.skip(["(rest of the zip)"], "entry limit reached (%d)" % MAX_ENTRIES)
            break
        if total > MAX_TOTAL:
            acc.skip(["(rest of the zip)"], "size budget reached (%d GB), remaining files not read" % (MAX_TOTAL // 1024 ** 3))
            break
        acc.entries += 1
        total += info.file_size
        chain = [info.filename]
        job.sizes[info.filename] = info.file_size
        for f in acc.names.check(chain, info.file_size):
            acc.add(f)
        if info.flag_bits & 1:
            acc.skip(chain, "password-protected, cannot be read")
            continue
        entries.append((i, info.file_size))
    return entries


def plan_folder(root, acc, job):
    entries = []
    total = 0
    stack = [""]
    while stack:
        if job.cancel.is_set():
            break
        rel = stack.pop()
        d = os.path.join(root, *rel.split("/")) if rel else root
        try:
            it = os.scandir(d)
        except OSError as e:
            acc.skip([rel or "."], "cannot open folder: %s" % e.strerror)
            continue
        with it:
            for en in it:
                r = rel + "/" + en.name if rel else en.name
                try:
                    if en.is_symlink():
                        acc.skip([r], "symbolic link, not followed")
                        continue
                    if en.is_dir(follow_symlinks=False):
                        if r.count("/") < 80:
                            stack.append(r)
                        else:
                            acc.skip([r], "folder nested too deep")
                        continue
                    if not en.is_file(follow_symlinks=False):
                        acc.skip([r], "not a regular file")
                        continue
                    size = en.stat(follow_symlinks=False).st_size
                except OSError as e:
                    acc.skip([r], "cannot read: %s" % e.strerror)
                    continue
                if acc.entries >= MAX_ENTRIES or total > MAX_TOTAL:
                    acc.skip(["(rest of the folder)"], "size or file-count limit reached, remaining files not read")
                    return entries
                acc.entries += 1
                total += size
                for f in acc.names.check([r], size):
                    acc.add(f)
                entries.append((r, size))
    return entries


def make_tasks(kind, root, entries, opts):
    entries = sorted(entries, key=lambda e: -e[1])
    tasks, sizes = [], []
    cur, cur_b = [], 0
    for key, size in entries:
        if cur and (cur_b + size > TASK_BYTES or len(cur) >= TASK_FILES):
            tasks.append((kind, root, cur, opts))
            sizes.append(cur_b)
            cur, cur_b = [], 0
        cur.append(key)
        cur_b += size
    if cur:
        tasks.append((kind, root, cur, opts))
        sizes.append(cur_b)
    return tasks, sizes


def run_tasks(job, tasks, sizes):
    parts = []
    if not tasks:
        return parts
    nfiles = sum(len(t[2]) for t in tasks)
    workers = min(os.cpu_count() or 2, 8 if nfiles < 150000 else 3, len(tasks))
    pending = set(range(len(tasks)))
    if workers > 1 and (sum(sizes) > INLINE_BYTES or nfiles > INLINE_FILES):
        try:
            ctx = multiprocessing.get_context("spawn")
            with concurrent.futures.ProcessPoolExecutor(max_workers=workers, mp_context=ctx) as ex:
                futs = {ex.submit(scan_task, t): i for i, t in enumerate(tasks)}
                for fut in concurrent.futures.as_completed(futs):
                    i = futs[fut]
                    try:
                        res = fut.result()
                    except Exception:
                        continue
                    parts.append(res)
                    pending.discard(i)
                    job.advance(len(tasks[i][2]), sizes[i], len(res["findings"]))
                    if job.cancel.is_set():
                        for f in futs:
                            f.cancel()
                        break
        except Exception:
            pass
    for i in sorted(pending):
        if job.cancel.is_set():
            break
        res = scan_task(tasks[i])
        parts.append(res)
        job.advance(len(tasks[i][2]), sizes[i], len(res["findings"]))
    return parts


def resolve_real(job, chain, isdir=False):
    if job.kind == "folder":
        if len(chain) == 1:
            return os.path.join(job.root, *chain[0].split("/"))
        return None
    if len(chain) != 1:
        return None
    parts = chain[0].split("/")
    size = job.sizes.get(chain[0])
    for base in job.bases:
        for sub in (parts, parts[1:]):
            if not sub:
                continue
            cand = os.path.join(base, *sub)
            if isdir:
                if os.path.isdir(cand):
                    return cand
            elif os.path.isfile(cand) and (size is None or os.path.getsize(cand) == size):
                return cand
    return None


def describe(job, chain, isdir=False, hist=False):
    path = "!/".join(chain)
    real = resolve_real(job, chain, isdir)
    outer = resolve_real(job, chain[:1]) if not real and len(chain) > 1 else None
    fid = job.register(chain, isdir, real, outer)
    leaf = chain[-1].replace("\\", "/").rstrip("/")
    name = leaf.rsplit("/", 1)[-1] or leaf
    folder = path[:len(path) - len(name)].rstrip("/")
    if real:
        full, where = real, "disk"
    elif outer:
        full, where = outer + "!/" + "!/".join(chain[1:]), "nested"
    else:
        full = (job.label if job.uploaded else job.root) + "!/" + path
        where = "upload" if job.uploaded else ("zip" if len(chain) == 1 else "nested")
    can_reveal = bool(real or outer) or job.kind == "folder" or not job.uploaded
    return {"id": fid, "path": path, "name": name, "dir": folder, "full": full, "where": where,
            "real": bool(real), "can_open": not isdir and not hist, "can_reveal": can_reveal}


VENDOR = re.compile(r"(?:^|/)(?:node_modules|site-packages|\.venv|venv|__pycache__|bower_components|\.tox)(?:/|$)")


def build_result(job, parts, elapsed):
    findings, skipped, manual = [], [], []
    ignore = set()
    nfiles = nbytes = nentries = 0
    truncated = False
    for p in parts:
        findings.extend(p["findings"])
        skipped.extend(p["skipped"])
        manual.extend(p["manual"])
        ignore.update(p["ignore"])
        nfiles += p["files"]
        nbytes += p["bytes"]
        nentries += p["entries"]
        truncated = truncated or p["truncated"]
    findings.sort(key=lambda f: (SEV_ORDER[f["sev"]], "!/".join(f["chain"]), f["line"] or 0, f["off"] or 0))
    counts = {k: 0 for k in SEV_ORDER}
    cats = {}
    groups = {}
    vendor_found = 0
    for f in findings:
        key = tuple(f["chain"])
        g = groups.get(key)
        if g is None:
            vend = not f.get("isdir") and bool(VENDOR.search("/".join(f["chain"]).replace("\\", "/")))
            g = groups[key] = {"chain": f["chain"], "items": [], "total": 0, "top": f["sev"], "hist": False,
                               "dir": False, "vendor": vend}
        if g["vendor"]:
            vendor_found += 1
        else:
            counts[f["sev"]] += 1
            cats[f["cat"]] = cats.get(f["cat"], 0) + 1
        g["total"] += 1
        if len(g["items"]) < MAX_ITEMS:
            g["items"].append({k: f[k] for k in ("sev", "cat", "type", "line", "off", "prev")})
        g["hist"] = g["hist"] or bool(f.get("hist"))
        g["dir"] = g["dir"] or bool(f.get("isdir"))
    files, vendor = [], []
    for key, g in groups.items():
        d = describe(job, g["chain"], g["dir"], g["hist"])
        d.update({"top": g["top"], "items": g["items"], "more": g["total"] - len(g["items"]), "hist": g["hist"],
                  "isdir": g["dir"]})
        (vendor if g["vendor"] else files).append(d)
    files.sort(key=lambda x: (SEV_ORDER[x["top"]], x["path"].lower()))
    vendor.sort(key=lambda x: (SEV_ORDER[x["top"]], x["path"].lower()))
    manual_out = []
    for x in manual[:MAX_LIST]:
        d = describe(job, x["chain"])
        manual_out.append({"id": d["id"], "path": d["path"], "full": d["full"], "reason": x["reason"],
                           "can_open": d["can_open"]})
    skipped_out = [{"path": "!/".join(x["chain"]), "reason": x["reason"]} for x in skipped[:MAX_LIST]]
    summary = {"label": job.label, "kind": job.kind, "files": nfiles, "entries": nentries, "bytes": nbytes,
               "elapsed": round(elapsed, 1), "counts": counts, "cats": cats, "flagged": len(files),
               "vendor_files": len(vendor), "vendor_findings": vendor_found,
               "skipped": len(skipped), "manual": len(manual), "truncated": truncated}
    return {"summary": summary, "files": files, "vendor": vendor[:MAX_VENDOR], "skipped": skipped_out,
            "manual": manual_out, "ignore": sorted(ignore)}


def run_job(job):
    t0 = time.time()
    try:
        job.state = "running"
        job.phase = "Listing files"
        opts = {"terms": job.terms, "budget": NESTED_BUDGET}
        main = Acc(opts)
        if job.kind == "zip":
            with zipfile.ZipFile(job.root) as zf:
                entries = plan_zip(zf, main, job)
        else:
            entries = plan_folder(job.root, main, job)
        if job.cancel.is_set():
            job.state = "cancelled"
            return
        tasks, sizes = make_tasks(job.kind, job.root, entries, opts)
        job.total = len(entries)
        job.bytes_total = sum(sizes)
        job.phase = "Scanning"
        parts = run_tasks(job, tasks, sizes)
        if job.cancel.is_set():
            job.state = "cancelled"
            return
        job.phase = "Building the report"
        parts.append(main.export())
        job.result = build_result(job, parts, time.time() - t0)
        job.state = "done"
    except zipfile.BadZipFile:
        job.error = "That zip is damaged and could not be opened."
        job.state = "error"
    except Exception as e:
        job.error = "%s: %s" % (type(e).__name__, e)
        job.state = "error"
    finally:
        close_zips(job.root)


PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="author" content="__CREDIT__">
<meta name="referrer" content="no-referrer">
<title>__APP__</title>
<style>
:root{
  --bg:#edf0f3;--panel:#ffffff;--ink:#101a24;--muted:#566677;--line:#d2dae2;--soft:#f3f5f8;
  --accent:#0a6a62;--accent-ink:#ffffff;
  --crit:#a1123e;--high:#b4460b;--med:#835f00;--low:#3d5c97;
  --crit-bg:#fde8ee;--high-bg:#fdebdd;--med-bg:#fbf1cf;--low-bg:#e7edf8;
  --mono:"Cascadia Mono","Cascadia Code",Consolas,"SF Mono",Menlo,monospace;
}
@media (prefers-color-scheme:dark){
  :root{
    --bg:#0b1118;--panel:#121a23;--ink:#e3ebf3;--muted:#8a9cae;--line:#233140;--soft:#0e151c;
    --accent:#3fd0c0;--accent-ink:#04201d;
    --crit:#ff7f9f;--high:#ff9f5c;--med:#e8c34b;--low:#92b2f2;
    --crit-bg:#3a1520;--high-bg:#38200f;--med-bg:#2e2710;--low-bg:#182640;
  }
}
*{box-sizing:border-box}
html,body{margin:0}
body{background:var(--bg);color:var(--ink);font:15px/1.5 "Segoe UI Variable Text","Segoe UI",system-ui,-apple-system,Roboto,sans-serif}
main{max-width:1040px;margin:0 auto;padding:28px 20px 56px}
.top{display:flex;justify-content:space-between;align-items:baseline;gap:8px 16px;flex-wrap:wrap;margin-bottom:18px}
h1{font-size:28px;line-height:1.15;font-weight:700;letter-spacing:-.02em;margin:0}
.lead{color:var(--muted);margin:6px 0 0;max-width:64ch}
.credit{color:var(--muted);font-size:13px}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:18px}
.pick{display:flex;flex-wrap:wrap;gap:8px}
.btn{font:inherit;font-size:14px;line-height:1.2;min-height:38px;padding:8px 14px;border:1px solid var(--line);background:var(--panel);color:var(--ink);border-radius:6px;cursor:pointer}
.btn:hover{border-color:var(--accent)}
.btn.primary{background:var(--accent);border-color:var(--accent);color:var(--accent-ink)}
.btn.small{min-height:34px;padding:6px 11px;font-size:13px}
.btn:disabled{opacity:.5;cursor:default}
button:focus-visible,input:focus-visible,textarea:focus-visible,summary:focus-visible,#drop:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
input[type=text],input[type=search],textarea{font:inherit;color:var(--ink);background:var(--soft);border:1px solid var(--line);border-radius:6px;padding:8px 10px}
#path{flex:1 1 280px;min-width:0;font:13px var(--mono)}
#drop{margin-top:12px;padding:14px;border:1px dashed var(--line);border-radius:6px;text-align:center;color:var(--muted);cursor:pointer}
#drop:hover,#drop.over{border-color:var(--accent);color:var(--ink)}
.more{margin-top:14px;padding-top:12px;border-top:1px solid var(--line)}
.more summary{cursor:pointer;font-weight:600}
.more textarea{display:block;width:100%;min-height:86px;margin-top:10px;resize:vertical;font:13px/1.45 var(--mono)}
.more input[type=text]{display:block;width:100%;margin-top:10px;font:13px var(--mono)}
.hint{color:var(--muted);font-size:13px;margin:8px 0 0;max-width:72ch}
.check{display:flex;gap:8px;align-items:center;margin-top:10px;font-size:14px}
#status{margin-top:14px}
#status:empty{margin:0}
#status .msg{color:var(--muted)}
#status .err{color:var(--crit);font-weight:600}
.bar{height:6px;background:var(--line);border-radius:3px;overflow:hidden;margin:8px 0 10px}
.bar i{display:block;height:100%;width:0;background:var(--accent);transition:width .2s}
#results{margin-top:22px}
.verdict{background:var(--panel);border:1px solid var(--line);border-left:6px solid var(--accent);border-radius:6px;padding:16px 18px}
.verdict.bad{border-left-color:var(--crit)}
.verdict.warn{border-left-color:var(--med)}
.verdict h2{margin:0 0 4px;font-size:20px;line-height:1.25}
.verdict p{margin:0;color:var(--muted);max-width:72ch}
.stats{display:flex;flex-wrap:wrap;gap:4px 18px;margin-top:10px;color:var(--muted);font-size:13px}
.stats span{overflow-wrap:anywhere}
.tools{position:sticky;top:0;z-index:5;display:flex;flex-wrap:wrap;gap:8px;align-items:center;padding:12px 0;margin-top:8px;background:var(--bg)}
.tools input{flex:1 1 200px;min-width:160px}
.chip{font:inherit;font-size:13px;min-height:32px;border:1px solid var(--line);background:var(--panel);color:var(--ink);border-radius:999px;padding:4px 12px;cursor:pointer}
.chip[aria-pressed=false]{opacity:.45}
.chip.critical{border-color:var(--crit);color:var(--crit)}
.chip.high{border-color:var(--high);color:var(--high)}
.chip.medium{border-color:var(--med);color:var(--med)}
.chip.low{border-color:var(--low);color:var(--low)}
.sep{width:1px;height:22px;background:var(--line)}
.file{background:var(--panel);border:1px solid var(--line);border-left:6px solid var(--low);border-radius:6px;padding:14px 16px;margin:0 0 10px}
.file.critical{border-left-color:var(--crit)}
.file.high{border-left-color:var(--high)}
.file.medium{border-left-color:var(--med)}
.fh{display:flex;flex-wrap:wrap;gap:10px 16px;justify-content:space-between;align-items:flex-start}
.fi{flex:1 1 360px;min-width:0}
.fname{font-weight:650;font-size:16px;overflow-wrap:anywhere}
.fdir{color:var(--muted);font-size:13px;overflow-wrap:anywhere}
.ffull{margin-top:6px;font:12.5px/1.45 var(--mono);color:var(--muted);overflow-wrap:anywhere;user-select:all}
.tags{display:flex;flex-wrap:wrap;gap:6px;margin-top:6px}
.tag{font-size:12px;color:var(--muted);border:1px solid var(--line);border-radius:4px;padding:0 7px;line-height:20px}
.acts{display:flex;flex-wrap:wrap;gap:6px}
.items{margin-top:12px;border-top:1px solid var(--line)}
.item{display:grid;grid-template-columns:78px minmax(130px,230px) 1fr;gap:4px 14px;padding:8px 0;border-bottom:1px solid var(--line);align-items:baseline}
.sev{display:inline-block;padding:1px 9px;border-radius:999px;font-size:12px;font-weight:600;text-align:center}
.sev.critical{background:var(--crit-bg);color:var(--crit)}
.sev.high{background:var(--high-bg);color:var(--high)}
.sev.medium{background:var(--med-bg);color:var(--med)}
.sev.low{background:var(--low-bg);color:var(--low)}
.type{font-weight:600;font-size:14px}
.where{color:var(--muted);font-size:12.5px}
.linkbtn{font:inherit;font-size:12.5px;color:var(--accent);background:none;border:0;padding:0;cursor:pointer;text-decoration:underline}
.prev{font:12.5px/1.45 var(--mono);overflow-wrap:anywhere}
.rest{padding:10px 0 0}
.empty{padding:22px;text-align:center;color:var(--muted);border:1px dashed var(--line);border-radius:6px}
.list>.btn{display:block;margin:6px auto 0}
.sect{margin-top:14px;background:var(--panel);border:1px solid var(--line);border-radius:6px;padding:12px 16px}
.sect summary{cursor:pointer;font-weight:600}
.code{margin:10px 0;padding:10px 12px;background:var(--soft);border:1px solid var(--line);border-radius:6px;font:12.5px/1.5 var(--mono);overflow:auto}
.rows{margin-top:8px;max-height:340px;overflow:auto;font-size:13px}
.rows div{padding:5px 0;border-bottom:1px solid var(--line);overflow-wrap:anywhere}
.rows span{color:var(--muted)}
.vendor{margin-top:12px}
.note{color:var(--muted);font-size:13px;margin:18px 0 0;max-width:80ch}
footer{margin-top:34px;color:var(--muted);font-size:13px}
#toast{position:fixed;left:50%;bottom:24px;transform:translateX(-50%);max-width:min(560px,92vw);background:var(--ink);color:var(--bg);padding:10px 16px;border-radius:6px;font-size:14px;opacity:0;pointer-events:none;transition:opacity .15s;z-index:20}
#toast.show{opacity:1}
@media (max-width:640px){
  .item{grid-template-columns:1fr}
  main{padding:20px 14px 48px}
}
</style>
</head>
<body>
<main>
  <header class="top">
    <div>
      <h1>__APP__</h1>
      <p class="lead">Find passwords, keys, tokens and your personal details in a zip or project folder before it goes to GitHub.</p>
    </div>
    <span class="credit">__CREDIT__</span>
  </header>

  <section class="panel">
    <div class="pick">
      <button class="btn primary" id="bzip" type="button">Choose zip</button>
      <button class="btn" id="bdir" type="button">Choose folder</button>
      <input id="path" type="text" spellcheck="false" autocomplete="off" placeholder="Or paste the path to a zip or folder and press Enter" aria-label="Path to a zip file or folder">
      <button class="btn" id="bscan" type="button">Scan</button>
    </div>
    <div id="drop" tabindex="0" role="button" aria-label="Drop a zip file here to scan it">Drop a .zip here to scan it</div>
    <input id="file" type="file" accept=".zip,application/zip" hidden>

    <details class="more" id="mine">
      <summary>Your own details to look for</summary>
      <textarea id="terms" spellcheck="false" placeholder="One per line: your full name, phone number, email, home address, student ID, anything you do not want public"></textarea>
      <p class="hint">Upper and lower case, spaces, dashes and Bangla digits are ignored when matching. Matches are always shown masked.</p>
      <label class="check"><input type="checkbox" id="remember"> Remember these on this computer</label>
    </details>

    <details class="more">
      <summary>Original project folder (only for zips)</summary>
      <input id="source" type="text" spellcheck="false" autocomplete="off" placeholder="Folder the zip was made from" aria-label="Original project folder">
      <p class="hint">The scanner already looks next to the zip for a matching folder. Set this if your project lives somewhere else, so Go to file opens your real files instead of copies.</p>
    </details>

    <div id="status" aria-live="polite"></div>
  </section>

  <section id="results"></section>

  <footer>
    <p>__APP__ by __CREDIT__. Everything runs on this computer and nothing is sent anywhere.</p>
  </footer>
</main>
<div id="toast" role="status" aria-live="polite"></div>

<script>
const $ = s => document.querySelector(s);
const TOKEN = '__TOKEN__';
const SEV = ['critical', 'high', 'medium', 'low'];
const SEVN = {critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low'};
const CATN = {secret: 'Secrets and keys', personal: 'Personal info', custom: 'Your own details', file: 'Sensitive files', repo: 'Repository'};
const STEP = 40;
const SHOWN_ITEMS = 6;
let job = null, report = null, timer = null, limit = STEP, query = '', ui = null, toastTimer = null;
let sevOn = new Set(SEV), catOn = new Set(Object.keys(CATN));

const fmt = n => Number(n).toLocaleString();
const mb = n => (n / 1048576).toFixed(n >= 104857600 ? 0 : 1);
const plural = (n, w) => fmt(n) + ' ' + w + (n === 1 ? '' : 's');

function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined) n.textContent = text;
  return n;
}

function btn(label, cls, fn, tip) {
  const b = el('button', cls, label);
  b.type = 'button';
  b.onclick = fn;
  if (tip) b.title = tip;
  return b;
}

function toast(msg) {
  const t = $('#toast');
  t.textContent = msg;
  t.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove('show'), 4500);
}

async function api(path, body) {
  const opt = {headers: {'X-Token': TOKEN}};
  if (body !== undefined) {
    opt.method = 'POST';
    opt.headers['Content-Type'] = 'application/json';
    opt.body = JSON.stringify(body);
  }
  let r, d = null;
  try { r = await fetch(path, opt); } catch (e) { throw new Error('Cannot reach the scanner. Is the script still running?'); }
  try { d = await r.json(); } catch (e) {}
  if (!r.ok || !d || d.error) throw new Error((d && d.error) || 'Request failed (' + r.status + ')');
  return d;
}

function busy(on) {
  ['#bzip', '#bdir', '#bscan'].forEach(s => { $(s).disabled = on; });
}

function startStatus(text) {
  const box = $('#status');
  box.replaceChildren();
  const msg = el('div', 'msg', text);
  const bar = el('div', 'bar');
  const fill = el('i');
  bar.appendChild(fill);
  const cancel = btn('Cancel', 'btn small', () => { if (job) api('/api/cancel', {job}).catch(() => {}); });
  box.append(msg, bar, cancel);
  ui = {msg, fill, cancel};
}

function showProgress(p) {
  if (!ui) return;
  const pct = p.total ? Math.min(100, Math.round(p.done / p.total * 100)) : 6;
  ui.fill.style.width = pct + '%';
  let t = p.phase;
  if (p.total) t += ': ' + fmt(p.done) + ' of ' + plural(p.total, 'file');
  if (p.found) t += ', ' + plural(p.found, 'finding') + ' so far';
  ui.msg.textContent = t;
}

function fail(msg, quiet) {
  clearTimeout(timer);
  busy(false);
  ui = null;
  $('#status').replaceChildren(el('div', quiet ? 'msg' : 'err', msg));
}

function terms() {
  return $('#terms').value.split('\n').map(s => s.trim()).filter(Boolean);
}

function saveTerms() {
  try {
    if ($('#remember').checked) localStorage.setItem('zs_terms', $('#terms').value);
    else localStorage.removeItem('zs_terms');
  } catch (e) {}
}

function begin(extra) {
  saveTerms();
  $('#results').replaceChildren();
  report = null;
  busy(true);
  startStatus('Starting...');
  const body = Object.assign({terms: terms(), source: $('#source').value.trim()}, extra);
  api('/api/scan', body).then(d => { job = d.job; poll(); }).catch(e => fail(e.message));
}

function scanPath() {
  const p = $('#path').value.trim();
  if (!p) { toast('Choose a zip or a folder first.'); return; }
  begin({path: p});
}

function pick(kind) {
  busy(true);
  $('#status').replaceChildren(el('div', 'msg', 'Waiting for the file dialog...'));
  api('/api/pick', {kind}).then(d => {
    busy(false);
    $('#status').replaceChildren();
    if (d.path) { $('#path').value = d.path; scanPath(); }
  }).catch(e => { busy(false); $('#status').replaceChildren(); toast(e.message); });
}

function upload(file) {
  if (!/\.zip$/i.test(file.name)) { toast('Drop a .zip file.'); return; }
  $('#results').replaceChildren();
  busy(true);
  startStatus('Uploading ' + file.name + ' (' + mb(file.size) + ' MB)...');
  const xhr = new XMLHttpRequest();
  xhr.open('POST', '/api/upload?name=' + encodeURIComponent(file.name));
  xhr.setRequestHeader('X-Token', TOKEN);
  xhr.upload.onprogress = e => { if (e.lengthComputable && ui) ui.fill.style.width = (e.loaded / e.total * 100) + '%'; };
  xhr.onerror = () => fail('Cannot reach the scanner. Is the script still running?');
  xhr.onload = () => {
    let d = null;
    try { d = JSON.parse(xhr.responseText); } catch (e) {}
    if (xhr.status !== 200 || !d || d.error) { fail((d && d.error) || 'Upload failed.'); return; }
    begin({upload: d.upload});
  };
  xhr.send(file);
}

async function poll() {
  let p;
  try { p = await api('/api/progress?job=' + job); } catch (e) { fail(e.message); return; }
  showProgress(p);
  if (p.state === 'done') {
    try { report = await api('/api/result?job=' + job); } catch (e) { fail(e.message); return; }
    busy(false);
    ui = null;
    $('#status').replaceChildren();
    limit = STEP;
    query = '';
    sevOn = new Set(SEV);
    catOn = new Set(Object.keys(CATN));
    render();
    return;
  }
  if (p.state === 'error') { fail(p.error || 'The scan failed.'); return; }
  if (p.state === 'cancelled') { fail('Scan cancelled.', true); return; }
  timer = setTimeout(poll, 250);
}

function verdict() {
  const s = report.summary, c = s.counts;
  const bad = c.critical + c.high;
  const total = SEV.reduce((a, k) => a + c[k], 0);
  const v = el('div', 'verdict ' + (bad ? 'bad' : total ? 'warn' : 'ok'));
  if (bad) {
    const n = report.files.filter(f => f.top === 'critical' || f.top === 'high').length;
    v.appendChild(el('h2', '', 'Do not upload this yet'));
    v.appendChild(el('p', '', plural(bad, 'serious finding') + ' in ' + plural(n, 'file') + '. Go to each file, remove or replace the value, and change any real password or key that was exposed.'));
  } else if (total) {
    v.appendChild(el('h2', '', 'Review before you upload'));
    v.appendChild(el('p', '', 'Nothing critical was found, but ' + plural(total, 'item') + ' could identify you or your machine.'));
  } else {
    v.appendChild(el('h2', '', 'No known patterns found'));
    v.appendChild(el('p', '', 'This is a pattern check. It cannot read text inside pictures and cannot catch every kind of private data.'));
  }
  const st = el('div', 'stats');
  [plural(s.files, 'file') + ' scanned', mb(s.bytes) + ' MB read', s.elapsed + ' s',
   s.skipped ? plural(s.skipped, 'file') + ' not scanned' : '',
   s.vendor_findings ? plural(s.vendor_findings, 'finding') + ' in dependency folders, listed separately' : '', s.label].filter(Boolean)
    .forEach(t => st.appendChild(el('span', '', t)));
  v.appendChild(st);
  if (s.truncated) v.appendChild(el('p', '', 'There were more findings than this list can hold. It is cut at the most serious ones.'));
  return v;
}

function toggle(set, key, b) {
  if (set.has(key)) set.delete(key); else set.add(key);
  b.setAttribute('aria-pressed', set.has(key));
  limit = STEP;
  paint();
}

function toolbar() {
  const t = el('div', 'tools');
  const c = report.summary.counts, k = report.summary.cats;
  SEV.forEach(s => {
    if (!c[s]) return;
    const b = el('button', 'chip ' + s, SEVN[s] + ' ' + fmt(c[s]));
    b.type = 'button';
    b.setAttribute('aria-pressed', 'true');
    b.onclick = () => toggle(sevOn, s, b);
    t.appendChild(b);
  });
  t.appendChild(el('span', 'sep'));
  Object.keys(CATN).forEach(key => {
    if (!k[key]) return;
    const b = el('button', 'chip', CATN[key] + ' ' + fmt(k[key]));
    b.type = 'button';
    b.setAttribute('aria-pressed', 'true');
    b.onclick = () => toggle(catOn, key, b);
    t.appendChild(b);
  });
  const q = el('input');
  q.type = 'search';
  q.placeholder = 'Filter by file or finding';
  q.setAttribute('aria-label', 'Filter by file or finding');
  q.oninput = () => { query = q.value.trim().toLowerCase(); limit = STEP; paint(); };
  t.appendChild(q);
  t.appendChild(btn('Download report', 'btn small', download));
  return t;
}

function visible(f) {
  const pathHit = query && f.path.toLowerCase().includes(query);
  return f.items.filter(i => sevOn.has(i.sev) && catOn.has(i.cat) &&
    (!query || pathHit || (i.type + ' ' + i.prev).toLowerCase().includes(query)));
}

function paint() {
  const box = $('#list');
  box.replaceChildren();
  const rows = [];
  report.files.forEach(f => { const its = visible(f); if (its.length) rows.push([f, its]); });
  if (!rows.length) { box.appendChild(el('div', 'empty', 'Nothing matches these filters.')); return; }
  rows.slice(0, limit).forEach(r => box.appendChild(card(r[0], r[1])));
  if (rows.length > limit) {
    box.appendChild(btn('Show ' + Math.min(STEP, rows.length - limit) + ' more files (' + fmt(rows.length - limit) + ' left)', 'btn', () => { limit += STEP; paint(); }));
  }
}

function act(f, action, line) {
  api('/api/open', {job, file: f.id, action, line}).then(d => toast(d.message)).catch(e => toast(e.message));
}

function itemRow(f, i) {
  const r = el('div', 'item');
  r.appendChild(el('span', 'sev ' + i.sev, SEVN[i.sev]));
  const w = el('div');
  w.appendChild(el('div', 'type', i.type));
  if (i.line) {
    if (f.can_open) w.appendChild(btn('Go to line ' + fmt(i.line), 'linkbtn', () => act(f, 'open', i.line), 'Open the file at this line'));
    else w.appendChild(el('div', 'where', 'line ' + fmt(i.line)));
  } else if (i.off !== null && i.off !== undefined) {
    w.appendChild(el('div', 'where', 'byte ' + fmt(i.off)));
  }
  r.appendChild(w);
  r.appendChild(el('div', 'prev', i.prev));
  return r;
}

function card(f, its) {
  const top = SEV.find(s => its.some(i => i.sev === s)) || 'low';
  const c = el('article', 'file ' + top);
  const head = el('div', 'fh');
  const info = el('div', 'fi');
  info.appendChild(el('div', 'fname', f.name));
  if (f.dir) info.appendChild(el('div', 'fdir', f.dir));
  const tags = el('div', 'tags');
  if (f.hist) tags.appendChild(el('span', 'tag', 'Stored in git history'));
  if (f.isdir) tags.appendChild(el('span', 'tag', 'Folder'));
  if (f.where === 'zip') tags.appendChild(el('span', 'tag', 'Inside the zip'));
  if (f.where === 'nested') tags.appendChild(el('span', 'tag', 'Inside an archive'));
  if (f.where === 'upload') tags.appendChild(el('span', 'tag', 'Uploaded zip, original folder unknown'));
  if (tags.childNodes.length) info.appendChild(tags);
  info.appendChild(el('div', 'ffull', f.full));
  head.appendChild(info);
  const acts = el('div', 'acts');
  const first = its.find(i => i.line);
  if (f.can_open) acts.appendChild(btn('Go to file', 'btn primary small', () => act(f, 'open', first ? first.line : null),
    'Opens the file at the first finding in VS Code if it is installed, otherwise in Notepad. If your original is not found you get a temporary copy.'));
  if (f.can_reveal) {
    const lbl = f.real ? 'Show in folder' : (report.summary.kind === 'zip' ? 'Show zip in folder' : 'Show archive in folder');
    acts.appendChild(btn(lbl, 'btn small', () => act(f, 'reveal', null)));
  }
  acts.appendChild(btn('Copy path', 'btn small', () => copy(f.full, 'Copied the path.')));
  head.appendChild(acts);
  c.appendChild(head);
  const items = el('div', 'items');
  its.slice(0, SHOWN_ITEMS).forEach(i => items.appendChild(itemRow(f, i)));
  if (its.length > SHOWN_ITEMS) {
    const rest = el('div', 'rest');
    const b = btn('Show ' + (its.length - SHOWN_ITEMS) + ' more findings in this file', 'btn small', () => {
      its.slice(SHOWN_ITEMS).forEach(i => items.insertBefore(itemRow(f, i), rest));
      rest.remove();
    });
    rest.appendChild(b);
    items.appendChild(rest);
  }
  if (f.more) items.appendChild(el('div', 'rest where', plural(f.more, 'more finding') + ' in this file are not listed.'));
  c.appendChild(items);
  return c;
}

function fallbackCopy(text, done) {
  const t = document.createElement('textarea');
  t.value = text;
  t.style.position = 'fixed';
  t.style.opacity = '0';
  document.body.appendChild(t);
  t.select();
  try { document.execCommand('copy'); done(); } catch (e) { toast('Could not copy. Select the text and copy it yourself.'); }
  t.remove();
}

function copy(text, msg) {
  const done = () => toast(msg || 'Copied.');
  if (navigator.clipboard && window.isSecureContext) navigator.clipboard.writeText(text).then(done, () => fallbackCopy(text, done));
  else fallbackCopy(text, done);
}

function download() {
  const blob = new Blob([JSON.stringify(report, null, 2)], {type: 'application/json'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'zip-scan-report.json';
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

function listing(title, rows, withOpen) {
  const d = el('details', 'sect');
  d.appendChild(el('summary', '', title + ' (' + fmt(rows.length) + ')'));
  const box = el('div', 'rows');
  rows.slice(0, 500).forEach(x => {
    const r = el('div');
    r.appendChild(document.createTextNode(x.path));
    r.appendChild(el('span', '', '  ' + x.reason));
    if (withOpen && x.can_open) {
      r.appendChild(document.createTextNode(' '));
      r.appendChild(btn('Go to file', 'linkbtn', () => act(x, 'open', null)));
    }
    box.appendChild(r);
  });
  d.appendChild(box);
  if (rows.length > 500) d.appendChild(el('p', 'hint', 'Showing 500. Download the report for the full list.'));
  return d;
}

function vendorSection() {
  const rows = report.vendor, s = report.summary;
  const d = el('details', 'sect');
  d.appendChild(el('summary', '', 'Inside dependency folders: ' + plural(s.vendor_findings, 'finding') + ' in ' + plural(s.vendor_files, 'file')));
  d.appendChild(el('p', 'hint', 'These are libraries such as node_modules or a virtual environment. They are not your code, they should not be uploaded, and they are not counted above.'));
  const box = el('div', 'vendor');
  d.appendChild(box);
  d.addEventListener('toggle', () => {
    if (!d.open || box.childNodes.length) return;
    rows.slice(0, 100).forEach(f => box.appendChild(card(f, f.items)));
    if (s.vendor_files > 100) box.appendChild(el('p', 'hint', 'Showing the first 100 files. Download the report for the rest.'));
  });
  return d;
}

function extras(root) {
  const r = report;
  if (r.vendor.length) root.appendChild(vendorSection());
  if (r.ignore.length) {
    const d = el('details', 'sect');
    d.appendChild(el('summary', '', 'Suggested .gitignore lines (' + r.ignore.length + ')'));
    d.appendChild(el('pre', 'code', r.ignore.join('\n')));
    d.appendChild(btn('Copy lines', 'btn small', () => copy(r.ignore.join('\n'), 'Copied the .gitignore lines.')));
    root.appendChild(d);
  }
  if (r.manual.length) root.appendChild(listing('Check these by eye', r.manual, true));
  if (r.skipped.length) root.appendChild(listing('Not scanned', r.skipped, false));
  root.appendChild(el('p', 'note', 'Previews are masked. The scan reads text, code, data files, binaries, nested archives, git history, PDFs (best effort) and photo GPS tags. It cannot read text drawn inside pictures or password-protected files.'));
}

function render() {
  const root = $('#results');
  root.replaceChildren();
  root.appendChild(verdict());
  if (report.files.length) {
    root.appendChild(toolbar());
    const box = el('div', 'list');
    box.id = 'list';
    root.appendChild(box);
    paint();
  }
  extras(root);
}

const drop = $('#drop'), fileIn = $('#file');
drop.addEventListener('click', () => fileIn.click());
drop.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); fileIn.click(); } });
['dragenter', 'dragover'].forEach(n => drop.addEventListener(n, e => { e.preventDefault(); drop.classList.add('over'); }));
['dragleave', 'drop'].forEach(n => drop.addEventListener(n, e => { e.preventDefault(); drop.classList.remove('over'); }));
drop.addEventListener('drop', e => { const f = e.dataTransfer.files[0]; if (f) upload(f); });
fileIn.addEventListener('change', () => { if (fileIn.files[0]) upload(fileIn.files[0]); fileIn.value = ''; });
$('#bzip').onclick = () => pick('zip');
$('#bdir').onclick = () => pick('folder');
$('#bscan').onclick = scanPath;
$('#path').addEventListener('keydown', e => { if (e.key === 'Enter') scanPath(); });
try {
  const saved = localStorage.getItem('zs_terms');
  if (saved) { $('#terms').value = saved; $('#remember').checked = true; $('#mine').open = true; }
} catch (e) {}
</script>
</body>
</html>
"""


JOBS = {}
JOBS_LOCK = threading.Lock()
UPLOADS = {}
SAFE_ARG = re.compile(r"^[\w\s.:\\/()\-\[\]+,@~]+$")
VIEWABLE = {".pdf", ".png", ".jpg", ".jpeg", ".jfif", ".gif", ".bmp", ".webp", ".tif", ".tiff", ".ico",
            ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp"}
PICK_CODE = (
    "import sys\n"
    "import tkinter as tk\n"
    "from tkinter import filedialog\n"
    "root = tk.Tk()\n"
    "root.withdraw()\n"
    "try:\n"
    "    root.attributes('-topmost', True)\n"
    "except Exception:\n"
    "    pass\n"
    "root.update()\n"
    "if sys.argv[1] == 'folder':\n"
    "    p = filedialog.askdirectory(title='Choose the project folder to scan')\n"
    "else:\n"
    "    p = filedialog.askopenfilename(title='Choose a zip file', "
    "filetypes=[('Zip archives', '*.zip'), ('All files', '*.*')])\n"
    "sys.stdout.buffer.write((p or '').encode('utf-8'))\n"
)


def cleanup():
    shutil.rmtree(WORKDIR, ignore_errors=True)


def sweep():
    root = tempfile.gettempdir()
    cutoff = time.time() - 24 * 3600
    try:
        names = os.listdir(root)
    except OSError:
        return
    for n in names:
        p = os.path.join(root, n)
        if n.startswith("zipscanner-") and p != WORKDIR:
            try:
                if os.path.getmtime(p) < cutoff:
                    shutil.rmtree(p, ignore_errors=True)
            except OSError:
                pass


def stop(*args):
    raise KeyboardInterrupt


def clean_path(s):
    s = str(s or "").strip().strip('"').strip("'").strip()
    if not s:
        return ""
    return os.path.abspath(os.path.expanduser(os.path.expandvars(s)))


def retire(job):
    job.cancel.set()
    shutil.rmtree(os.path.join(WORKDIR, "open", job.id), ignore_errors=True)
    if job.uploaded:
        try:
            os.remove(job.root)
        except OSError:
            pass


def new_job(kind, root, label, uploaded, terms, source):
    job = Job(secrets.token_hex(6), kind, root, label, uploaded, terms, source)
    with JOBS_LOCK:
        JOBS[job.id] = job
        while len(JOBS) > MAX_JOBS:
            retire(JOBS.pop(next(iter(JOBS))))
    threading.Thread(target=run_job, args=(job,), daemon=True).start()
    return job


def pick(kind):
    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    try:
        r = subprocess.run([sys.executable, "-c", PICK_CODE, "folder" if kind == "folder" else "zip"],
                           capture_output=True, timeout=900, env=env)
    except Exception:
        raise ValueError("The file dialog could not start. Paste the path instead.")
    if r.returncode != 0:
        raise ValueError("The file dialog is not available on this computer. Paste the path instead.")
    return r.stdout.decode("utf-8", "replace").strip()


def spawn(args, **kw):
    subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, **kw)


def reveal(path):
    path = os.path.normpath(path)
    if os.name == "nt":
        if os.path.isdir(path):
            spawn(["explorer", path])
        else:
            spawn('explorer /select,"%s"' % path)
    elif sys.platform == "darwin":
        spawn(["open", "-R", path])
    else:
        spawn(["xdg-open", path if os.path.isdir(path) else os.path.dirname(path)])


def edit(path, line):
    path = os.path.normpath(path)
    if os.path.splitext(path.lower())[1] in VIEWABLE:
        if os.name == "nt":
            os.startfile(path)
        elif sys.platform == "darwin":
            spawn(["open", path])
        else:
            spawn(["xdg-open", path])
        return
    code = shutil.which("code")
    if code and (os.name != "nt" or SAFE_ARG.match(path)):
        flags = {"creationflags": 0x08000000} if os.name == "nt" else {}
        spawn([code, "-g", "%s:%d" % (path, line or 1)], **flags)
    elif os.name == "nt":
        spawn(["notepad.exe", path])
    elif sys.platform == "darwin":
        spawn(["open", "-t", path])
    else:
        spawn(["xdg-open", path])


def read_inner(blob, name):
    kind = sniff(blob[:600])
    bio = io.BytesIO(blob)
    if kind == "zip":
        with zipfile.ZipFile(bio) as z:
            return z.read(name)
    if kind in ("tar", "gz", "bz2", "xz"):
        try:
            with tarfile.open(fileobj=bio, mode="r:*") as t:
                f = t.extractfile(name)
                if f is not None:
                    return f.read()
        except tarfile.TarError:
            pass
        bio.seek(0)
        if kind == "gz":
            z = gzip.GzipFile(fileobj=bio, mode="rb")
        elif kind == "bz2":
            z = bz2.BZ2File(bio)
        elif kind == "xz":
            z = lzma.LZMAFile(bio)
        else:
            z = None
        if z is not None:
            with z:
                return z.read(READ_CAP + 1)
    raise ValueError("The inner archive could not be opened.")


def read_chain(job, chain):
    too_big = ValueError("That file is larger than 1 GB. Open it from your project folder instead.")
    if job.kind == "folder":
        with open(os.path.join(job.root, *chain[0].split("/")), "rb") as f:
            blob = f.read(READ_CAP + 1)
    else:
        with zipfile.ZipFile(job.root) as zf:
            info = zf.getinfo(chain[0])
            if info.file_size > READ_CAP:
                raise too_big
            blob = zf.read(info)
    for name in chain[1:]:
        if len(blob) > READ_CAP:
            raise too_big
        blob = read_inner(blob, name)
    if len(blob) > READ_CAP:
        raise too_big
    return blob


def extract(job, chain):
    data = read_chain(job, chain)
    folder = os.path.join(WORKDIR, "open", job.id)
    os.makedirs(folder, exist_ok=True)
    leaf = chain[-1].replace("\\", "/").rsplit("/", 1)[-1]
    name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", leaf).strip(" .") or "file"
    stem, ext = os.path.splitext(name)
    job.copies += 1
    dest = os.path.join(folder, "%d_%s%s" % (job.copies, stem[:60], ext[:12]))
    with open(dest, "wb") as f:
        f.write(data)
    return dest


def do_open(job, fid, action, line):
    if not isinstance(fid, int) or fid < 0 or fid >= len(job.files):
        raise ValueError("Unknown file.")
    rec = job.files[fid]
    chain = rec["chain"]
    if action == "reveal":
        target = rec["real"] or rec["outer"]
        if not target:
            if job.kind == "folder":
                target = os.path.join(job.root, *chain[0].split("/"))
            elif not job.uploaded:
                target = job.root
        if not target or not os.path.exists(target):
            raise ValueError("The original location is not available because this zip was uploaded from the browser.")
        reveal(target)
        return "Opened the folder in your file manager."
    if action == "open":
        if rec["isdir"]:
            raise ValueError("That is a folder. Use Show in folder.")
        path = rec["real"]
        is_copy = False
        if not path or not os.path.isfile(path):
            path = extract(job, chain)
            is_copy = True
        edit(path, line if isinstance(line, int) and line > 0 else None)
        if is_copy:
            return "Opened a temporary copy. Fix the file in your project folder, not this copy."
        return "Opened the file."
    raise ValueError("Unknown action.")


def render_page():
    return PAGE.replace("__TOKEN__", TOKEN).replace("__CREDIT__", CREDIT).replace("__APP__", APP).encode("utf-8")


class Handler(BaseHTTPRequestHandler):
    server_version = "ZipScanner"

    def log_message(self, *a):
        pass

    def trusted(self):
        host = (self.headers.get("Host") or "").lower()
        if host not in ("127.0.0.1:%d" % PORT, "localhost:%d" % PORT):
            return False
        origin = self.headers.get("Origin")
        return not origin or origin.lower() in ("http://127.0.0.1:%d" % PORT, "http://localhost:%d" % PORT)

    def authed(self):
        got = (self.headers.get("X-Token") or "").encode("utf-8")
        return self.trusted() and secrets.compare_digest(got, TOKEN.encode("utf-8"))

    def send(self, code, body, ctype):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy",
                         "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
                         "connect-src 'self'; base-uri 'none'; form-action 'none'")
        self.end_headers()
        self.wfile.write(body)

    def json(self, code, obj):
        self.send(code, json.dumps(obj).encode("utf-8"), "application/json; charset=utf-8")

    def body(self):
        try:
            n = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            n = 0
        if n <= 0:
            return {}
        if n > 1 << 20:
            raise ValueError("Request too large.")
        d = json.loads(self.rfile.read(n).decode("utf-8"))
        if not isinstance(d, dict):
            raise ValueError("Bad request.")
        return d

    def do_GET(self):
        url = urllib.parse.urlsplit(self.path)
        if url.path == "/":
            if not self.trusted():
                return self.json(403, {"error": "Forbidden"})
            return self.send(200, render_page(), "text/html; charset=utf-8")
        if not self.authed():
            return self.json(403, {"error": "Forbidden"})
        job = JOBS.get((urllib.parse.parse_qs(url.query).get("job") or [""])[0])
        if job is None:
            return self.json(404, {"error": "That scan is no longer available."})
        if url.path == "/api/progress":
            return self.json(200, job.snapshot())
        if url.path == "/api/result":
            if job.state != "done":
                return self.json(409, {"error": "The scan is not finished."})
            return self.json(200, job.result)
        self.json(404, {"error": "Not found"})

    def do_POST(self):
        if not self.authed():
            return self.json(403, {"error": "Forbidden"})
        url = urllib.parse.urlsplit(self.path)
        try:
            if url.path == "/api/upload":
                return self.upload(url)
            d = self.body()
            if url.path == "/api/pick":
                return self.json(200, {"path": pick(d.get("kind"))})
            if url.path == "/api/scan":
                return self.scan(d)
            job = JOBS.get(str(d.get("job")))
            if job is None:
                return self.json(404, {"error": "That scan is no longer available."})
            if url.path == "/api/cancel":
                job.cancel.set()
                return self.json(200, {"ok": True})
            if url.path == "/api/open":
                return self.json(200, {"message": do_open(job, d.get("file"), d.get("action"), d.get("line"))})
        except ValueError as e:
            return self.json(400, {"error": str(e)})
        except Exception as e:
            return self.json(500, {"error": "%s: %s" % (type(e).__name__, e)})
        self.json(404, {"error": "Not found"})

    def upload(self, url):
        name = re.sub(r"[^\w .()\-]", "_", (urllib.parse.parse_qs(url.query).get("name") or ["upload.zip"])[0])[:120]
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length <= 0:
            return self.json(400, {"error": "Empty upload."})
        if length > MAX_UPLOAD:
            return self.json(413, {"error": "That zip is larger than 8 GB."})
        folder = os.path.join(WORKDIR, "uploads")
        os.makedirs(folder, exist_ok=True)
        uid = secrets.token_hex(8)
        dest = os.path.join(folder, uid + ".zip")
        left = length
        with open(dest, "wb") as f:
            while left > 0:
                chunk = self.rfile.read(min(1 << 20, left))
                if not chunk:
                    break
                f.write(chunk)
                left -= len(chunk)
        if left > 0 or not zipfile.is_zipfile(dest):
            os.remove(dest)
            return self.json(400, {"error": "That file is not a valid .zip archive."})
        UPLOADS[uid] = {"path": dest, "name": name or "upload.zip"}
        self.json(200, {"upload": uid})

    def scan(self, d):
        terms = [str(t).strip() for t in (d.get("terms") or []) if str(t).strip()][:60]
        source = clean_path(d.get("source"))
        if d.get("upload"):
            item = UPLOADS.get(str(d["upload"]))
            if not item:
                raise ValueError("That upload is no longer available. Drop the zip again.")
            job = new_job("zip", item["path"], item["name"], True, terms, source)
        else:
            p = clean_path(d.get("path"))
            if not p or not os.path.exists(p):
                raise ValueError("That path does not exist.")
            if os.path.isdir(p):
                job = new_job("folder", p, p, False, terms, "")
            elif zipfile.is_zipfile(p):
                job = new_job("zip", p, p, False, terms, source)
            else:
                raise ValueError("That is not a .zip file or a folder.")
        self.json(200, {"job": job.id})


def text_report(res):
    s = res["summary"]
    c = s["counts"]
    out = ["", "Scanned %s" % s["label"],
           "%d files, %.1f MB, %.1f s, %d not scanned" % (s["files"], s["bytes"] / 1048576, s["elapsed"], s["skipped"]),
           "%d critical, %d high, %d medium, %d low" % (c["critical"], c["high"], c["medium"], c["low"])]
    for f in res["files"]:
        out.append("")
        out.append("%s  [%s]%s" % (f["full"], f["top"], "  (git history)" if f["hist"] else ""))
        for i in f["items"]:
            where = "line %d" % i["line"] if i["line"] else ("byte %d" % i["off"] if i["off"] is not None else "")
            out.append("   %-8s %-36s %-11s %s" % (i["sev"], i["type"][:36], where, i["prev"]))
        if f["more"]:
            out.append("   and %d more" % f["more"])
    if res["ignore"]:
        out += ["", "Suggested .gitignore lines:"] + ["   " + x for x in res["ignore"]]
    if s["vendor_files"]:
        out += ["", "Dependency folders (node_modules, venv and similar): %d files with %d findings, not listed here."
                % (s["vendor_files"], s["vendor_findings"])]
    if res["manual"]:
        out += ["", "Check by eye (not readable automatically): %d files, for example %s" % (len(res["manual"]), res["manual"][0]["path"])]
    if res["skipped"]:
        out += ["", "Not scanned: %d (use --json for the list)" % len(res["skipped"])]
    out += ["", "%s  |  %s" % (APP, CREDIT)]
    return "\n".join(out)


def cli(argv):
    ap = argparse.ArgumentParser(prog="zip_scanner.py",
                                 description="%s by %s. Scan a zip or folder for secrets and personal info." % (APP, CREDIT))
    ap.add_argument("target", help="path to a .zip file or a project folder")
    ap.add_argument("-t", "--term", action="append", default=[],
                    help="a word of your own to look for, such as your name or phone number (repeat for more)")
    ap.add_argument("--source", default="", help="original project folder, so zip findings point at your real files")
    ap.add_argument("--json", metavar="FILE", help="also write the full report as JSON")
    a = ap.parse_args(argv)
    p = clean_path(a.target)
    terms = [t.strip() for t in a.term if t.strip()]
    if os.path.isdir(p):
        job = Job("cli", "folder", p, p, False, terms, "")
    elif os.path.isfile(p) and zipfile.is_zipfile(p):
        job = Job("cli", "zip", p, p, False, terms, clean_path(a.source))
    else:
        print("Not a zip file or a folder: %s" % p, file=sys.stderr)
        return 2
    try:
        sys.stdout.reconfigure(errors="replace")
    except Exception:
        pass
    print("%s  |  %s" % (APP, CREDIT))
    worker = threading.Thread(target=run_job, args=(job,), daemon=True)
    worker.start()
    while worker.is_alive():
        sys.stderr.write("\r  %s: %d of %d files   " % (job.phase, job.done, job.total))
        sys.stderr.flush()
        worker.join(0.5)
    sys.stderr.write("\r" + " " * 70 + "\r")
    if job.state != "done":
        print(job.error or "The scan did not finish.", file=sys.stderr)
        return 2
    res = job.result
    print(text_report(res))
    if a.json:
        with open(a.json, "w", encoding="utf-8") as f:
            json.dump(res, f, indent=2)
        print("Report written to %s" % a.json)
    c = res["summary"]["counts"]
    return 1 if c["critical"] or c["high"] else 0


def main():
    global PORT
    multiprocessing.freeze_support()
    if len(sys.argv) > 1:
        sys.exit(cli(sys.argv[1:]))
    server = None
    for p in PORTS:
        try:
            server = ThreadingHTTPServer((HOST, p), Handler)
            PORT = p
            break
        except OSError:
            continue
    if server is None:
        sys.exit("No free port between %d and %d." % (PORTS[0], PORTS[-1]))
    atexit.register(cleanup)
    sweep()
    for name in ("SIGTERM", "SIGBREAK"):
        sig = getattr(signal, name, None)
        if sig is not None:
            try:
                signal.signal(sig, stop)
            except (ValueError, OSError):
                pass
    url = "http://127.0.0.1:%d" % PORT
    print("%s  |  %s" % (APP, CREDIT))
    print("Running at %s  (press Ctrl+C to stop)" % url)
    threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
