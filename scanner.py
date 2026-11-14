import ipaddress
import logging
import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin, urlparse

import nmap
import requests

log = logging.getLogger("scanner")


class ScanError(Exception):
    pass


MAX_INPUT_LEN = 300
MAX_REDIRECTS = 4
HTTP_BUDGET_SECONDS = 20
USER_AGENT = (
    "Mozilla/5.0 (compatible; WebSecurityAuditor/2.0; +https://github.com)"
)
# فحص أهم 16 منفذ للويب وقواعد البيانات مع تقليل إعادة المحاولة لتجنب الـ Timeout
TARGET_PORTS = "21,22,23,25,80,110,139,443,445,3306,3389,5432,6379,8080,8443,27017"
NMAP_ARGS = f"-sT -p {TARGET_PORTS} -T4 --max-retries 1 --host-timeout 20s -Pn -n"

DOMAIN_RE = re.compile(
    r"(?=.{4,253}\Z)"
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})"
)

MSG_INVALID = "الرجاء إدخال رابط أو دومين صالح، مثل example.com"


def extract_domain(raw):
    if not isinstance(raw, str):
        raise ScanError(MSG_INVALID)
    raw = raw.strip()
    if not raw or len(raw) > MAX_INPUT_LEN or any(ord(c) < 33 for c in raw):
        raise ScanError(MSG_INVALID)
    try:
        parts = urlparse(raw if "://" in raw else "http://" + raw)
        host = parts.hostname
        _ = parts.port
    except ValueError:
        raise ScanError(MSG_INVALID) from None
    if parts.scheme not in ("http", "https") or not host:
        raise ScanError(MSG_INVALID)
    try:
        host = host.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError:
        raise ScanError(MSG_INVALID) from None
    if not DOMAIN_RE.fullmatch(host):
        raise ScanError("الدومين غير صالح. أدخل اسم دومين مثل example.com (عناوين IP غير مسموحة).")
    return host


def is_public_ip(value):
    """True فقط إذا كان العنوان عاماً وقابلاً للوصول من الإنترنت."""
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    blocked = (
        ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_multicast
        or ip.is_link_local or ip.is_unspecified
    )
    return ip.is_global and not blocked


def resolve_public_ip(domain):
    """يحلّ الدومين ويرفض إن أشار أي سجل منه إلى عنوان داخلي أو محجوز."""
    try:
        infos = socket.getaddrinfo(domain, None, proto=socket.IPPROTO_TCP)
    except OSError:
        raise ScanError("تعذّر العثور على هذا الدومين. تأكد من كتابته بشكل صحيح.") from None
    ips = []
    for info in infos:
        addr = info[4][0].split("%")[0]
        if addr not in ips:
            ips.append(addr)
    if not ips:
        raise ScanError("تعذّر العثور على عنوان IP لهذا الدومين.")
    if not all(is_public_ip(a) for a in ips):
        raise ScanError("هذا الدومين يشير إلى عنوان داخلي أو محجوز، ولا يمكن فحصه.")
    ips.sort(key=lambda a: ipaddress.ip_address(a).version)
    return ipaddress.ip_address(ips[0])


PORT_RISK = {
    23: (15, "Telnet بروتوكول غير مشفّر، يجب إغلاقه فوراً."),
    445: (15, "SMB لا ينبغي كشفه على الإنترنت أبداً."),
    3389: (15, "RDP (سطح المكتب البعيد) هدف متكرر لهجمات التخمين."),
    6379: (15, "Redis مكشوف للعامة؛ قد يسمح بالتحكم الكامل بالسيرفر."),
    27017: (15, "MongoDB مكشوفة للعامة؛ خطر تسريب قواعد البيانات."),
    3306: (12, "MySQL مكشوفة للإنترنت؛ يفضّل حصرها محلياً (127.0.0.1)."),
    5432: (12, "PostgreSQL مكشوفة للإنترنت؛ يفضّل تقييد الوصول عبر جدار الحماية."),
    21: (10, "FTP ينقل كلمات المرور دون تشفير؛ استخدم SFTP."),
    139: (10, "NetBIOS يكشف معلومات عن الشبكة الداخلية."),
    110: (5, "POP3 غير مشفّر؛ فضّل POP3S أو IMAPS."),
    25: (3, "SMTP: تأكد من منع الترحيل المفتوح (Open Relay)."),
    8080: (3, "منفذ ويب بديل (8080)؛ تأكد أنه لا يكشف لوحة تحكم أو بيئة تطوير."),
    22: (2, "SSH: قيّد الوصول بالمفاتيح وجدار الحماية."),
}
SAFE_PORTS = {80, 443, 8443}
DEFAULT_PENALTY = 5
PORTS_MAX = 40


def scan_ports(ip):
    ip_obj = ipaddress.ip_address(ip)
    if not is_public_ip(str(ip_obj)):
        raise ScanError("هذا العنوان لا يمكن فحصه.")
    args = NMAP_ARGS + (" -6" if ip_obj.version == 6 else "")
    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=str(ip_obj), arguments=args, timeout=30)
    except Exception:
        log.exception("nmap failed")
        raise ScanError("تعذّر إكمال فحص البورتات حالياً.") from None

    open_ports, penalty = [], 0
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            for port, info in sorted(nm[host][proto].items()):
                if info.get("state") != "open":
                    continue
                cost, note = PORT_RISK.get(
                    port, (0 if port in SAFE_PORTS else DEFAULT_PENALTY, "")
                )
                penalty += cost
                open_ports.append({
                    "port": port,
                    "protocol": proto,
                    "service": info.get("name") or "unknown",
                    "risk": "high" if cost >= 10 else ("medium" if cost > 0 else "low"),
                    "note": note,
                })
    return {
        "ok": True,
        "open": open_ports,
        "score": max(0, PORTS_MAX - penalty),
        "max": PORTS_MAX,
    }


CSP_VALUE = "default-src 'self'; frame-ancestors 'self'; base-uri 'self'; form-action 'self'"
SECURITY_HEADERS = [
    {"name": "Strict-Transport-Security", "weight": 12, "value": "max-age=31536000; includeSubDomains",
     "why": "يُجبر المتصفح على استخدام HTTPS دائماً، فيحمي الزوار من خفض التشفير وسرقة الجلسات."},
    {"name": "Content-Security-Policy", "weight": 14, "value": CSP_VALUE,
     "why": "يحدد المصادر المسموح بتحميلها في صفحتك، وهو خط الدفاع الأهم ضد هجمات XSS وحقن السكربتات."},
    {"name": "X-Frame-Options", "weight": 10, "value": "SAMEORIGIN",
     "why": "يمنع عرض موقعك داخل إطار (iframe) في موقع آخر، فيحميك من هجمات Clickjacking."},
    {"name": "X-Content-Type-Options", "weight": 8, "value": "nosniff",
     "why": "يمنع المتصفح من تخمين نوع الملفات، فيقلل خطر تنفيذ ملف خبيث على أنه سكربت."},
    {"name": "Referrer-Policy", "weight": 6, "value": "strict-origin-when-cross-origin",
     "why": "يتحكم في كمية معلومات الرابط المُرسَلة إلى المواقع الأخرى، فيحفظ خصوصية زوارك."},
    {"name": "Permissions-Policy", "weight": 5, "value": "geolocation=(), microphone=(), camera=()",
     "why": "يحدد ميزات المتصفح (الكاميرا، الميكروفون، الموقع) التي يُسمح للصفحة باستخدامها."},
    {"name": "X-Powered-By (إخفاء البصمة)", "weight": 5, "value": "off", "leak_header": "x-powered-by",
     "why": "إخفاء هذه الترويسة يمنع المهاجمين من معرفة إصدار لغة البرمجة أو الإطار المستخدم (مثل PHP أو Express)."},
]
HEADERS_MAX = sum(h["weight"] for h in SECURITY_HEADERS)  # = 60


def _peer_is_public(resp):
    try:
        sock = getattr(resp.raw._connection, "sock", None)
        if sock is None:
            return True
        peer = sock.getpeername()[0]
        return is_public_ip(peer.split("%")[0])
    except Exception:
        return False


def _fetch(url, deadline):
    session = requests.Session()
    try:
        for _ in range(MAX_REDIRECTS + 1):
            if time.monotonic() > deadline:
                raise ScanError("انتهت مهلة جلب ترويسات الموقع.")
            parts = urlparse(url)
            try:
                host = extract_domain(parts.hostname or "")
                port_ok = parts.port in (None, 80, 443, 8080, 8443)
            except (ScanError, ValueError):
                raise ScanError("حوّل الموقع الطلب إلى عنوان غير مسموح بفحصه.") from None
            if parts.scheme not in ("http", "https") or not port_ok:
                raise ScanError("حوّل الموقع الطلب إلى عنوان غير مسموح بفحصه.")
            resolve_public_ip(host)
            resp = session.get(
                url, headers={"User-Agent": USER_AGENT}, timeout=(3, 6),
                allow_redirects=False, stream=True, verify=True,
            )
            try:
                if not _peer_is_public(resp):
                    raise ScanError("هذا الموقع يشير إلى عنوان داخلي أو محجوز.")
                if resp.is_redirect:
                    url = urljoin(url, resp.headers.get("Location", ""))
                    continue
                return url, resp.status_code, dict(resp.headers)
            finally:
                resp.close()
        raise ScanError("الموقع يحوّل الطلب عدداً كبيراً من المرات.")
    finally:
        session.close()


def check_headers(domain):
    deadline = time.monotonic() + HTTP_BUDGET_SECONDS
    result = None
    for scheme in ("https", "http"):
        try:
            result = _fetch(f"{scheme}://{domain}/", deadline)
            break
        except requests.RequestException:
            continue
    if result is None:
        raise ScanError("تعذّر الاتصال بالموقع عبر HTTP أو HTTPS لفحص الترويسات.")

    final_url, status, raw = result
    is_https = final_url.startswith("https://")
    headers = {k.lower(): v for k, v in raw.items()}
    items, earned = [], 0

    for spec in SECURITY_HEADERS:
        if "leak_header" in spec:
            leaked_val = headers.get(spec["leak_header"])
            present = leaked_val is None
            display_val = "مخفي (آمن)" if present else f"مكشوف: {leaked_val}"
            nginx_fix = "fastcgi_hide_header X-Powered-By; server_tokens off;"
            apache_fix = "Header unset X-Powered-By"
        else:
            value = headers.get(spec["name"].lower())
            if spec["name"] == "Strict-Transport-Security" and not is_https:
                value = None
            elif (value is None and spec["name"] == "X-Frame-Options"
                  and "frame-ancestors" in headers.get("content-security-policy", "").lower()):
                value = "(مغطّى عبر CSP: frame-ancestors)"
            present = value is not None
            display_val = value[:200] if present else None
            nginx_fix = f'add_header {spec["name"]} "{spec["value"]}" always;'
            apache_fix = f'Header always set {spec["name"]} "{spec["value"]}"'

        earned += spec["weight"] if present else 0
        items.append({
            "name": spec["name"],
            "present": present,
            "value": display_val,
            "why": spec["why"],
            "nginx": nginx_fix,
            "apache": apache_fix,
        })

    return {
        "ok": True,
        "items": items,
        "present": sum(i["present"] for i in items),
        "total": len(items),
        "https": is_https,
        "status": status,
        "score": earned,
        "max": HEADERS_MAX,
    }


def _safe(fn, *args):
    try:
        return fn(*args)
    except ScanError as exc:
        return {"ok": False, "error": str(exc)}
    except Exception:
        log.exception("unexpected scan error")
        return {"ok": False, "error": "حدث خطأ أثناء هذا الجزء من الفحص."}


def _grade(score):
    if score >= 90:
        return "A", "ممتاز", "good"
    if score >= 75:
        return "B", "جيد", "good"
    if score >= 60:
        return "C", "متوسط", "warn"
    if score >= 40:
        return "D", "ضعيف", "bad"
    return "F", "حرج", "bad"


def run_audit(raw_target):
    domain = extract_domain(raw_target)
    ip = str(resolve_public_ip(domain))

    with ThreadPoolExecutor(max_workers=2) as pool:
        f_ports = pool.submit(_safe, scan_ports, ip)
        f_heads = pool.submit(_safe, check_headers, domain)
        ports, headers = f_ports.result(), f_heads.result()

    earned = possible = 0
    for part in (ports, headers):
        if part.get("ok"):
            earned += part["score"]
            possible += part["max"]

    score = {"value": None, "grade": "—", "label": "غير متاح", "level": "warn"}
    if possible:
        value = round(earned * 100 / possible)
        # سقف التقييم عند غياب HTTPS أو فشل أحد الفحصين لمنع تقييم A مضلل
        if headers.get("ok") and not headers.get("https"):
            value = min(value, 65)
        if not (ports.get("ok") and headers.get("ok")):
            value = min(value, 70)
        grade, label, level = _grade(value)
        score = {"value": value, "grade": grade, "label": label, "level": level}

    return {"domain": domain, "ip": ip, "score": score, "ports": ports, "headers": headers}
