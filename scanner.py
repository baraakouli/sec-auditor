import ipaddress
import logging
import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin, urlparse

import nmap
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
log = logging.getLogger("scanner")


class ScanError(Exception):
    pass


MAX_INPUT_LEN = 300
MAX_REDIRECTS = 4
HTTP_BUDGET_SECONDS = 20
USER_AGENT = (
    "Mozilla/5.0 (compatible; WebSecurityAuditor/2.1; +https://github.com)"
)
# أهم 10 منافذ مع ضبط RTT لمنع تعليق الفحص عند وجود جدار ناري
TARGET_PORTS = "21,22,23,25,80,443,3306,3389,8080,8443"
NMAP_ARGS = (
    f"-sT -p {TARGET_PORTS} -T4 --max-retries 1 "
    "--initial-rtt-timeout 500ms --max-rtt-timeout 1200ms "
    "--host-timeout 15s -Pn -n"
)

DOMAIN_RE = re.compile(
    r"(?=.{4,253}\Z)"
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})"
)
VERSION_RE = re.compile(r"\d+\.\d+")

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
    3389: (15, "RDP (سطح المكتب البعيد) هدف متكرر لهجمات التخمين."),
    3306: (12, "MySQL مكشوفة للإنترنت؛ يفضّل حصرها محلياً (127.0.0.1)."),
    21: (10, "FTP ينقل كلمات المرور دون تشفير؛ استخدم SFTP."),
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
        nm.scan(hosts=str(ip_obj), arguments=args, timeout=25)
    except Exception:
        log.exception("nmap failed")
        raise ScanError("تعذّر إكمال فحص البورتات حالياً.") from None

    hosts = nm.all_hosts()
    if not hosts or not nm[hosts[0]].all_protocols():
        raise ScanError("انتهت مهلة فحص البورتات أو أن جدار الحماية يحجب الفحص.")

    open_ports, penalty, filtered_count, total_scanned = [], 0, 0, 0
    for host in hosts:
        for proto in nm[host].all_protocols():
            for port, info in sorted(nm[host][proto].items()):
                total_scanned += 1
                state = info.get("state")
                if state == "filtered":
                    filtered_count += 1
                    continue
                if state != "open":
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

    # إذا كانت جميع البورتات مفلترة بالكامل، نعتبر الفحص محجوباً وليس "0 بورت مفتوح"
    if total_scanned > 0 and filtered_count == total_scanned:
        raise ScanError("جدار الحماية الخاص بالموقع يحجب فحص البورتات (Filtered).")

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
    {"name": "إخفاء بصمة السيرفر (Server / X-Powered-By)", "weight": 5, "value": "off", "is_leak_check": True,
     "why": "إخفاء إصدارات السيرفر ولغة البرمجة يمنع المهاجمين من البحث عن ثغرات جاهزة (CVEs) لإصدارك."},
]
HEADERS_MAX = sum(h["weight"] for h in SECURITY_HEADERS)  # = 60


def _peer_is_public(resp):
    try:
        peer = resp.raw._connection.sock.getpeername()[0]
    except Exception:
        return True
    return is_public_ip(peer.split("%")[0])


def _fetch(url, deadline, verify_ssl=True):
    session = requests.Session()
    checked_hosts = set()
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
            if host not in checked_hosts:
                resolve_public_ip(host)
                checked_hosts.add(host)
            resp = session.get(
                url, headers={"User-Agent": USER_AGENT}, timeout=(4, 7),
                allow_redirects=False, stream=True, verify=verify_ssl,
            )
            try:
                if not _peer_is_public(resp):
                    raise ScanError("هذا الموقع يشير إلى عنوان داخلي أو محجوز.")
                if resp.is_redirect and "Location" in resp.headers:
                    url = urljoin(url, resp.headers["Location"])
                    continue
                return url, resp.status_code, dict(resp.headers), verify_ssl
            finally:
                resp.close()
        raise ScanError("الموقع يحوّل الطلب عدداً كبيراً من المرات.")
    finally:
        session.close()


def _validate_header(name, value, headers, is_https):
    """يتحقق من وجود الترويسة وصحة قيمتها أمنياً."""
    if name == "Strict-Transport-Security":
        if not is_https or not value:
            return False, None
        if "max-age=0" in value.lower().replace(" ", ""):
            return False, None
        return True, value[:200]

    if name == "X-Frame-Options":
        if value and any(k in value.lower() for k in ("deny", "sameorigin")):
            return True, value[:200]
        if "frame-ancestors" in headers.get("content-security-policy", "").lower():
            return True, "(مغطّى عبر CSP: frame-ancestors)"
        return False, None

    if name == "X-Content-Type-Options":
        if value and "nosniff" in value.lower():
            return True, value[:200]
        return False, None

    if value is not None and value.strip():
        return True, value[:200]
    return False, None


def check_headers(domain):
    result = None
    # المحاولة بـ HTTPS ثم HTTP، مع التعامل مع الشهادات المنتهية دون إيقاف الفحص
    for scheme, verify in (("https", True), ("http", True), ("https", False)):
        deadline = time.monotonic() + 10
        try:
            result = _fetch(f"{scheme}://{domain}/", deadline, verify_ssl=verify)
            break
        except (requests.RequestException, ScanError) as exc:
            if isinstance(exc, ScanError) and "داخلي أو محجوز" in str(exc):
                raise
            continue

    if result is None:
        raise ScanError("تعذّر الاتصال بالموقع عبر HTTP أو HTTPS لفحص الترويسات.")

    final_url, status, raw, ssl_verified = result
    is_https = final_url.startswith("https://") and ssl_verified
    headers = {k.lower(): v for k, v in raw.items()}
    items, earned = [], 0

    for spec in SECURITY_HEADERS:
        if spec.get("is_leak_check"):
            x_pow = headers.get("x-powered-by")
            srv = headers.get("server", "")
            srv_leaks = bool(VERSION_RE.search(srv))
            leaks = []
            if x_pow:
                leaks.append(f"X-Powered-By: {x_pow}")
            if srv_leaks:
                leaks.append(f"Server: {srv}")
            present = len(leaks) == 0
            display_val = "مخفي (آمن)" if present else f"مكشوف ({' | '.join(leaks)[:180]})"
            nginx_fix = "server_tokens off; fastcgi_hide_header X-Powered-By;"
            apache_fix = "ServerTokens Prod\nHeader unset X-Powered-By"
        else:
            raw_val = headers.get(spec["name"].lower())
            present, display_val = _validate_header(
                spec["name"], raw_val, headers, is_https
            )
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

    # استكمال منطقي: إذا نجح الاتصال بالويب بينما لم يظهر المنفذ في Nmap، نضيفه تلقائياً
    if ports.get("ok") and headers.get("ok") and not ports.get("open"):
        web_port = 443 if headers.get("https") else 80
        ports["open"].append({
            "port": web_port,
            "protocol": "tcp",
            "service": "https" if web_port == 443 else "http",
            "risk": "low",
            "note": "",
        })

    earned = possible = 0
    for part in (ports, headers):
        if part.get("ok"):
            earned += part["score"]
            possible += part["max"]

    score = {"value": None, "grade": "—", "label": "غير متاح", "level": "warn"}
    if possible:
        value = round(earned * 100 / possible)
        # إذا كان الموقع يعمل بدون HTTPS صالح، السقف الأعلى للتقييم 65 (C)
        if headers.get("ok") and not headers.get("https"):
            value = min(value, 65)
        # إذا فشل الاتصال بالويب كلياً ونجح فحص البورتات فقط، السقف الأعلى 40 (D)
        if not headers.get("ok"):
            value = min(value, 40)
        grade, label, level = _grade(value)
        score = {"value": value, "grade": grade, "label": label, "level": level}

    return {"domain": domain, "ip": ip, "score": score, "ports": ports, "headers": headers}
