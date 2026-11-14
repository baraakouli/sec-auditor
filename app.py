import logging
import os
import secrets

from flask import Flask, g, jsonify, render_template, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.exceptions import HTTPException
from werkzeug.middleware.proxy_fix import ProxyFix

from scanner import ScanError, run_audit

logging.basicConfig(level=logging.INFO)

app = Flask(__name__, static_folder=None)
app.config.update(DEBUG=False, TESTING=False, PROPAGATE_EXCEPTIONS=False,
                  MAX_CONTENT_LENGTH=2048) 

app.wsgi_app = ProxyFix(app.wsgi_app, x_for=int(os.environ.get("PROXY_HOPS", "1")))

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["60 per minute"],
    storage_uri="memory://",
)

FRAME_ANCESTORS = os.environ.get("FRAME_ANCESTORS", "'self' https://huggingface.co")


@app.before_request
def _make_nonce():
    g.nonce = secrets.token_urlsafe(16)


@app.after_request
def _security_headers(resp):
    nonce = g.get("nonce") or secrets.token_urlsafe(16)
    resp.headers["Content-Security-Policy"] = "; ".join([
        "default-src 'none'",
        f"script-src 'nonce-{nonce}' https://cdn.tailwindcss.com",
        "style-src 'unsafe-inline' https://fonts.googleapis.com", 
        "font-src https://fonts.gstatic.com",
        "img-src 'self' data:",
        "connect-src 'self'",
        "base-uri 'none'",
        "form-action 'self'",
        f"frame-ancestors {FRAME_ANCESTORS}",
    ])
    resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=(), payment=()"
    resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.get("/")
def index():
    return render_template("index.html", nonce=g.nonce)


@app.get("/healthz")
@limiter.exempt
def healthz():
    return jsonify(status="ok")


@app.post("/scan")
@limiter.limit("5 per minute")
def scan():
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or not isinstance(data.get("target"), str):
        return jsonify(error="الرجاء إدخال رابط أو دومين صالح."), 400
    try:
        return jsonify(run_audit(data["target"]))
    except ScanError as exc:
        return jsonify(error=str(exc)), 422


HTTP_MESSAGES = {
    400: "الطلب غير صالح.",
    404: "الصفحة المطلوبة غير موجودة.",
    405: "هذه الطريقة غير مسموحة لهذا المسار.",
    413: "حجم الطلب كبير جداً.",
    415: "نوع المحتوى غير مدعوم.",
    429: "تجاوزت الحد المسموح (5 فحوصات في الدقيقة). انتظر قليلاً ثم أعد المحاولة.",
}


@app.errorhandler(HTTPException)
def handle_http_error(exc):
    code = exc.code or 500
    return jsonify(error=HTTP_MESSAGES.get(code, "تعذّر إكمال الطلب.")), code


@app.errorhandler(Exception)
def handle_unexpected(exc):
    app.logger.exception("Unhandled error")  # التفاصيل في سجلات السيرفر فقط
    return jsonify(error="حدث خطأ غير متوقع. يرجى المحاولة لاحقاً."), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=7860, debug=False)
