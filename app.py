import secrets

from flask import Flask, abort, g, redirect, render_template, request, session, url_for

from config import Config
from database import get_user_by_id, init_db
from routes.ai import ai_bp
from routes.auth import auth_bp
from routes.dashboard import dashboard_bp
from routes.email_scanner import email_scanner_bp
from routes.file_scanner import file_scanner_bp
from routes.qr_scanner import qr_scanner_bp
from routes.report import report_bp
from routes.url_scanner import url_scanner_bp
from utils import decode_access_token

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config.from_object(Config)
app.config["UPLOAD_FOLDER"] = Config.UPLOAD_FOLDER
app.config["REPORTS_FOLDER"] = Config.REPORTS_FOLDER
app.config["MAX_CONTENT_LENGTH"] = Config.MAX_CONTENT_LENGTH
app.secret_key = Config.SECRET_KEY

app.register_blueprint(auth_bp)
app.register_blueprint(dashboard_bp)
app.register_blueprint(url_scanner_bp)
app.register_blueprint(email_scanner_bp)
app.register_blueprint(file_scanner_bp)
app.register_blueprint(qr_scanner_bp)
app.register_blueprint(report_bp)
app.register_blueprint(ai_bp)


@app.before_request
def load_user():
    init_db()
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(16)

    if (
        request.method == "POST"
        and not request.path.startswith("/static")
        and request.path not in ["/health", "/logout", "/login", "/register", "/forgot-password", "/verify-otp"]
        and request.path.startswith(("/scan-", "/reports", "/dashboard", "/threat-history", "/notifications", "/admin", "/profile"))
    ):
        token = request.form.get("csrf_token")
        if token != session.get("csrf_token"):
            abort(400)

    token = request.cookies.get("access_token")
    if token:
        payload = decode_access_token(token)
        if payload:
            g.user = get_user_by_id(payload.get("user_id"))
            return
    g.user = None

    protected_paths = [
        "/dashboard",
        "/threat-history",
        "/notifications",
        "/scan-url",
        "/scan-email",
        "/scan-file",
        "/scan-qr",
        "/reports",
        "/admin",
    ]
    if request.path in protected_paths or request.path.startswith("/reports/"):
        return redirect(url_for("auth.login"))


@app.context_processor
def inject_globals():
    return {"current_user": g.get("user"), "csrf_token": session.get("csrf_token")}


@app.route("/")
def home():
    if g.user:
        return redirect(url_for("dashboard.dashboard"))
    return redirect(url_for("auth.login"))


@app.route("/health")
def health():
    return {"status": "ok", "service": "SafeLink AI"}


@app.route("/profile")
def profile():
    if not g.user:
        return redirect(url_for("auth.login"))
    return render_template("profile.html")


if __name__ == "__main__":
    init_db()
    app.run(debug=True, host="0.0.0.0", port=5000)
