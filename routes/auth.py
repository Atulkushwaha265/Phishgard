import secrets
import smtplib
from datetime import datetime, timezone
from email.message import EmailMessage

from flask import Blueprint, flash, redirect, render_template, request, session, url_for

from config import Config
from database import authenticate_user, create_user, get_user_by_email, log_activity
from utils import create_access_token

auth_bp = Blueprint("auth", __name__)


def generate_otp() -> str:
    return str(secrets.randbelow(900000) + 100000)


def send_otp_email(email: str, otp: str) -> bool:
    if not Config.EMAIL_OTP_ENABLED:
        return False

    host = Config.SMTP_HOST
    port = Config.SMTP_PORT
    username = Config.SMTP_USERNAME
    password = Config.SMTP_PASSWORD
    from_email = Config.SMTP_FROM_EMAIL

    if not host or not username or not password:
        return False

    message = EmailMessage()
    message["Subject"] = "SafeLink AI verification code"
    message["From"] = from_email
    message["To"] = email
    message.add_alternative(
         f"""
        <!DOCTYPE html>
        <html>
        <body style="margin:0; padding:0; background:#f4f7fb; font-family:Arial,sans-serif;">

            <div style="max-width:600px; margin:40px auto; background:white;
                    border-radius:12px; padding:35px;">

                <h2 style="text-align:center; color:#1e3a8a;">
                    SafeLink AI
                </h2>

                <h3 style="text-align:center;">
                    Email Verification
                </h3>

                <p>Hello,</p>

                <p>
                    We received a request to verify your email address.
                    Use the verification code below:
                </p>

                <div style="text-align:center; margin:30px 0;">
                    <span style="display:inline-block; padding:15px 30px;
                                 background:#eef2ff; border-radius:8px;
                                 font-size:32px; font-weight:bold;
                                 letter-spacing:6px; color:#1e3a8a;">
                        {otp}
                    </span>
                </div>

                <p>
                    This verification code will expire in
                    <strong>10 minutes</strong>.
                </p>

                <p>
                    If you did not request this code, you can safely ignore
                    this email.
                </p>

                <hr>

                <p style="text-align:center; color:#777; font-size:12px;">
                    © 2026 SafeLink AI. All rights reserved.
                </p>

            </div>

        </body>
        </html>
        """,
        subtype="html"
    )
    try:
        with smtplib.SMTP(host, port) as smtp_server:
            smtp_server.starttls()
            smtp_server.login(username, password)
            smtp_server.send_message(message)
        return True
    except smtplib.SMTPException as exc:
        print(f"OTP email failed: {exc}")
        return False


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = authenticate_user(email, password)
        if user:
            otp = generate_otp()
            session["pending_login"] = {
                "user_id": user["id"],
                "email": user["email"],
                "otp": otp,
            }
            session["otp_created_at"] = datetime.now(timezone.utc).isoformat()
            delivered = send_otp_email(user["email"], otp)
            if delivered:
                flash("A verification code has been sent to your email. Please enter it below.", "info")
            else:
                flash("SMTP credentials are not configured yet. Please set SMTP_USERNAME and SMTP_PASSWORD to enable email delivery.", "warning")
            return redirect(url_for("auth.verify_otp"))
        flash("Invalid login credentials", "danger")
    return render_template("auth/login.html")


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if not full_name or not email or not password:
            flash("Please fill out every field", "warning")
        elif get_user_by_email(email):
            flash("That email already exists", "warning")
        else:
            user_id = create_user(email, password, full_name, role="user")
            log_activity(user_id, "register", "New account created")
            flash("Registration successful. You may now sign in.", "success")
            return redirect(url_for("auth.login"))
    return render_template("auth/register.html")


@auth_bp.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():
    pending = session.get("pending_login")
    if not pending:
        return redirect(url_for("auth.login"))

    created_at = session.get("otp_created_at")
    if created_at:
        try:
            if (datetime.now(timezone.utc) - datetime.fromisoformat(created_at.replace("Z", "+00:00"))).total_seconds() > 600:
                session.pop("pending_login", None)
                session.pop("otp_created_at", None)
                flash("The verification code expired. Please sign in again.", "warning")
                return redirect(url_for("auth.login"))
        except ValueError:
            pass

    if request.method == "POST":
        submitted_otp = request.form.get("otp", "").strip()
        if submitted_otp == pending.get("otp"):
            user = get_user_by_email(pending["email"])
            if user:
                token = create_access_token(user)
                log_activity(user["id"], "login", "User logged in after OTP verification")
                response = redirect(url_for("dashboard.dashboard"))
                response.set_cookie("access_token", token, httponly=True, samesite="Lax")
                session.pop("pending_login", None)
                session.pop("otp_created_at", None)
                flash("Welcome back. Your security dashboard is ready.", "success")
                return response

        flash("The verification code is invalid. Please try again.", "danger")

    return render_template("auth/verify-otp.html", email=pending.get("email"))


@auth_bp.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        if email:
            flash(f"Password reset instructions were prepared for {email}.", "info")
            return redirect(url_for("auth.login"))
    return render_template("auth/forgot-password.html")


@auth_bp.route("/logout")
def logout():
    response = redirect(url_for("auth.login"))
    response.delete_cookie("access_token")
    session.clear()
    flash("You have been logged out", "info")
    return response
