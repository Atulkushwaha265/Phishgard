from flask import Blueprint, g, render_template

from database import (
    get_admin_stats,
    get_dashboard_stats,
    get_notifications,
    get_scan_history,
)

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/dashboard")
def dashboard():
    stats = get_dashboard_stats(g.user["id"])
    history = get_scan_history(g.user["id"], limit=8)
    notifications = get_notifications(g.user["id"])
    return render_template(
        "dashboard.html",
        stats=stats,
        history=history,
        notifications=notifications,
        title="Security Dashboard",
    )


@dashboard_bp.route("/threat-history")
def threat_history():
    history = get_scan_history(g.user["id"], limit=50)
    return render_template("threat_history.html", history=history, title="Threat History")


@dashboard_bp.route("/notifications")
def notifications():
    rows = get_notifications(g.user["id"])
    return render_template("notifications.html", notifications=rows, title="Notifications")


@dashboard_bp.route("/admin")
def admin_dashboard():
    if g.user["role"] != "admin":
        return render_template("403.html", title="Unauthorized"), 403
    stats = get_admin_stats()
    return render_template("admin.html", stats=stats, title="Admin Dashboard")
