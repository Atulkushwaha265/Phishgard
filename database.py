import json
import os
import sqlite3

from flask import g
from werkzeug.security import check_password_hash, generate_password_hash

from config import Config

DB_PATH = Config.DB_PATH


def get_db():
    if "db" not in g:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        g.db = conn
    return g.db


def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            full_name TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS user_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            scan_type TEXT NOT NULL,
            entity TEXT NOT NULL,
            result TEXT NOT NULL,
            threat_level TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            details TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS url_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            url TEXT NOT NULL,
            result TEXT NOT NULL,
            threat_level TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            details TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS email_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            sender TEXT,
            subject TEXT,
            body TEXT,
            links TEXT,
            result TEXT NOT NULL,
            threat_level TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            details TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS file_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            filename TEXT NOT NULL,
            file_path TEXT NOT NULL,
            result TEXT NOT NULL,
            threat_level TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            details TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS qr_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            filename TEXT NOT NULL,
            decoded_url TEXT,
            result TEXT NOT NULL,
            threat_level TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            details TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            message TEXT NOT NULL,
            severity TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS security_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            report_type TEXT NOT NULL,
            title TEXT NOT NULL,
            report_path TEXT NOT NULL,
            summary TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS activity_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            action TEXT NOT NULL,
            details TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    conn.commit()

    cursor = conn.execute("SELECT id FROM users LIMIT 1")
    if cursor.fetchone() is None:
        create_user("admin@phishgard.com", "Admin@123", "System Administrator", role="admin")

    conn.close()


def create_user(email, password, full_name, role="user"):
    conn = sqlite3.connect(DB_PATH)
    hashed = generate_password_hash(password)
    cursor = conn.execute(
        "INSERT INTO users (email, password, full_name, role) VALUES (?, ?, ?, ?)",
        (email.lower(), hashed, full_name, role),
    )
    user_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return user_id


def authenticate_user(email, password):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    user = conn.execute("SELECT * FROM users WHERE email = ?", (email.lower(),)).fetchone()
    conn.close()
    if user and check_password_hash(user["password"], password):
        return dict(user)
    return None


def get_user_by_id(user_id):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    return dict(user) if user else None


def get_user_by_email(email):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    user = conn.execute("SELECT * FROM users WHERE email = ?", (email.lower(),)).fetchone()
    conn.close()
    return dict(user) if user else None


def save_scan_history(user_id, scan_type, entity, result, threat_level, risk_score, details):
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT INTO scan_history (user_id, scan_type, entity, result, threat_level, risk_score, details) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (user_id, scan_type, entity, result, threat_level, risk_score, json.dumps(details)),
    )
    conn.commit()
    conn.close()


def save_url_scan(user_id, url, result, threat_level, risk_score, details):
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT INTO url_scans (user_id, url, result, threat_level, risk_score, details) VALUES (?, ?, ?, ?, ?, ?)",
        (user_id, url, result, threat_level, risk_score, json.dumps(details)),
    )
    conn.commit()
    conn.close()


def save_email_scan(user_id, sender, subject, body, links, result, threat_level, risk_score, details):
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT INTO email_scans (user_id, sender, subject, body, links, result, threat_level, risk_score, details) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (user_id, sender, subject, body, links, result, threat_level, risk_score, json.dumps(details)),
    )
    conn.commit()
    conn.close()


def save_file_scan(user_id, filename, file_path, result, threat_level, risk_score, details):
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT INTO file_scans (user_id, filename, file_path, result, threat_level, risk_score, details) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (user_id, filename, file_path, result, threat_level, risk_score, json.dumps(details)),
    )
    conn.commit()
    conn.close()


def save_qr_scan(user_id, filename, decoded_url, result, threat_level, risk_score, details):
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT INTO qr_scans (user_id, filename, decoded_url, result, threat_level, risk_score, details) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (user_id, filename, decoded_url, result, threat_level, risk_score, json.dumps(details)),
    )
    conn.commit()
    conn.close()


def add_notification(user_id, title, message, severity):
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT INTO notifications (user_id, title, message, severity) VALUES (?, ?, ?, ?)",
        (user_id, title, message, severity),
    )
    conn.commit()
    conn.close()


def get_notifications(user_id):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT 8",
        (user_id,),
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def save_security_report(user_id, report_type, title, report_path, summary):
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT INTO security_reports (user_id, report_type, title, report_path, summary) VALUES (?, ?, ?, ?, ?)",
        (user_id, report_type, title, report_path, summary),
    )
    conn.commit()
    conn.close()


def get_security_reports(user_id):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM security_reports WHERE user_id = ? ORDER BY created_at DESC",
        (user_id,),
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def log_activity(user_id, action, details):
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT INTO activity_logs (user_id, action, details) VALUES (?, ?, ?)",
        (user_id, action, details),
    )
    conn.commit()
    conn.close()


def get_scan_history(user_id, limit=10):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM scan_history WHERE user_id = ? ORDER BY created_at DESC LIMIT ?",
        (user_id, limit),
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_dashboard_stats(user_id):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    stats = {}
    stats["safe_links"] = conn.execute("SELECT COUNT(*) AS c FROM scan_history WHERE user_id = ? AND threat_level = 'Safe'", (user_id,)).fetchone()["c"]
    stats["dangerous_links"] = conn.execute("SELECT COUNT(*) AS c FROM scan_history WHERE user_id = ? AND threat_level IN ('High', 'Critical')", (user_id,)).fetchone()["c"]
    stats["emails_scanned"] = conn.execute("SELECT COUNT(*) AS c FROM email_scans WHERE user_id = ?", (user_id,)).fetchone()["c"]
    stats["files_scanned"] = conn.execute("SELECT COUNT(*) AS c FROM file_scans WHERE user_id = ?", (user_id,)).fetchone()["c"]
    stats["qr_scanned"] = conn.execute("SELECT COUNT(*) AS c FROM qr_scans WHERE user_id = ?", (user_id,)).fetchone()["c"]
    stats["security_score"] = max(60, 100 - (stats["dangerous_links"] * 8))
    conn.close()
    return stats


def get_admin_stats():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    users = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
    scans = conn.execute("SELECT COUNT(*) AS c FROM scan_history").fetchone()["c"]
    dangerous_domains = conn.execute(
        "SELECT entity AS domain, COUNT(*) AS count FROM scan_history WHERE threat_level IN ('High', 'Critical') GROUP BY entity ORDER BY count DESC LIMIT 10"
    ).fetchall()
    attack_types = conn.execute(
        "SELECT scan_type AS attack, COUNT(*) AS count FROM scan_history GROUP BY scan_type ORDER BY count DESC LIMIT 10"
    ).fetchall()
    conn.close()
    return {
        "users": users,
        "scans": scans,
        "dangerous_domains": [dict(row) for row in dangerous_domains],
        "attack_types": [dict(row) for row in attack_types],
    }
