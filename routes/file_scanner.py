import os

from flask import Blueprint, current_app, g, render_template, request
from werkzeug.utils import secure_filename

from database import log_activity, save_file_scan, save_scan_history

file_scanner_bp = Blueprint("file_scanner", __name__)


def analyze_file(filename, file_size):
    ext = os.path.splitext(filename)[1].lower()
    score = 10
    details = {"extension": ext, "size_bytes": file_size, "suspicious_extensions": []}
    if ext in {".exe", ".apk", ".scr", ".bat", ".cmd"}:
        score += 55
        details["suspicious_extensions"].append(ext)
    elif ext in {".docm", ".xlsm", ".js", ".zip"}:
        score += 25
        details["suspicious_extensions"].append(ext)
    if file_size > 5 * 1024 * 1024:
        score += 10
    if score < 25:
        threat_level = "Safe"
    elif score < 50:
        threat_level = "Medium"
    elif score < 75:
        threat_level = "High"
    else:
        threat_level = "Critical"
    return {
        "risk_score": min(100, score),
        "threat_level": threat_level,
        "explanation": "The attachment uses a risky extension and warrants deeper inspection before opening.",
        "recommendations": ["Scan with endpoint protection", "Quarantine the file", "Avoid executing macros"],
        "details": details,
    }


@file_scanner_bp.route("/scan-file", methods=["GET", "POST"])
def scan_file():
    result = None
    if request.method == "POST":
        if "file" not in request.files:
            return render_template("file_scanner.html", result=None, title="File Scanner")
        uploaded = request.files["file"]
        if uploaded.filename == "":
            return render_template("file_scanner.html", result=None, title="File Scanner")
        filename = secure_filename(uploaded.filename)
        path = os.path.join(current_app.config["UPLOAD_FOLDER"], filename)
        uploaded.save(path)
        result = analyze_file(filename, os.path.getsize(path))
        save_file_scan(g.user["id"], filename, path, result["threat_level"], result["threat_level"], result["risk_score"], result["details"])
        save_scan_history(g.user["id"], "file", filename, result["threat_level"], result["threat_level"], result["risk_score"], result["details"])
        log_activity(g.user["id"], "scan_file", filename)
    return render_template("file_scanner.html", result=result, title="File Scanner")
