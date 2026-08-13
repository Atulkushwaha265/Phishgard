import os

from flask import Blueprint, current_app, g, render_template, request
from werkzeug.utils import secure_filename

from database import log_activity, save_qr_scan, save_scan_history
from security.qr_analyzer import analyze_qr_security

qr_scanner_bp = Blueprint("qr_scanner", __name__)


def analyze_qr(filename, decoded_url=None):
    """Analyze QR code using comprehensive security analysis."""
    image_path = os.path.join(current_app.config["UPLOAD_FOLDER"], filename)
    
    # Perform comprehensive QR analysis
    analysis = analyze_qr_security(image_path, decoded_url)
    
    if not analysis.get('success'):
        # Return error result
        return {
            "risk_score": 0,
            "threat_level": "Unknown",
            "verdict": analysis.get('verdict', 'UNKNOWN'),
            "explanation": analysis.get('error', 'QR analysis failed'),
            "recommendations": [analysis.get('recommended_action', 'Please try again.')],
            "details": {
                "decoded_url": analysis.get('decoded_data', 'Unable to decode'),
                "image_name": filename,
                "payload_type": analysis.get('payload_type', 'unknown'),
                "error": analysis.get('error')
            },
        }
    
    # Extract signal names for display
    signal_names = [signal['name'] for signal in analysis.get('signals', [])]
    
    return {
        "risk_score": analysis['risk_score'],
        "threat_level": analysis['threat_level'],
        "verdict": analysis['verdict'],
        "explanation": analysis.get('explanation', 'QR analysis completed.'),
        "recommendations": [analysis['recommended_action']],
        "details": {
            "decoded_url": analysis['decoded_data'],
            "image_name": filename,
            "payload_type": analysis['payload_type'],
            "signals": signal_names,
            "confidence": analysis.get('confidence', 'Low'),
            "url_analysis": analysis.get('url_analysis')
        },
    }


@qr_scanner_bp.route("/scan-qr", methods=["GET", "POST"])
def scan_qr():
    result = None
    if request.method == "POST":
        if "image" not in request.files:
            return render_template("qr_scanner.html", result=None, title="QR Scanner")
        uploaded = request.files["image"]
        if uploaded.filename == "":
            return render_template("qr_scanner.html", result=None, title="QR Scanner")
        filename = secure_filename(uploaded.filename)
        path = os.path.join(current_app.config["UPLOAD_FOLDER"], filename)
        uploaded.save(path)
        decoded_url = request.form.get("decoded_url", "") or None
        result = analyze_qr(filename, decoded_url)
        save_qr_scan(g.user["id"], filename, decoded_url, result["verdict"], result["threat_level"], result["risk_score"], result["details"])
        save_scan_history(g.user["id"], "qr", filename, result["verdict"], result["threat_level"], result["risk_score"], result["details"])
        log_activity(g.user["id"], "scan_qr", filename)
    return render_template("qr_scanner.html", result=result, title="QR Scanner")
