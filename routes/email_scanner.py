
from flask import Blueprint, g, render_template, request

from database import log_activity, save_email_scan, save_scan_history
from security.email_analyzer import analyze_email_security

email_scanner_bp = Blueprint("email_scanner", __name__)


def analyze_email(raw_email):
    """Analyze email using comprehensive security analysis."""
    # Perform comprehensive email analysis
    analysis = analyze_email_security(raw_email)
    
    if not analysis.get('success'):
        # Return error result
        return {
            "risk_score": 0,
            "threat_level": "Unknown",
            "verdict": analysis.get('verdict', 'UNKNOWN'),
            "explanation": analysis.get('error', 'Email analysis failed'),
            "recommendations": [analysis.get('recommended_action', 'Please try again.')],
            "details": {
                "sender": "Unknown",
                "subject": "Unknown",
                "body": "",
                "links": [],
                "error": analysis.get('error')
            },
        }
    
    # Extract signal names for display
    signal_names = [signal['name'] for signal in analysis.get('signals', [])]
    
    # Extract URLs for display
    urls = []
    for url_analysis in analysis.get('url_analyses', []):
        urls.append(url_analysis.get('url', ''))
    
    return {
        "risk_score": analysis['risk_score'],
        "threat_level": analysis['threat_level'],
        "verdict": analysis['verdict'],
        "explanation": analysis.get('explanation', 'Email analysis completed.'),
        "recommendations": [analysis['recommended_action']],
        "details": {
            "sender": analysis['headers'].get('from', 'Unknown'),
            "subject": analysis['headers'].get('subject', 'Unknown'),
            "body": raw_email[:500] if len(raw_email) > 500 else raw_email,
            "links": urls,
            "signals": signal_names,
            "confidence": analysis.get('confidence', 'Low'),
            "url_analyses": analysis.get('url_analyses', [])
        },
    }


@email_scanner_bp.route("/scan-email", methods=["GET", "POST"])
def scan_email():
    result = None
    if request.method == "POST":
        raw_email = request.form.get("email", "")
        if raw_email:
            result = analyze_email(raw_email)
            info = result["details"]
            save_email_scan(g.user["id"], info["sender"], info["subject"], info["body"], ", ".join(info["links"]), result["verdict"], result["threat_level"], result["risk_score"], result["details"])
            save_scan_history(g.user["id"], "email", info["subject"], result["verdict"], result["threat_level"], result["risk_score"], result["details"])
            log_activity(g.user["id"], "scan_email", info["subject"])
    return render_template("email_scanner.html", result=result, title="Email Scanner")
