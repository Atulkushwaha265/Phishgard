from flask import Blueprint, g, render_template, request

from database import log_activity, save_scan_history, save_url_scan
from security.ai_explainer import generate_ai_explanation
from security.url_analyzer import analyze_url_security

url_scanner_bp = Blueprint("url_scanner", __name__)


def analyze_url(url):
    """Analyze URL using the comprehensive security analysis system."""
    # Perform comprehensive security analysis
    analysis = analyze_url_security(url)
    
    if not analysis.get('success'):
        # Return error result
        return {
            "risk_score": 0,
            "threat_level": "Unknown",
            "verdict": "UNKNOWN",
            "explanation": analysis.get('error', 'Invalid URL'),
            "recommendations": ["Please check the URL and try again."],
            "details": {"error": analysis.get('error')},
        }
    
    # Generate AI explanation based on the security analysis
    ai_explanation = generate_ai_explanation(analysis)
    
    # Extract signal names for display
    signal_names = [signal['name'] for signal in analysis.get('signals', [])]
    
    return {
        "risk_score": analysis['risk_score'],
        "threat_level": analysis['threat_level'],
        "verdict": analysis.get('verdict', 'UNKNOWN'),
        "explanation": ai_explanation,
        "recommendations": [analysis['recommended_action']],
        "details": {
            "signals": signal_names,
            "technical_details": analysis.get('technical_details', {}),
            "confidence": analysis.get('confidence', 'Low')
        },
    }


@url_scanner_bp.route("/scan-url", methods=["GET", "POST"])
def scan_url():
    result = None
    if request.method == "POST":
        target = request.form.get("url", "").strip()
        if target:
            result = analyze_url(target)
            save_url_scan(g.user["id"], target, result["verdict"], result["threat_level"], result["risk_score"], result["details"])
            save_scan_history(g.user["id"], "url", target, result["verdict"], result["threat_level"], result["risk_score"], result["details"])
            log_activity(g.user["id"], "scan_url", target)
    return render_template("url_scanner.html", result=result, title="Link Scanner")
