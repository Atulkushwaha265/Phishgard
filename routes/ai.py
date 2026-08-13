import requests
from flask import Blueprint, jsonify, request

from config import Config

ai_bp = Blueprint("ai", __name__)


def build_ai_prompt(entity_type, payload):
    if entity_type == "url":
        return f"Analyze this URL and explain whether it is phishing, why, risk level, confidence, and security recommendations. Return JSON with keys: verdict, risk_level, confidence, reasons, recommendations. URL: {payload}"
    if entity_type == "email":
        return f"Analyze this email and explain whether it is phishing, whether it contains spoofing, urgency, credential theft, fake links, and recommendations. Return JSON with keys: verdict, risk_level, confidence, reasons, recommendations. Email: {payload}"
    if entity_type == "security_analysis":
        # For security analysis, the payload is already a structured analysis
        return payload
    return f"Analyze the following security object and provide a simple JSON summary. {payload}"


def analyze_with_gemini(entity_type, payload):
    api_key = Config.GEMINI_API_KEY
    if not api_key:
        return None
    prompt = build_ai_prompt(entity_type, payload)
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={api_key}"
    body = {"contents": [{"parts": [{"text": prompt}]}]}
    try:
        resp = requests.post(url, json=body, timeout=12)
        if resp.ok:
            data = resp.json()
            text = data["candidates"][0]["content"]["parts"][0]["text"]
            return text
    except requests.RequestException:
        return None

@ai_bp.route("/ai-analyzer", methods=["POST"])
def ai_analyzer():
    payload = request.json or {}
    entity_type = payload.get("type", "url")
    content = payload.get("content", "")
    ai_response = analyze_with_gemini(entity_type, content)
    if ai_response:
        return jsonify({"ok": True, "response": ai_response})
    return jsonify({"ok": False, "response": "Gemini API not configured; using heuristic analysis."})
