"""
AI Explainer Module
Generates human-readable explanations using AI based on security signals.
"""
import logging

import requests

from routes.ai import analyze_with_gemini

logger = logging.getLogger(__name__)


def generate_ai_explanation(analysis_result: dict) -> str:
    """
    Generate AI explanation based on security analysis results.
    
    The AI receives only the deterministic security analysis results
    and converts them into human-readable language.
    """
    # If AI is not available, return a default explanation
    if not analysis_result.get('success'):
        return "Unable to analyze URL. Please check the URL and try again."
    
    # Build a summary of the analysis for the AI
    risk_score = analysis_result.get('risk_score', 0)
    threat_level = analysis_result.get('threat_level', 'Unknown')
    confidence = analysis_result.get('confidence', 'Low')
    signals = analysis_result.get('all_signals', [])
    
    # Create a structured summary for the AI
    signal_summary = []
    for signal in signals:
        signal_summary.append(
            f"- {signal.get('name', 'Unknown')} ({signal.get('severity', 'low')}): {signal.get('description', '')}"
        )
    
    signal_text = "\n".join(signal_summary) if signal_summary else "No suspicious signals detected."
    
    # Build the prompt for AI
    prompt = f"""You are a security assistant. Explain the following URL security assessment in simple, clear language for a general user.

Risk Score: {risk_score}/100
Threat Level: {threat_level}
Confidence: {confidence}

Detected Security Signals:
{signal_text}

Instructions:
- Explain why this URL received this risk level in simple language
- Do NOT claim that the URL is definitely malicious or safe
- Do NOT invent security findings beyond what is provided
- Only explain the signals provided by the security engine
- Give a short, practical recommended action
- Keep the explanation under 150 words
- Use clear, non-technical language"""

    try:
        ai_response = analyze_with_gemini("security_analysis", prompt)
        
        if ai_response:
            # Clean up the AI response
            return ai_response.strip()
            
    except requests.RequestException:
        # AI service unavailable or network error - use fallback
        logger.warning("AI service unavailable, using fallback explanation")
    except (ValueError, KeyError, TypeError):
        # Invalid AI response format - use fallback
        logger.warning("Invalid AI response format, using fallback explanation")
    except Exception:  # noqa: BLE001
        # Final resilience boundary for unexpected errors from AI library
        logger.warning("Unexpected AI error, using fallback explanation")
    
    # Fallback explanation if AI is unavailable
    return generate_fallback_explanation(threat_level, signals)


def generate_fallback_explanation(threat_level: str, signals: list) -> str:
    """
    Generate a fallback explanation when AI is unavailable.
    """
    signal_count = len(signals)
    
    if threat_level == "Low":
        return "This URL appears to have minimal suspicious indicators based on automated security checks. Continue to use normal caution when browsing."
    
    elif threat_level == "Medium":
        return f"This URL has {signal_count} potential security concern(s) that should be reviewed. Verify the destination domain before entering any sensitive information."
    
    elif threat_level == "High":
        return f"This URL shows {signal_count} suspicious indicators including potential security risks. Avoid entering passwords, payment information, or personal data until you can independently verify the destination."
    
    else:  # Critical
        return f"This URL exhibits {signal_count} high-risk security signals. Do not enter sensitive information or download files. Verify the website through an official source before proceeding."
