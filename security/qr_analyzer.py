"""
QR Analyzer Module
Analyzes QR codes with proper detection and classification.
"""
import logging
import re

from PIL import Image

logger = logging.getLogger(__name__)

try:
    from pyzbar import pyzbar
    PYZBAR_AVAILABLE = True
except ImportError:
    PYZBAR_AVAILABLE = False


# Verdict types
VERDICT_NO_QR_DETECTED = "NO_QR_DETECTED"
VERDICT_INVALID_QR = "INVALID_QR"
VERDICT_TEXT_QR = "TEXT_QR"
VERDICT_PHONE_QR = "PHONE_QR"
VERDICT_EMAIL_QR = "EMAIL_QR"
VERDICT_URL_QR = "URL_QR"
VERDICT_WIFI_QR = "WIFI_QR"
VERDICT_UNKNOWN_QR = "UNKNOWN_QR"


def decode_qr_from_image(image_path: str) -> tuple[bool, str | None, str | None]:
    """
    Decode QR code from image file.
    
    Returns:
        Tuple of (success, decoded_data, error_message)
    """
    if not PYZBAR_AVAILABLE:
        return False, None, "QR decoding library (pyzbar) not available"
    
    try:
        image = Image.open(image_path)
        decoded_objects = pyzbar.decode(image)
        
        if not decoded_objects:
            return False, None, None  # No QR detected
        
        # Return first decoded QR
        decoded_data = decoded_objects[0].data.decode('utf-8')
        return True, decoded_data, None
        
    except OSError:
        # Image file error - cannot read image
        return False, None, "Unable to read image file"
    except (UnicodeDecodeError, AttributeError):
        # QR data decoding error
        return False, None, "Unable to decode QR data"
    except Exception:  # noqa: BLE001
        # Final resilience boundary for unexpected QR library errors
        logger.warning("Unexpected QR decoding error")
        return False, None, "QR decoding failed"


def classify_qr_payload(decoded_data: str) -> tuple[str, str]:
    """
    Classify QR code payload type.
    
    Returns:
        Tuple of (verdict, payload_type)
    """
    if not decoded_data:
        return VERDICT_INVALID_QR, "invalid"
    
    # Check for URL
    if decoded_data.startswith(('http://', 'https://')):
        return VERDICT_URL_QR, "url"
    
    # Check for phone number (tel: or phone number pattern)
    if decoded_data.startswith('tel:') or re.match(r'^\+?[\d\s\-()]{10,}$', decoded_data):
        return VERDICT_PHONE_QR, "phone"
    
    # Check for email (mailto: or email pattern)
    if decoded_data.startswith('mailto:') or re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', decoded_data):
        return VERDICT_EMAIL_QR, "email"
    
    # Check for Wi-Fi configuration
    if decoded_data.startswith('WIFI:'):
        return VERDICT_WIFI_QR, "wifi"
    
    # Check for vCard/contact
    if decoded_data.startswith('BEGIN:VCARD'):
        return VERDICT_TEXT_QR, "vcard"
    
    # Default to text
    return VERDICT_TEXT_QR, "text"


def analyze_qr_security(image_path: str, manual_url: str | None = None) -> dict:
    """
    Perform comprehensive QR code security analysis.
    
    Returns:
        Dictionary with complete security assessment
    """
    result = {
        'success': True,
        'verdict': VERDICT_NO_QR_DETECTED,
        'payload_type': None,
        'decoded_data': None,
        'risk_score': 0,
        'threat_level': 'Unknown',
        'confidence': 'Low',
        'signals': [],
        'recommended_action': '',
        'url_analysis': None,
        'error': None
    }
    
    # Try to decode QR from image
    qr_detected, decoded_data, error = decode_qr_from_image(image_path)
    
    if error:
        result['success'] = False
        result['error'] = error
        result['verdict'] = VERDICT_INVALID_QR
        result['recommended_action'] = 'QR decoding failed. Ensure the image contains a valid QR code.'
        return result
    
    if not qr_detected:
        # No QR code detected
        result['verdict'] = VERDICT_NO_QR_DETECTED
        result['recommended_action'] = 'No QR code detected in the uploaded image. Please upload an image containing a QR code.'
        return result
    
    # QR detected and decoded
    result['decoded_data'] = decoded_data
    
    # If manual URL provided, use it instead of decoded data
    if manual_url:
        decoded_data = manual_url
        result['decoded_data'] = manual_url
        result['manual_override'] = True
    
    # Classify payload type
    verdict, payload_type = classify_qr_payload(decoded_data)
    result['verdict'] = verdict
    result['payload_type'] = payload_type
    
    # Handle different payload types
    if verdict == VERDICT_URL_QR:
        # URL QR - use comprehensive URL analyzer
        from .ai_explainer import generate_ai_explanation
        from .url_analyzer import analyze_url_security
        
        url_analysis = analyze_url_security(decoded_data)
        
        if url_analysis.get('success'):
            result['url_analysis'] = url_analysis
            result['risk_score'] = url_analysis['risk_score']
            result['threat_level'] = url_analysis['threat_level']
            result['confidence'] = url_analysis['confidence']
            result['signals'] = url_analysis['signals']
            
            # Generate explanation
            ai_explanation = generate_ai_explanation(url_analysis)
            result['explanation'] = ai_explanation
            result['recommended_action'] = url_analysis['recommended_action']
            
            # Override verdict based on URL analysis
            if url_analysis['threat_level'] == 'Low':
                result['verdict'] = 'SAFE'
            elif url_analysis['threat_level'] == 'Medium':
                result['verdict'] = 'LOW_RISK'
            elif url_analysis['threat_level'] == 'High':
                result['verdict'] = 'HIGH_RISK'
            else:
                result['verdict'] = 'PHISHING'
        else:
            result['error'] = url_analysis.get('error', 'URL analysis failed')
            result['verdict'] = 'UNKNOWN'
            result['recommended_action'] = 'Failed to analyze the URL contained in the QR code.'
    
    elif verdict == VERDICT_TEXT_QR:
        # Text QR - show decoded content
        result['risk_score'] = 0
        result['threat_level'] = 'Unknown'
        result['confidence'] = 'High'
        result['explanation'] = f'The QR code contains text content: "{decoded_data[:100]}{"..." if len(decoded_data) > 100 else ""}"'
        result['recommended_action'] = 'Review the decoded text content. If it contains sensitive information, handle with caution.'
    
    elif verdict == VERDICT_PHONE_QR:
        # Phone QR
        result['risk_score'] = 5
        result['threat_level'] = 'Low'
        result['confidence'] = 'High'
        result['explanation'] = f'The QR code contains a phone number: {decoded_data}'
        result['recommended_action'] = 'Verify the phone number before calling. Be cautious of unknown numbers.'
    
    elif verdict == VERDICT_EMAIL_QR:
        # Email QR
        result['risk_score'] = 5
        result['threat_level'] = 'Low'
        result['confidence'] = 'High'
        result['explanation'] = f'The QR code contains an email address: {decoded_data}'
        result['recommended_action'] = 'Verify the email address before sending any information.'
    
    elif verdict == VERDICT_WIFI_QR:
        # Wi-Fi QR
        result['risk_score'] = 10
        result['threat_level'] = 'Low'
        result['confidence'] = 'High'
        result['explanation'] = 'The QR code contains Wi-Fi network configuration.'
        result['recommended_action'] = 'Only connect to Wi-Fi networks from trusted sources. Public Wi-Fi networks may pose security risks.'
    
    else:
        # Unknown QR
        result['risk_score'] = 0
        result['threat_level'] = 'Unknown'
        result['confidence'] = 'Low'
        result['explanation'] = f'The QR code contains data of an unknown type: "{decoded_data[:100]}{"..." if len(decoded_data) > 100 else ""}"'
        result['recommended_action'] = 'Review the decoded content carefully before taking any action.'
    
    return result
