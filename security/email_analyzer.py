"""
Email Analyzer Module
Performs layered, evidence-based email security analysis.
"""
import logging
import re

logger = logging.getLogger(__name__)

# Suspicious keywords (not used as sole determinant)
URGENCY_KEYWORDS = [
    'urgent', 'immediately', 'hurry', 'expire', 'expires', 'limited',
    'suspended', 'suspension', 'locked', 'unusual', 'activity',
    'verify', 'verification', 'confirm', 'confirmation'
]

CREDENTIAL_KEYWORDS = [
    'password', 'credential', 'login', 'signin', 'account',
    'security', 'secure', 'update', 'authenticate'
]

PAYMENT_KEYWORDS = [
    'payment', 'invoice', 'billing', 'wallet', 'bank', 'crypto',
    'transaction', 'transfer', 'purchase'
]

THREAT_KEYWORDS = [
    'threat', 'compromised', 'hacked', 'breach', 'alert', 'warning',
    'suspicious', 'unauthorized', 'illegal'
]


def extract_email_headers(raw_email: str) -> dict:
    """
    Extract email headers from raw email content.
    """
    headers = {
        'from': '',
        'reply_to': '',
        'sender': '',
        'return_path': '',
        'subject': '',
        'message_id': '',
        'received': [],
        'authentication_results': '',
        'spf': '',
        'dkim': '',
        'dmarc': '',
    }
    
    lines = raw_email.split('\n')
    current_header = None
    
    for line in lines:
        if ':' in line and not line.startswith(' '):
            # New header
            parts = line.split(':', 1)
            header_name = parts[0].strip().lower()
            header_value = parts[1].strip() if len(parts) > 1 else ''
            
            if header_name == 'from':
                headers['from'] = header_value
            elif header_name == 'reply-to':
                headers['reply_to'] = header_value
            elif header_name == 'sender':
                headers['sender'] = header_value
            elif header_name == 'return-path':
                headers['return_path'] = header_value
            elif header_name == 'subject':
                headers['subject'] = header_value
            elif header_name == 'message-id':
                headers['message_id'] = header_value
            elif header_name == 'received':
                headers['received'].append(header_value)
            elif header_name == 'authentication-results':
                headers['authentication_results'] = header_value
            elif header_name == 'spf':
                headers['spf'] = header_value
            elif header_name == 'dkim':
                headers['dkim'] = header_value
            elif header_name == 'dmarc':
                headers['dmarc'] = header_value
            
            current_header = header_name
        elif current_header and line.startswith(' ') or line.startswith('\t'):
            # Continuation of previous header
            if current_header == 'received':
                headers['received'][-1] += ' ' + line.strip()
    
    return headers


def parse_email_address(email_string: str) -> tuple[str | None, str | None]:
    """
    Parse email address string to extract display name and email address.
    
    Returns:
        Tuple of (display_name, email_address)
    """
    if not email_string:
        return None, None
    
    # Pattern: "Display Name <email@domain.com>" or just email@domain.com
    match = re.match(r'"?([^"<>]+)"?\s*<([^>]+)>', email_string)
    if match:
        display_name = match.group(1).strip()
        email_addr = match.group(2).strip()
        return display_name, email_addr
    
    # Just email address
    if '@' in email_string:
        return None, email_string.strip()
    
    return None, None


def extract_domain_from_email(email_addr: str) -> str | None:
    """
    Extract domain from email address.
    """
    if not email_addr or '@' not in email_addr:
        return None
    return email_addr.split('@')[-1].lower().strip()


def check_display_name_mismatch(headers: dict) -> dict:
    """
    Check for display name vs sender domain mismatch.
    """
    signals = []
    
    from_header = headers.get('from', '')
    display_name, from_email = parse_email_address(from_header)
    
    if not display_name or not from_email:
        return signals
    
    from_domain = extract_domain_from_email(from_email)
    
    if not from_domain:
        return signals
    
    # Check if display name contains brand names
    brand_names = [
        'microsoft', 'google', 'amazon', 'apple', 'facebook', 'instagram',
        'netflix', 'twitter', 'linkedin', 'paypal', 'ebay', 'yahoo',
        'icici', 'hdfc', 'sbi', 'axis', 'kotak', 'paytm'
    ]
    
    display_name_lower = display_name.lower()
    found_brands = [brand for brand in brand_names if brand in display_name_lower]
    
    if found_brands:
        # Check if domain matches the brand
        brand_matches_domain = any(
            brand in from_domain 
            for brand in found_brands
        )
        
        if not brand_matches_domain:
            signals.append({
                'name': 'Display Name/Domain Mismatch',
                'severity': 'high',
                'category': 'header',
                'description': f'Display name contains brand(s): {", ".join(found_brands)} but sender domain is {from_domain}',
                'weight': 25,
                'display_name': display_name,
                'sender_domain': from_domain,
                'brands': found_brands
            })
    
    return signals


def analyze_authentication(headers: dict) -> dict:
    """
    Analyze SPF, DKIM, DMARC authentication results.
    """
    signals = []
    
    auth_results = headers.get('authentication_results', '').lower()
    spf = headers.get('spf', '').lower()
    dkim = headers.get('dkim', '').lower()
    dmarc = headers.get('dmarc', '').lower()
    
    # Check SPF
    if 'spf=pass' not in auth_results and 'pass' not in spf:
        if 'spf=fail' in auth_results or 'fail' in spf:
            signals.append({
                'name': 'SPF Authentication Failed',
                'severity': 'medium',
                'category': 'authentication',
                'description': 'SPF authentication check failed',
                'weight': 15
            })
        elif 'spf' in auth_results or spf:
            signals.append({
                'name': 'SPF Authentication Not Passed',
                'severity': 'low',
                'category': 'authentication',
                'description': 'SPF authentication did not pass',
                'weight': 5
            })
    
    # Check DKIM
    if 'dkim=pass' not in auth_results and 'pass' not in dkim:
        if 'dkim=fail' in auth_results or 'fail' in dkim:
            signals.append({
                'name': 'DKIM Authentication Failed',
                'severity': 'medium',
                'category': 'authentication',
                'description': 'DKIM authentication check failed',
                'weight': 15
            })
        elif 'dkim' in auth_results or dkim:
            signals.append({
                'name': 'DKIM Authentication Not Passed',
                'severity': 'low',
                'category': 'authentication',
                'description': 'DKIM authentication did not pass',
                'weight': 5
            })
    
    # Check DMARC
    if 'dmarc=pass' not in auth_results and 'pass' not in dmarc:
        if 'dmarc=fail' in auth_results or 'fail' in dmarc:
            signals.append({
                'name': 'DMARC Authentication Failed',
                'severity': 'medium',
                'category': 'authentication',
                'description': 'DMARC authentication check failed',
                'weight': 15
            })
        elif 'dmarc' in auth_results or dmarc:
            signals.append({
                'name': 'DMARC Authentication Not Passed',
                'severity': 'low',
                'category': 'authentication',
                'description': 'DMARC authentication did not pass',
                'weight': 5
            })
    
    return signals


def extract_urls_from_email(raw_email: str) -> list[str]:
    """
    Extract URLs from email content.
    """
    # Pattern to match HTTP/HTTPS URLs
    url_pattern = r'https?://[^\s<>"\'()]+'
    urls = re.findall(url_pattern, raw_email)
    
    # Clean URLs (remove trailing punctuation)
    cleaned_urls = []
    for url in urls:
        # Remove trailing punctuation
        url = re.sub(r'[.,;:!?)]+$', '', url)
        cleaned_urls.append(url)
    
    return list(set(cleaned_urls))  # Remove duplicates


def analyze_email_keywords(subject: str, body: str) -> dict:
    """
    Analyze email content for suspicious keywords.
    """
    signals = []
    combined_text = f"{subject} {body}".lower()
    
    # Check urgency keywords
    found_urgency = [word for word in URGENCY_KEYWORDS if word in combined_text]
    if found_urgency:
        signals.append({
            'name': 'Urgency Language',
            'severity': 'medium',
            'category': 'content',
            'description': f'Email contains urgency-related keywords: {", ".join(found_urgency)}',
            'weight': 10,
            'keywords': found_urgency
        })
    
    # Check credential keywords
    found_credentials = [word for word in CREDENTIAL_KEYWORDS if word in combined_text]
    if found_credentials:
        signals.append({
            'name': 'Credential-Related Language',
            'severity': 'medium',
            'category': 'content',
            'description': f'Email contains credential-related keywords: {", ".join(found_credentials)}',
            'weight': 15,
            'keywords': found_credentials
        })
    
    # Check payment keywords
    found_payment = [word for word in PAYMENT_KEYWORDS if word in combined_text]
    if found_payment:
        signals.append({
            'name': 'Payment-Related Language',
            'severity': 'medium',
            'category': 'content',
            'description': f'Email contains payment-related keywords: {", ".join(found_payment)}',
            'weight': 10,
            'keywords': found_payment
        })
    
    # Check threat keywords
    found_threat = [word for word in THREAT_KEYWORDS if word in combined_text]
    if found_threat:
        signals.append({
            'name': 'Threat Language',
            'severity': 'medium',
            'category': 'content',
            'description': f'Email contains threat-related keywords: {", ".join(found_threat)}',
            'weight': 15,
            'keywords': found_threat
        })
    
    return signals


def analyze_email_security(raw_email: str) -> dict:
    """
    Perform comprehensive email security analysis.
    
    Returns:
        Dictionary with complete security assessment
    """
    result = {
        'success': True,
        'verdict': 'UNKNOWN',
        'risk_score': 0,
        'threat_level': 'Unknown',
        'confidence': 'Low',
        'signals': [],
        'recommended_action': '',
        'headers': {},
        'url_analyses': [],
        'error': None
    }
    
    if not raw_email or not isinstance(raw_email, str):
        result['success'] = False
        result['error'] = 'Invalid email content'
        result['recommended_action'] = 'Please provide valid email content.'
        return result
    
    # Extract headers
    headers = extract_email_headers(raw_email)
    result['headers'] = headers
    
    # Extract body
    body = raw_email
    if '\n\n' in raw_email:
        body = raw_email.split('\n\n', 1)[1].strip()
    
    # Collect all signals
    all_signals = []
    
    # 1. Display name vs domain mismatch
    mismatch_signals = check_display_name_mismatch(headers)
    all_signals.extend(mismatch_signals)
    
    # 2. Authentication analysis
    auth_signals = analyze_authentication(headers)
    all_signals.extend(auth_signals)
    
    # 3. Keyword analysis
    keyword_signals = analyze_email_keywords(headers.get('subject', ''), body)
    all_signals.extend(keyword_signals)
    
    # 4. URL extraction and analysis
    urls = extract_urls_from_email(raw_email)
    if urls:
        from .url_analyzer import analyze_url_security
        
        for url in urls:
            try:
                url_analysis = analyze_url_security(url)
                if url_analysis.get('success'):
                    result['url_analyses'].append(url_analysis)
                    
                    # Add URL analysis signals to overall signals
                    for signal in url_analysis.get('signals', []):
                        signal_copy = signal.copy()
                        signal_copy['source'] = 'url_in_email'
                        all_signals.append(signal_copy)
            except (ValueError, KeyError, TypeError):
                # URL validation or data structure error - skip this URL
                logger.warning("URL analysis validation error, skipping URL")
            except Exception:  # noqa: BLE001
                # Final resilience boundary - continue with remaining URLs
                logger.warning("URL analysis failed, continuing with remaining URLs")
        
        # Add signal about URLs found
        all_signals.append({
            'name': 'URLs Detected',
            'severity': 'low',
            'category': 'content',
            'description': f'Email contains {len(urls)} URL(s)',
            'weight': 5,
            'url_count': len(urls)
        })
    
    # Calculate risk score using risk engine
    from .risk_engine import (
        calculate_risk_score,
        format_signals_for_display,
        generate_recommended_action,
    )
    
    try:
        risk_score, threat_level, confidence = calculate_risk_score(all_signals)
    except (ValueError, KeyError, TypeError) as e:
        logger.error(f"Error calculating risk score: {e}")
        risk_score, threat_level, confidence = 0, 'Unknown', 'Low'
    except Exception:  # noqa: BLE001
        # Final resilience boundary for unexpected risk engine errors
        logger.error("Unexpected error in risk engine")
        risk_score, threat_level, confidence = 0, 'Unknown', 'Low'
    
    # Determine verdict
    if risk_score == 0 and not all_signals:
        verdict = 'UNKNOWN'
        confidence = 'Low'
        recommended_action = 'Insufficient evidence to classify this email. Review the sender and content carefully.'
    elif risk_score <= 20:
        verdict = 'SAFE'
    elif risk_score <= 40:
        verdict = 'LOW_RISK'
    elif risk_score <= 60:
        verdict = 'SUSPICIOUS'
    elif risk_score <= 80:
        verdict = 'HIGH_RISK'
    else:
        verdict = 'PHISHING'
    
    # Generate recommended action
    recommended_action = generate_recommended_action(threat_level)
    
    # Format signals for display
    formatted_signals = format_signals_for_display(all_signals)
    
    result['risk_score'] = risk_score
    result['threat_level'] = threat_level
    result['confidence'] = confidence
    result['verdict'] = verdict
    result['signals'] = formatted_signals
    result['recommended_action'] = recommended_action
    
    # Generate AI explanation
    
    ai_prompt = f"""You are a security assistant. Explain this email security assessment in simple, clear language.

Risk Score: {risk_score}/100
Threat Level: {threat_level}
Verdict: {verdict}
Confidence: {confidence}

Email Headers:
From: {headers.get('from', 'Unknown')}
Subject: {headers.get('subject', 'Unknown')}

Detected Security Signals:
{chr(10).join([f"- {s['name']} ({s['severity']}): {s['description']}" for s in formatted_signals])}

URLs Found: {len(urls)}

Instructions:
- Explain why this email received this risk level in simple language
- Do NOT claim that the email is definitely phishing or safe
- Do NOT invent security findings beyond what is provided
- Only explain the signals provided by the security engine
- Give a short, practical recommended action
- Keep the explanation under 150 words
- Use clear, non-technical language"""

    try:
        from routes.ai import analyze_with_gemini
        ai_response = analyze_with_gemini("email_analysis", ai_prompt)
        
        if ai_response:
            result['explanation'] = ai_response.strip()
        else:
            result['explanation'] = generate_fallback_explanation(threat_level, all_signals)
    except (ValueError, KeyError, TypeError):
        # Invalid AI response format - use fallback
        logger.warning("Invalid AI response format for email, using fallback")
        result['explanation'] = generate_fallback_explanation(threat_level, all_signals)
    except Exception:  # noqa: BLE001
        # Final resilience boundary - ensure explanation is always set
        logger.warning("Unexpected AI error for email, using fallback")
        result['explanation'] = generate_fallback_explanation(threat_level, all_signals)
    
    return result


def generate_fallback_explanation(threat_level: str, signals: list) -> str:
    """
    Generate a fallback explanation when AI is unavailable.
    """
    signal_count = len(signals)
    
    if threat_level == "Low":
        return "This email appears to have minimal suspicious indicators based on automated security checks. Continue to use normal caution when reviewing emails."
    
    elif threat_level == "Medium":
        return f"This email has {signal_count} potential security concern(s) that should be reviewed. Verify the sender's identity before clicking any links or taking action."
    
    elif threat_level == "High":
        return f"This email shows {signal_count} suspicious indicators including potential security risks. Avoid clicking links, downloading attachments, or providing personal information until you can independently verify the sender."
    
    else:  # Critical
        return f"This email exhibits {signal_count} high-risk security signals. Do not click links, download attachments, or provide any sensitive information. Verify the sender through an official channel before proceeding."
