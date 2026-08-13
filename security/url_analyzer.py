"""
Main URL Analyzer Module
Integrates all security analysis modules for comprehensive URL risk assessment.
"""

from .domain_analyzer import analyze_hostname, check_auth_payment_terms, detect_brand_impersonation
from .keyword_analyzer import analyze_brand_keywords, analyze_keywords
from .redirect_analyzer import analyze_redirects
from .risk_engine import (
    calculate_risk_score,
    format_signals_for_display,
    generate_recommended_action,
)
from .url_parser import extract_domain, get_url_length_info, parse_url, validate_and_normalize_url
from .url_structure_analyzer import analyze_ssl_security, analyze_url_structure


def analyze_url_security(url: str) -> dict:
    """
    Perform comprehensive URL security analysis.
    
    Returns:
        Dictionary with complete security assessment
    """
    # Validate and normalize URL
    is_valid, normalized_url, error = validate_and_normalize_url(url)
    
    if not is_valid:
        return {
            'success': False,
            'error': error,
            'url': url,
            'risk_score': 0,
            'threat_level': 'Unknown',
            'confidence': 'Low',
            'signals': [],
            'recommended_action': 'Invalid URL provided'
        }
    
    # Parse URL components
    url_components = parse_url(normalized_url)
    
    # Collect all signals
    all_signals = []
    
    # 1. Domain Analysis
    hostname_signals = analyze_hostname(url_components['hostname'])
    all_signals.extend(hostname_signals)
    
    # 2. Brand Impersonation Detection
    brand_signals = detect_brand_impersonation(url_components['hostname'])
    all_signals.extend(brand_signals)
    
    # 3. Auth/Payment Terms in Hostname
    auth_signals = check_auth_payment_terms(url_components['hostname'])
    all_signals.extend(auth_signals)
    
    # 4. Keyword Analysis
    keyword_signals = analyze_keywords(
        normalized_url,
        url_components['path'],
        url_components['query']
    )
    all_signals.extend(keyword_signals)
    
    # 5. Brand Keywords
    brand_keyword_signals = analyze_brand_keywords(normalized_url)
    all_signals.extend(brand_keyword_signals)
    
    # 6. URL Structure Analysis
    structure_signals = analyze_url_structure(normalized_url)
    all_signals.extend(structure_signals)
    
    # 7. SSL Security Analysis
    ssl_signals = analyze_ssl_security(normalized_url)
    all_signals.extend(ssl_signals)
    
    # 8. Redirect Analysis (safe, with SSRF protection)
    redirect_analysis = analyze_redirects(normalized_url)
    if redirect_analysis.get('signals'):
        all_signals.extend(redirect_analysis['signals'])
    
    # Calculate risk score
    risk_score, threat_level, confidence = calculate_risk_score(all_signals)
    
    # Determine verdict
    if risk_score == 0 and not all_signals:
        verdict = 'SAFE'
        confidence = 'Low'
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
    
    # Build technical details
    technical_details = {
        'scheme': url_components['scheme'],
        'hostname': url_components['hostname'],
        'port': url_components['port'],
        'path': url_components['path'],
        'query': url_components['query'],
        'domain': extract_domain(url_components['hostname']),
        'redirect_count': redirect_analysis.get('redirect_count', 0),
        'redirect_chain': redirect_analysis.get('redirect_chain', []),
        'final_destination': redirect_analysis.get('final_destination', normalized_url),
        'url_length': get_url_length_info(normalized_url)
    }
    
    return {
        'success': True,
        'url': normalized_url,
        'original_url': url,
        'risk_score': risk_score,
        'threat_level': threat_level,
        'confidence': confidence,
        'verdict': verdict,
        'signals': formatted_signals,
        'all_signals': all_signals,  # Full signal data for AI
        'recommended_action': recommended_action,
        'technical_details': technical_details,
        'redirect_analysis': redirect_analysis
    }
