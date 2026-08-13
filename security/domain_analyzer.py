"""
Domain Analyzer Module
Analyzes domain and hostname for suspicious signals.
"""
import ipaddress
import re

# Suspicious TLDs that are often used for malicious purposes
SUSPICIOUS_TLDS = {
    'xyz', 'top', 'zip', 'tk', 'ml', 'ga', 'cf', 'gq', 'cc', 'pw'
}

# Commonly impersonated brands and their official domains
BRAND_DOMAINS = {
    'paytm': ['paytm.com', 'paytm.in'],
    'paypal': ['paypal.com'],
    'google': ['google.com', 'google.co.in'],
    'microsoft': ['microsoft.com', 'microsoft.co.in'],
    'amazon': ['amazon.com', 'amazon.in'],
    'apple': ['apple.com'],
    'facebook': ['facebook.com', 'fb.com'],
    'instagram': ['instagram.com'],
    'netflix': ['netflix.com'],
    'twitter': ['twitter.com', 'x.com'],
    'linkedin': ['linkedin.com'],
    'yahoo': ['yahoo.com', 'yahoo.co.in'],
    'icici': ['icicibank.com'],
    'hdfc': ['hdfcbank.com'],
    'sbi': ['onlinesbi.com', 'sbi.co.in'],
    'axis': ['axisbank.com'],
    'kotak': ['kotak.com'],
}


def analyze_hostname(hostname: str) -> dict:
    """
    Analyze hostname for suspicious signals.
    
    Returns dictionary of detected signals.
    """
    signals = []
    hostname_lower = hostname.lower()
    
    # Check for IP address
    if is_ip_address(hostname):
        signals.append({
            'name': 'IP Address Used',
            'severity': 'high',
            'category': 'domain',
            'description': 'URL uses an IP address instead of a domain name',
            'weight': 25
        })
    
    # Check for excessive subdomains
    subdomain_count = hostname_lower.count('.')
    if subdomain_count > 3:
        signals.append({
            'name': 'Excessive Subdomains',
            'severity': 'medium',
            'category': 'domain',
            'description': f'Hostname contains {subdomain_count} subdomains',
            'weight': 15
        })
    
    # Check for excessive hyphens
    hyphen_count = hostname_lower.count('-')
    if hyphen_count > 2:
        signals.append({
            'name': 'Excessive Hyphens',
            'severity': 'medium',
            'category': 'domain',
            'description': f'Hostname contains {hyphen_count} hyphens',
            'weight': 10
        })
    
    # Check for unusually long hostname
    if len(hostname) > 50:
        signals.append({
            'name': 'Unusually Long Hostname',
            'severity': 'low',
            'category': 'domain',
            'description': f'Hostname is unusually long ({len(hostname)} characters)',
            'weight': 5
        })
    
    # Check for suspicious TLD
    tld = hostname_lower.split('.')[-1] if '.' in hostname_lower else ''
    if tld.lower() in SUSPICIOUS_TLDS:
        signals.append({
            'name': 'Suspicious TLD',
            'severity': 'medium',
            'category': 'domain',
            'description': f'Uses TLD commonly associated with malicious sites: .{tld}',
            'weight': 10
        })
    
    # Check for suspicious characters
    if re.search(r'[^a-zA-Z0-9.\-]', hostname):
        signals.append({
            'name': 'Suspicious Characters',
            'severity': 'medium',
            'category': 'domain',
            'description': 'Hostname contains unusual characters',
            'weight': 15
        })
    
    # Check for punycode/IDN
    if 'xn--' in hostname_lower:
        signals.append({
            'name': 'Punycode/IDN Domain',
            'severity': 'medium',
            'category': 'domain',
            'description': 'Uses punycode encoding (internationalized domain name)',
            'weight': 15
        })
    
    return signals


def is_ip_address(hostname: str) -> bool:
    """
    Check if hostname is an IP address.
    """
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def detect_brand_impersonation(hostname: str) -> dict:
    """
    Detect potential brand impersonation.
    
    Returns dictionary with brand impersonation signals.
    """
    signals = []
    hostname_lower = hostname.lower()
    
    for brand, official_domains in BRAND_DOMAINS.items():
        if brand in hostname_lower:
            # Check if the actual domain matches official domains
            domain = '.'.join(hostname_lower.split('.')[-2:]) if '.' in hostname_lower else hostname_lower
            
            if domain not in official_domains:
                signals.append({
                    'name': 'Brand Impersonation',
                    'severity': 'high',
                    'category': 'brand',
                    'description': f'Hostname contains brand name "{brand}" but does not match official domain(s): {", ".join(official_domains)}',
                    'weight': 30,
                    'brand': brand,
                    'detected_domain': domain,
                    'expected_domains': official_domains
                })
    
    return signals


def check_auth_payment_terms(hostname: str) -> dict:
    """
    Check for authentication/payment-related terms in hostname.
    """
    signals = []
    hostname_lower = hostname.lower()
    
    auth_terms = ['login', 'signin', 'verify', 'verification', 'account', 'secure', 
                  'payment', 'wallet', 'bank', 'billing', 'credential', 'auth']
    
    for term in auth_terms:
        if term in hostname_lower:
            signals.append({
                'name': 'Authentication/Payment Term in Hostname',
                'severity': 'low',
                'category': 'domain',
                'description': f'Hostname contains authentication/payment term: "{term}"',
                'weight': 5
            })
            break  # Only add once if any term is found
    
    return signals
