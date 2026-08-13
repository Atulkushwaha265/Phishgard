"""
Keyword Analyzer Module
Analyzes URLs for suspicious keywords and brand terms.
"""


# Suspicious keywords that may indicate phishing
SUSPICIOUS_KEYWORDS = [
    'login', 'signin', 'verify', 'verification', 'account', 'password',
    'secure', 'security', 'update', 'confirm', 'payment', 'wallet', 'bank',
    'billing', 'credential', 'unlock', 'urgent', 'suspend', 'support',
    'recover', 'restore', 'activate', 'validate', 'authenticate'
]

# Urgency keywords
URGENCY_KEYWORDS = [
    'urgent', 'immediately', 'hurry', 'expire', 'expires', 'limited',
    'suspended', 'suspension', 'locked', 'unusual', 'activity'
]

# Brand keywords for impersonation detection
BRAND_KEYWORDS = [
    'paytm', 'paypal', 'google', 'microsoft', 'amazon', 'apple',
    'facebook', 'instagram', 'netflix', 'twitter', 'linkedin', 'yahoo',
    'icici', 'hdfc', 'sbi', 'axis', 'kotak', 'flipkart'
]


def analyze_keywords(url: str, path: str = '', query: str = '') -> dict:
    """
    Analyze URL components for suspicious keywords.
    
    Returns dictionary of detected keyword signals.
    """
    signals = []
    
    # Combine all URL components for analysis
    combined_text = f"{url} {path} {query}".lower()
    
    # Check for suspicious keywords
    found_suspicious = []
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in combined_text:
            found_suspicious.append(keyword)
    
    if found_suspicious:
        signals.append({
            'name': 'Suspicious Keywords',
            'severity': 'medium',
            'category': 'keyword',
            'description': f'URL contains suspicious keywords: {", ".join(found_suspicious)}',
            'weight': 10,
            'keywords': found_suspicious
        })
    
    # Check for urgency keywords
    found_urgency = []
    for keyword in URGENCY_KEYWORDS:
        if keyword in combined_text:
            found_urgency.append(keyword)
    
    if found_urgency:
        signals.append({
            'name': 'Urgency Language',
            'severity': 'medium',
            'category': 'keyword',
            'description': f'URL contains urgency-related keywords: {", ".join(found_urgency)}',
            'weight': 15,
            'keywords': found_urgency
        })
    
    return signals


def analyze_brand_keywords(url: str) -> dict:
    """
    Analyze URL for brand-related keywords.
    
    Returns dictionary of brand keyword signals.
    """
    signals = []
    url_lower = url.lower()
    
    found_brands = []
    for brand in BRAND_KEYWORDS:
        if brand in url_lower:
            found_brands.append(brand)
    
    if found_brands:
        signals.append({
            'name': 'Brand Keywords Present',
            'severity': 'low',
            'category': 'brand',
            'description': f'URL contains brand-related keywords: {", ".join(found_brands)}',
            'weight': 5,
            'brands': found_brands
        })
    
    return signals
