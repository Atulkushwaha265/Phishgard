"""
URL Structure Analyzer Module
Analyzes URL structure for suspicious patterns.
"""
from urllib.parse import parse_qs, urlparse

# Suspicious redirect parameters
REDIRECT_PARAMS = [
    'redirect', 'url', 'next', 'return', 'continue', 'target', 
    'goto', 'link', 'dest', 'destination', 'forward', 'relay'
]

# Suspicious file extensions
SUSPICIOUS_EXTENSIONS = [
    '.exe', '.scr', '.bat', '.cmd', '.pif', '.com', '.vbs', '.js',
    '.jar', '.php', '.asp', '.aspx', '.jsp'
]


def analyze_url_structure(url: str) -> dict:
    """
    Analyze URL structure for suspicious patterns.
    
    Returns dictionary of detected structure signals.
    """
    signals = []
    parsed = urlparse(url)
    
    # Check URL length
    if len(url) > 200:
        signals.append({
            'name': 'Excessive URL Length',
            'severity': 'medium',
            'category': 'structure',
            'description': f'URL is unusually long ({len(url)} characters)',
            'weight': 10
        })
    
    # Check for @ symbol (username:password@host)
    if '@' in url:
        signals.append({
            'name': 'Email-like URL',
            'severity': 'high',
            'category': 'structure',
            'description': 'URL contains @ symbol, possibly using embedded credentials',
            'weight': 20
        })
    
    # Check for suspicious ports
    if parsed.port and parsed.port not in (80, 443, 8080, 8443):
        signals.append({
            'name': 'Unusual Port',
            'severity': 'medium',
            'category': 'structure',
            'description': f'URL uses non-standard port: {parsed.port}',
            'weight': 15
        })
    
    # Check query parameters
    query_params = parse_qs(parsed.query)
    param_count = len(query_params)
    
    if param_count > 5:
        signals.append({
            'name': 'Excessive Query Parameters',
            'severity': 'low',
            'category': 'structure',
            'description': f'URL contains {param_count} query parameters',
            'weight': 5
        })
    
    # Check for redirect parameters
    redirect_found = []
    for param in query_params:
        if any(redirect in param.lower() for redirect in REDIRECT_PARAMS):
            redirect_found.append(param)
    
    if redirect_found:
        signals.append({
            'name': 'Redirect Parameters',
            'severity': 'medium',
            'category': 'structure',
            'description': f'URL contains redirect-related parameters: {", ".join(redirect_found)}',
            'weight': 15,
            'parameters': redirect_found
        })
    
    # Check for suspicious file extensions in path
    for ext in SUSPICIOUS_EXTENSIONS:
        if ext in parsed.path.lower():
            signals.append({
                'name': 'Suspicious File Extension',
                'severity': 'high',
                'category': 'structure',
                'description': f'Path contains suspicious file extension: {ext}',
                'weight': 20
            })
            break
    
    # Check for excessive URL encoding
    encoded_count = url.count('%')
    if encoded_count > 5:
        signals.append({
            'name': 'Excessive URL Encoding',
            'severity': 'medium',
            'category': 'structure',
            'description': f'URL contains excessive encoding ({encoded_count} encoded characters)',
            'weight': 10
        })
    
    # Check for nested URLs
    if 'http' in parsed.query.lower() or 'https' in parsed.query.lower():
        signals.append({
            'name': 'Nested URL',
            'severity': 'medium',
            'category': 'structure',
            'description': 'Query string appears to contain nested URLs',
            'weight': 15
        })
    
    # Check path depth
    path_depth = parsed.path.count('/')
    if path_depth > 5:
        signals.append({
            'name': 'Deep Path Structure',
            'severity': 'low',
            'category': 'structure',
            'description': f'URL has deep path structure ({path_depth} levels)',
            'weight': 5
        })
    
    # Check for credential-related paths
    credential_paths = ['login', 'signin', 'auth', 'verify', 'account', 'password']
    for cred_path in credential_paths:
        if cred_path in parsed.path.lower():
            signals.append({
                'name': 'Credential-Related Path',
                'severity': 'low',
                'category': 'structure',
                'description': f'Path contains credential-related term: {cred_path}',
                'weight': 5
            })
            break
    
    return signals


def analyze_ssl_security(url: str) -> dict:
    """
    Analyze SSL/TLS security of URL.
    
    Returns dictionary of SSL-related signals.
    """
    signals = []
    parsed = urlparse(url)
    
    # Check for HTTPS
    if parsed.scheme != 'https':
        signals.append({
            'name': 'No HTTPS',
            'severity': 'medium',
            'category': 'transport',
            'description': 'URL does not use HTTPS (unencrypted connection)',
            'weight': 20
        })
    
    return signals
