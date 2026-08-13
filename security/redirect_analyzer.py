"""
Redirect Analyzer Module
Safely analyzes HTTP redirects with SSRF protection.
"""
import ipaddress
import logging
from urllib.parse import urlparse

import requests

logger = logging.getLogger(__name__)

# Private IP ranges to block
PRIVATE_IP_RANGES = [
    '127.0.0.0/8',      # Loopback
    '10.0.0.0/8',       # Private Class A
    '172.16.0.0/12',    # Private Class B
    '192.168.0.0/16',   # Private Class C
    '169.254.0.0/16',   # Link-local
    '100.64.0.0/10',    # Carrier-grade NAT
]


def is_private_ip_address(ip: str) -> bool:
    """
    Check if IP address is in private range.
    """
    try:
        addr = ipaddress.ip_address(ip)
        for network in PRIVATE_IP_RANGES:
            if addr in ipaddress.ip_network(network):
                return True
        return False
    except ValueError:
        return False


def is_safe_destination(hostname: str) -> bool:
    """
    Check if destination hostname is safe for outbound requests.
    """
    return (
        hostname.lower() not in ('localhost', 'localhost.localdomain')
        and not is_private_ip_address(hostname)
    )


def analyze_redirects(url: str, max_redirects: int = 5, timeout: int = 10) -> dict:
    """
    Safely analyze HTTP redirects with SSRF protection.
    
    Returns dictionary with redirect analysis.
    """
    result = {
        'redirect_count': 0,
        'redirect_chain': [],
        'final_destination': url,
        'signals': [],
        'error': None
    }
    
    # Validate destination before making request
    parsed = urlparse(url)
    if not is_safe_destination(parsed.hostname or ''):
        result['error'] = 'Blocked: Private/internal address not allowed'
        result['signals'].append({
            'name': 'Blocked Destination',
            'severity': 'critical',
            'category': 'redirect',
            'description': 'Request blocked: destination is a private/internal address',
            'weight': 50
        })
        return result
    
    session = None
    try:
        # Create a session with redirect limit
        session = requests.Session()
        session.max_redirects = max_redirects
        
        response = session.get(
            url,
            allow_redirects=True,
            timeout=timeout,
            headers={'User-Agent': 'PhishGuard-Security-Scanner/1.0'}
        )
        
        # Track redirect chain
        if response.history:
            result['redirect_count'] = len(response.history)
            
            for i, resp in enumerate(response.history):
                chain_url = resp.url
                chain_parsed = urlparse(chain_url)
                
                result['redirect_chain'].append({
                    'step': i + 1,
                    'url': chain_url,
                    'hostname': chain_parsed.hostname or '',
                    'status_code': resp.status_code
                })
            
            result['final_destination'] = response.url
            
            # Analyze redirect behavior
            if result['redirect_count'] > 2:
                result['signals'].append({
                    'name': 'Multiple Redirects',
                    'severity': 'medium',
                    'category': 'redirect',
                    'description': f'URL redirects through {result["redirect_count"]} destinations',
                    'weight': 15
                })
            
            # Check for cross-domain redirects
            original_domain = parsed.hostname or ''
            final_domain = urlparse(response.url).hostname or ''
            
            if original_domain and final_domain and original_domain != final_domain:
                result['signals'].append({
                    'name': 'Cross-Domain Redirect',
                    'severity': 'medium',
                    'category': 'redirect',
                    'description': f'URL redirects from {original_domain} to {final_domain}',
                    'weight': 10
                })
        
        return result
        
    except requests.TooManyRedirects:
        result['error'] = 'Too many redirects'
        result['signals'].append({
            'name': 'Excessive Redirects',
            'severity': 'medium',
            'category': 'redirect',
            'description': 'URL exceeded maximum redirect limit',
            'weight': 20
        })
        return result
        
    except requests.Timeout:
        result['error'] = 'Request timeout'
        result['signals'].append({
            'name': 'Request Timeout',
            'severity': 'low',
            'category': 'redirect',
            'description': 'HTTP request timed out',
            'weight': 5
        })
        return result
        
    except requests.ConnectionError:
        result['error'] = 'Connection error'
        result['signals'].append({
            'name': 'Connection Error',
            'severity': 'low',
            'category': 'redirect',
            'description': 'Failed to establish connection',
            'weight': 5
        })
        return result
        
    except requests.RequestException as e:
        result['error'] = f'Request failed: {e!s}'
        result['signals'].append({
            'name': 'Request Failed',
            'severity': 'low',
            'category': 'redirect',
            'description': f'HTTP request failed: {e!s}',
            'weight': 5
        })
        return result
    except (ValueError, UnicodeError):
        # URL parsing or encoding error
        result['error'] = 'Invalid URL format'
        result['signals'].append({
            'name': 'Invalid URL',
            'severity': 'low',
            'category': 'redirect',
            'description': 'URL format is invalid',
            'weight': 5
        })
        return result
    except Exception:  # noqa: BLE001
        # Final resilience boundary for unexpected errors
        logger.warning("Unexpected redirect analysis error")
        result['error'] = 'Unexpected analysis error'
        result['signals'].append({
            'name': 'Analysis Error',
            'severity': 'low',
            'category': 'redirect',
            'description': 'Unexpected error during redirect analysis',
            'weight': 5
        })
        return result
    finally:
        if session:
            session.close()
