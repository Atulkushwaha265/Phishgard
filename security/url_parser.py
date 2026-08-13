"""
URL Parser Module
Safely parses and validates URLs using standard library functions.
"""
import ipaddress
import logging
from urllib.parse import urlparse, urlunparse

logger = logging.getLogger(__name__)


def validate_and_normalize_url(url: str) -> tuple[bool, str | None, dict | None]:
    """
    Validate and normalize a URL.
    
    Returns:
        Tuple of (is_valid, normalized_url, error_message)
    """
    if not url or not isinstance(url, str):
        return False, None, "URL cannot be empty"
    
    url = url.strip()
    
    # Add scheme if missing
    if not url.startswith(('http://', 'https://')):
        if '.' in url and not url.startswith('/'):
            url = 'https://' + url
        else:
            return False, None, "Invalid URL format"
    
    try:
        parsed = urlparse(url)
        
        # Validate scheme
        if parsed.scheme not in ('http', 'https'):
            return False, None, "Only HTTP and HTTPS schemes are allowed"
        
        # Validate hostname
        if not parsed.hostname:
            return False, None, "Invalid hostname"
        
        # Check for private/internal IPs
        if is_private_ip(parsed.hostname):
            return False, None, "Private/internal IP addresses are not allowed"
        
        # Normalize URL
        normalized = urlunparse(parsed)
        
        return True, normalized, None
        
    except ValueError:
        # Invalid URL format or scheme
        return False, None, "Invalid URL format"
    except UnicodeError:
        # URL encoding error
        return False, None, "Invalid URL encoding"
    except Exception:  # noqa: BLE001
        # Final resilience boundary for unexpected parsing errors
        logger.warning("Unexpected URL parsing error")
        return False, None, "URL parsing failed"


def parse_url(url: str) -> dict:
    """
    Parse URL into components using urllib.parse.
    
    Returns dictionary with URL components.
    """
    parsed = urlparse(url)
    
    return {
        'scheme': parsed.scheme,
        'hostname': parsed.hostname or '',
        'port': parsed.port,
        'path': parsed.path,
        'query': parsed.query,
        'fragment': parsed.fragment,
        'username': parsed.username,
        'password': parsed.password,
        'full_url': url
    }


def is_private_ip(hostname: str) -> bool:
    """
    Check if hostname is a private/internal IP address.
    """
    hostname_lower = hostname.lower()

    if hostname_lower in ('localhost', '127.0.0.1'):
        return True

    try:
        ip = ipaddress.ip_address(hostname)
    except ValueError:
        return False

    return (
        ip.is_private or
        ip.is_loopback or
        ip.is_link_local or
        ip.is_reserved
    )


def extract_domain(hostname: str) -> str:
    """
    Extract the registrable domain from hostname.
    This is a simplified version - for production, use a proper library like tldextract.
    """
    parts = hostname.split('.')
    
    if len(parts) >= 2:
        # Return the last two parts as domain (simplified)
        return '.'.join(parts[-2:])
    
    return hostname


def get_url_length_info(url: str) -> dict:
    """
    Get length information about URL components.
    """
    parsed = urlparse(url)
    
    return {
        'total_length': len(url),
        'hostname_length': len(parsed.hostname or ''),
        'path_length': len(parsed.path),
        'query_length': len(parsed.query),
        'fragment_length': len(parsed.fragment)
    }
