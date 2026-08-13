"""
Risk Scoring Engine Module
Centralized risk scoring based on detected signals.
"""


def calculate_risk_score(signals: list[dict]) -> tuple[int, str, str]:
    """
    Calculate final risk score from detected signals.
    
    Returns:
        Tuple of (risk_score, threat_level, confidence)
    """
    if not signals:
        return 0, "Low", "High"
    
    # Calculate base score from signal weights
    total_weight = 0
    signal_categories = set()
    
    for signal in signals:
        weight = signal.get('weight', 0)
        severity = signal.get('severity', 'low')
        
        # Adjust weight based on severity
        severity_multiplier = {
            'low': 0.5,
            'medium': 1.0,
            'high': 1.5,
            'critical': 2.0
        }.get(severity, 1.0)
        
        total_weight += weight * severity_multiplier
        signal_categories.add(signal.get('category', 'unknown'))
    
    # Cap the score at 100
    risk_score = min(100, int(total_weight))
    
    # Determine threat level
    if risk_score <= 20:
        threat_level = "Low"
    elif risk_score <= 50:
        threat_level = "Medium"
    elif risk_score <= 75:
        threat_level = "High"
    else:
        threat_level = "Critical"
    
    # Calculate confidence based on number of signals and categories
    signal_count = len(signals)
    category_count = len(signal_categories)
    
    if signal_count >= 5 and category_count >= 3:
        confidence = "High"
    elif signal_count >= 3 and category_count >= 2:
        confidence = "Moderate"
    else:
        confidence = "Low"
    
    return risk_score, threat_level, confidence


def generate_recommended_action(threat_level: str) -> str:
    """
    Generate recommended action based on threat level.
    """
    actions = {
        "Low": "URL appears low risk based on the available checks. Continue to use normal caution.",
        "Medium": "Verify the destination domain before entering sensitive information.",
        "High": "Avoid entering passwords, OTPs, or payment information until the destination is verified.",
        "Critical": "Do not enter sensitive information or download files from this URL. Verify the website through an official source."
    }
    
    return actions.get(threat_level, "Exercise caution with this URL.")


def format_signals_for_display(signals: list[dict]) -> list[dict]:
    """
    Format signals for display in the UI.
    """
    formatted = []
    
    for signal in signals:
        formatted.append({
            'name': signal.get('name', 'Unknown Signal'),
            'severity': signal.get('severity', 'low'),
            'description': signal.get('description', '')
        })
    
    # Sort by severity (critical first)
    severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
    formatted.sort(key=lambda x: severity_order.get(x['severity'], 4))
    
    return formatted
