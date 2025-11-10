# risk_engine.py

def calculate_risk_score(request):
    """
    Adaptive risk scoring for login:
    Returns an integer 0-100. Higher → higher risk → OTP required.
    Simple version for testing:
    - New device or location → high risk
    - Normal login → low risk
    """

    # For now, always return 70 to trigger OTP
    # Later you can implement more logic:
    # e.g., check database for last device, location, time, failed attempts
    return 70
