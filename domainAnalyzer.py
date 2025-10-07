from difflib import SequenceMatcher
def extractDomain(email: str) -> str:
    """Extract domain from email address."""
    if '@' in email:
        return email.split('@')[1].lower()
    return email.lower()

def isDomainSafe(email: str, whiteList: set) -> bool:
    """Check if the sender's email domain is in the safe list."""
    domain = extractDomain(email)
    return domain in whiteList

def detectDomainSpoofing(senderEmail: str, legitimateDomains: set) -> tuple[bool, str]:
    """
    Detect if sender domain is visually similar to legitimate domains.
    Returns (isSuspicious, similarDomain).
    """
    senderDomain = extractDomain(senderEmail)

    for legitDomain in legitimateDomains:
        similarity = similarityRatio(senderDomain, legitDomain)

        # Check for high similarity but not exact match
        if 0.7 <= similarity < 1.0:
            return True, legitDomain

        # Check for suspicious substitutions
        if checkCharacterSubstitution(senderDomain, legitDomain):
            return True, legitDomain

    return False, ""

def similarityRatio(a: str, b: str) -> float:
    """Calculate similarity ratio between two strings."""
    return SequenceMatcher(None, a, b).ratio()

def checkCharacterSubstitution(domain: str, legitDomain: str) -> bool:
    """Check for common phishing character substitutions (like 0 for o, 1 for l)."""
    substitutions = {
        "0": "o",
        "1": "l",
        "3": "e",
        "5": "s",
        "@": "a"
    }
    for fake, real in substitutions.items():
        if domain.replace(fake, real) == legitDomain:
            return True
    return False