import re
import urllib.parse
import ipaddress
from typing import List, Dict

def extractLinks(text: str) -> List[str]:
    """Extract all URLs from text."""
    urlPattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|' \
                  r'(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    return re.findall(urlPattern, text)

def analyzeLinks(links: List[str], claimedSenderDomain: str) -> Dict[str, int]:
    """
    Analyze links for suspicious patterns.
    Returns counts of different suspicious link types.
    """
    results = {
        'ip_addresses': 0,
        'mismatched_domains': 0,
        'suspicious_tlds': 0,
        'url_shorteners': 0
    }

    suspiciousTlds = {'.tk', '.ml', '.ga', '.cf', '.top', '.click', '.download'}
    urlShorteners = {'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'short.link'}

    for link in links:
        try:
            parsed = urllib.parse.urlparse(link)
            domain = parsed.netloc.lower()

            # Check for IP addresses
            try:
                ipaddress.ip_address(domain.split(':')[0])  # Remove port if present
                results['ip_addresses'] += 1
                continue
            except ValueError:
                pass

            # Check for URL shorteners
            if any(shortener in domain for shortener in urlShorteners):
                results['url_shorteners'] += 1

            # Check for suspicious TLDs
            if any(domain.endswith(tld) for tld in suspiciousTlds):
                results['suspicious_tlds'] += 1

            # Check for domain mismatch
            if claimedSenderDomain and claimedSenderDomain not in domain:
                legitimateServices = {'google.com', 'microsoft.com', 'amazon.com'}
                if not any(service in domain for service in legitimateServices):
                    results['mismatched_domains'] += 1

        except Exception:
            results['mismatched_domains'] += 1

    return results

def calculateLinkScore(subject: str, body: str, senderDomain: str) -> int:
    """Calculate risk score based on link analysis."""
    all_text = subject + " " + body
    links = extractLinks(all_text)
    
    if not links:
        return 0
    
    linkAnalysis = analyzeLinks(links, senderDomain)
    
    score = 0
    score += linkAnalysis['ip_addresses'] * 15
    score += linkAnalysis['mismatched_domains'] * 10
    score += linkAnalysis['suspicious_tlds'] * 8
    score += linkAnalysis['url_shorteners'] * 5
    
    return score