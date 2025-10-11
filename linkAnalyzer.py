import re
import urllib.parse
import ipaddress
from typing import List, Dict
"""Extract all URLs from text. using regex."""
def extractLinks(text: str) -> List[str]:
    urlPattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|' \
                  r'(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    return re.findall(urlPattern, text)

   
'''Analyze links for various risk factors.'''
def analyzeLinks(links: List[str], claimedSenderDomain: str) -> Dict[str, int]:
    results = {
        'ipAddresses': 0,
        'mismatchedDomains': 0,
        'suspiciousTlds': 0,
        'urlShorteners': 0
    }

    suspiciousTlds = {'.tk', '.ml', '.ga', '.cf', '.top', '.click', '.download'}
    urlShorteners = {'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'short.link'}

    for link in links:
        try:
            parsed = urllib.parse.urlparse(link)
            domain = parsed.netloc.lower()

            # Check for IP addresses
            try:
                ipaddress.ipAddress(domain.split(':')[0])  # Remove port if present
                results['ipAddresses'] += 1
                continue
            except ValueError:
                pass

            # Check for URL shorteners
            if any(shortener in domain for shortener in urlShorteners):
                results['urlShorteners'] += 1

            # Check for suspicious TLDs
            if any(domain.endswith(tld) for tld in suspiciousTlds):
                results['suspiciousTlds'] += 1

            # Check for domain mismatch
            if claimedSenderDomain and claimedSenderDomain not in domain:
                legitimateServices = {'google.com', 'microsoft.com', 'amazon.com'}
                if not any(service in domain for service in legitimateServices):
                    results['mismatchedDomains'] += 1

        except Exception:
            results['mismatchedDomains'] += 1

    return results

def calculateLinkScore(subject: str, body: str, senderDomain: str) -> int:
    """Calculate risk score based on link analysis."""
    allText = subject + " " + body
    links = extractLinks(allText)
    
    if not links:
        return 0
    
    linkAnalysis = analyzeLinks(links, senderDomain)
    
    score = 0
    score += linkAnalysis['ipAddresses'] * 15
    score += linkAnalysis['mismatchedDomains'] * 10
    score += linkAnalysis['suspiciousTlds'] * 8
    score += linkAnalysis['urlShorteners'] * 5
    
    return score