import re
import urllib.parse
import ipaddress
from typing import List, Dict
import domains

"""Extract all URLs from text. using regex."""
def extractLinks(text: str) -> List[str]:
    urlPattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|' \
                  r'(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    return re.findall(urlPattern, text)

   

'''Analyze links for various risk factors such as the use of IP addresses, domain mismatches, suspicious TLDs, and URL shorteners. Than return a dictionary with the number of each risk factor found.'''
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
                if not any(service in domain for service in domains.legitimateDomains):
                    results['mismatchedDomains'] += 1

        except Exception:
            results['mismatchedDomains'] += 1

    return results
    


'''Once each risk factor have been fond we assign them a score and then tally them up.'''
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

def formatLinkAnalysisReport(subject: str, body: str, senderDomain: str):
    # Step 1: Extract links from subject and body
    links = extractLinks(subject + " " + body)

    # Step 2: Check if links are found
    if not links:
        return "No link found"

    # Step 3: Analyze the links
    linkAnalysisResults = analyzeLinks(links, senderDomain)

    # Step 4: Return formatted analysis report
    analysisReport = f"Links analyzed: {', '.join(links)}\n" + \
                     f"Suspicious IP links: {linkAnalysisResults['ipAddresses']} \n" + \
                     f"Mismatched domains: {linkAnalysisResults['mismatchedDomains']} \n" + \
                     f"Suspicious TLDs: {linkAnalysisResults['suspiciousTlds']} \n" + \
                     f"URL shorteners: {linkAnalysisResults['urlShorteners']}"

    return analysisReport