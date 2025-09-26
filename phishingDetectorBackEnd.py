import re
import urllib.parse
from typing import List, Dict, Tuple
from difflib import SequenceMatcher
import ipaddress

class phishingDetector:
    def __init__(self, senderEmail, subject, body):
        self.senderEmail = senderEmail
        self.subject = subject
        self.body = body
        self.whiteList = {'gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com', 'aol.com',
                        'icloud.com', 'protonmail.com', 'amazon.com', 'microsoft.com',
                        'google.com', 'apple.com', 'facebook.com', 'twitter.com',
                        'linkedin.com', 'github.com', 'stackoverflow.com', 'reddit.com',
                        'paypal.com', 'ebay.com', 'netflix.com', 'spotify.com'
                        }
        self.highRiskkeywords = {'urgent', 'immediate', 'suspended', 'verify', 'confirm', 'click here',
            'act now', 'limited time', 'expires', 'winner', 'congratulations',
            'prize', 'lottery', 'inheritance', 'transfer', 'beneficiary',
            'scam', 'fraud', 'phishing', 'security alert', 'account locked',
            'unauthorized', 'suspicious activity', 'update payment', 'billing issue'
        }
        self.mediumRiskkeywords = {'free', 'offer', 'deal', 'discount', 'save money', 'cash',
            'investment', 'opportunity', 'guaranteed', 'risk-free',
            'no obligation', 'act fast', 'hurry', 'don\'t miss',
            'login', 'password', 'account', 'bank', 'credit card'
            }
        self.lowRiskkeywords = {'promotion', 'newsletter', 'unsubscribe', 'marketing',
            'advertisement', 'sale', 'new product', 'update'
            }
        self.legitimateDomains = {
            'paypal.com', 'amazon.com', 'microsoft.com', 'google.com',
            'apple.com', 'facebook.com', 'twitter.com', 'linkedin.com',
            'github.com', 'netflix.com', 'spotify.com', 'ebay.com',
            'instagram.com', 'youtube.com', 'dropbox.com', 'adobe.com'
        }

    def extractDomain(self, email: str) -> str:
        """Extract domain from email address."""
        if '@' in email:
            return email.split('@')[1].lower()
        return email.lower()
    
    def isDomainSafe(self, email: str) -> bool:
        """Check if the sender's email domain is in the safe list."""
        domain = self.extractDomain(email)
        return domain in self.whiteList

    def scanKeywords(self, text: str, isSubject: bool = False) -> Dict[str, int]:
        """
        Scan text for suspicious keywords and return counts by risk level.
        Subject lines get higher weight.
        """
        textLower = text.lower()
        results = {'high': 0, 'medium': 0, 'low': 0}
        multiplier = 2 if isSubject else 1
        
        for keyword in self.highRiskkeywords:
            count = len(re.findall(r'\b' + re.escape(keyword) + r'\b', textLower))
            results['high'] += count * multiplier
        
        for keyword in self.mediumRiskkeywords:
            count = len(re.findall(r'\b' + re.escape(keyword) + r'\b', textLower))
            results['medium'] += count * multiplier
        
        for keyword in self.lowRiskkeywords:
            count = len(re.findall(r'\b' + re.escape(keyword) + r'\b', textLower))
            results['low'] += count * multiplier
        
        return results

    def calculateKeywordScore(self, subject: str, body: str) -> int:
        """Calculate risk score based on keyword analysis."""
        subjectResults = self.scanKeywords(subject, isSubject=True)
        bodyResults = self.scanKeywords(body, isSubject=False)
        
        # Check for keywords in early part of message (first 100 characters)
        earlyBody = body[:100] if len(body) > 100 else body
        earlyResults = self.scanKeywords(earlyBody, isSubject=False)
        
        # Calculate weighted score
        score = 1
        score += (subjectResults['high'] + bodyResults['high']) * 1
        score += (subjectResults['medium'] + bodyResults['medium']) * 1
        score += (subjectResults['low'] + bodyResults['low']) * 1
        
        # Bonus for keywords appearing early in message
        score += earlyResults['high'] * 5
        score += earlyResults['medium'] * 3
        score += earlyResults['low'] * 1
        
        return score

    def similarityRatio(self, a: str, b: str) -> float:
        """Calculate similarity ratio between two strings."""
        return SequenceMatcher(None, a, b).ratio()

    def checkCharacterSubstitution(self, domain: str, legitDomain: str) -> bool:
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

    def detectDomainSpoofing(self, senderEmail: str) -> Tuple[bool, str]:
        """
        Detect if sender domain is visually similar to legitimate domains.
        Returns (is_suspicious, similar_domain).
        """
        senderDomain = self.extractDomain(senderEmail)

        for legitDomain in self.legitimateDomains:
            similarity = self.similarityRatio(senderDomain, legitDomain)

            # Check for high similarity but not exact match
            if 0.7 <= similarity < 1.0:
                return True, legitDomain

            # Check for suspicious substitutions
            if self.checkCharacterSubstitution(senderDomain, legitDomain):
                return True, legitDomain

        return False, ""

    def extractLinks(self, text: str) -> List[str]:
        """Extract all URLs from text."""
        urlPattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|' \
                      r'(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        return re.findall(urlPattern, text)

    def analyzeLinks(self, links: List[str], claimedSenderDomain: str) -> Dict[str, int]:
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

    def linkAnalysis(self) -> str:
        """User-facing summary of link analysis."""
        links = self.extractLinks(self.body)
        if not links:
            return "No links found"

        claimed_domain = self.extractDomain(self.senderEmail)
        analysis = self.analyzeLinks(links, claimed_domain)

        return (
            f"Links found: {', '.join(links)}<br>"
            f"Suspicious IP links: {analysis['ip_addresses']}<br>"
            f"Mismatched domains: {analysis['mismatched_domains']}<br>"
            f"Suspicious TLDs: {analysis['suspicious_tlds']}<br>"
            f"URL shorteners: {analysis['url_shorteners']}"
        )
        
    def calculateLinkScore(self, subject: str, body: str, senderDomain: str) -> int:
        """Calculate risk score based on link analysis."""
        all_text = subject + " " + body
        links = self.extractLinks(all_text)
        
        if not links:
            return 0
        
        linkAnalysis = self.analyzeLinks(links, senderDomain)
        
        score = 0
        score += linkAnalysis['ip_addresses'] * 15
        score += linkAnalysis['mismatched_domains'] * 10
        score += linkAnalysis['suspicious_tlds'] * 8
        score += linkAnalysis['url_shorteners'] * 5
        
        return score

    def calculateScore(self, senderEmail: str, subject: str, body: str) -> Dict:
        """
        Calculate total risk score and classification based on email analysis.
        Returns a dictionary with individual scores and final classification.
        """
        # Initialize results dictionary
        results = {
            'sender_email': senderEmail,
            'subject': subject,
            'analysis': {},
            'total_score': 0,
            'classification': 'Safe'
        }
        return results

    def analyze(self) -> Dict:
        """
        Perform full phishing email analysis using the class methods.
        Returns a dictionary with detailed analysis, scores, and classification.
        """
        # 1. Domain check
        domainSafe = self.isDomainSafe(self.senderEmail)
        domainScore = 0 if domainSafe else 10  # adjust weight as needed

        # 2. Keyword analysis
        keywordScore = self.calculateKeywordScore(self.subject, self.body)

        # 3. Domain spoofing
        isSpoofed, similar_domain = self.detectDomainSpoofing(self.senderEmail)
        spoofingScore = 15 if isSpoofed else 0

        # 4. Link analysis
        senderDomain = self.extractDomain(self.senderEmail)
        linkScore = self.calculateLinkScore(self.subject, self.body, senderDomain)

        # 5. Total score
        totalScore = domainScore + keywordScore + spoofingScore + linkScore

        # 6. Classification
        if totalScore >= 30:
            classfiction = "🚨  HIGH RISK: This email appears to be a phishing attempt!"
        elif totalScore >= 15:
            classfiction = "⚠️  MEDIUM RISK: This email contains suspicious elements."
        else:
            classfiction = "✅ LOW RISK: This email appears to be safe."
        
        # 6. Prepare final analysis dictionary
        results = {
            "senderEmail": self.senderEmail,
            "subjectMessage": self.subject,
            "bodyMessage": self.body,
            "domainSafe": domainSafe,
            "keywordScore": keywordScore,
            "domainSpoofing": {
                "isSuspicious": isSpoofed,
                "similarTo": similar_domain
            },
            "linkAnalysis": self.linkAnalysis(),
            "totalRiskScore": totalScore,
            "classification": classfiction
        }
        
        return results
