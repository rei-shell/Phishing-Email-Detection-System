import re
import urllib.parse
from typing import List, Dict, Tuple
from difflib import SequenceMatcher
import ipaddress

class PhishingDetector:
    def __init__(self, sender_email, subject, body):
        self.sender_email = sender_email
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

    def check_domain(self):
    # Extract the domain part of the email
        if "@" not in self.sender_email:
            return "Invalid Email"

        domain = self.sender_email.split("@")[-1].lower()

        # Check if the domain is in whitelist
        if domain in self.whiteList:
            return "Legitimate Domain"
        else:
            return "Suspicious or Unknown Domain"

    def scan_keywords(self, text: str, is_subject: bool = False) -> Dict[str, int]:
        """
        Scan text for suspicious keywords and return counts by risk level.
        Subject lines get higher weight.
        """
        text_lower = text.lower()
        results = {'high': 0, 'medium': 0, 'low': 0}
        multiplier = 2 if is_subject else 1
        
        for keyword in self.high_risk_keywords:
            count = len(re.findall(r'\b' + re.escape(keyword) + r'\b', text_lower))
            results['high'] += count * multiplier
        
        for keyword in self.medium_risk_keywords:
            count = len(re.findall(r'\b' + re.escape(keyword) + r'\b', text_lower))
            results['medium'] += count * multiplier
        
        for keyword in self.low_risk_keywords:
            count = len(re.findall(r'\b' + re.escape(keyword) + r'\b', text_lower))
            results['low'] += count * multiplier
        
        return results

    def calculate_keyword_score(self) -> int:
        """
        Calculate risk score based on keyword analysis.
        Weights:
        - Subject keywords are multiplied by 2
        - Early keywords (first 100 chars) give extra points
        """
        subject_results = self.scan_keywords(self.subject, is_subject=True)
        body_results = self.scan_keywords(self.body, is_subject=False)

        # Focus on early part of body
        early_body = self.body[:100] if len(self.body) > 100 else self.body
        early_results = self.scan_keywords(early_body, is_subject=False)

        score = 0
        # Base scores (1 point per keyword occurrence)
        score += subject_results['high'] + body_results['high']
        score += subject_results['medium'] + body_results['medium']
        score += subject_results['low'] + body_results['low']

        # Extra weight for early keywords
        score += early_results['high'] * 5
        score += early_results['medium'] * 3
        score += early_results['low'] * 1

        return score

    def similarity_ratio(self, a: str, b: str) -> float:
        """Calculate similarity ratio between two strings."""
        return SequenceMatcher(None, a, b).ratio()

    def _check_character_substitution(self, domain: str, legit_domain: str) -> bool:
        """Check for common phishing character substitutions (like 0 for o, 1 for l)."""
        substitutions = {
            "0": "o",
            "1": "l",
            "3": "e",
            "5": "s",
            "@": "a"
        }
        for fake, real in substitutions.items():
            if domain.replace(fake, real) == legit_domain:
                return True
        return False

    def detect_domain_spoofing(self) -> Tuple[bool, str]:
        """
        Detect if sender domain is visually similar to legitimate domains.
        Returns (is_suspicious, similar_domain).
        """
        sender_domain = self.extract_domain(self.sender_email)

        for legit_domain in self.legitimate_domains:
            similarity = self.similarity_ratio(sender_domain, legit_domain)

            # Check for high similarity but not exact match
            if 0.7 <= similarity < 1.0:
                return True, legit_domain

            # Check for suspicious substitutions
            if self._check_character_substitution(sender_domain, legit_domain):
                return True, legit_domain

        return False, ""

    def extract_links(self, text: str) -> List[str]:
        """Extract all URLs from text."""
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|' \
                      r'(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        return re.findall(url_pattern, text)

    def analyze_links(self, links: List[str], claimed_sender_domain: str) -> Dict[str, int]:
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

        suspicious_tlds = {'.tk', '.ml', '.ga', '.cf', '.top', '.click', '.download'}
        url_shorteners = {'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'short.link'}

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
                if any(shortener in domain for shortener in url_shorteners):
                    results['url_shorteners'] += 1

                # Check for suspicious TLDs
                if any(domain.endswith(tld) for tld in suspicious_tlds):
                    results['suspicious_tlds'] += 1

                # Check for domain mismatch
                if claimed_sender_domain and claimed_sender_domain not in domain:
                    legitimate_services = {'google.com', 'microsoft.com', 'amazon.com'}
                    if not any(service in domain for service in legitimate_services):
                        results['mismatched_domains'] += 1

            except Exception:
                results['mismatched_domains'] += 1

        return results

    def link_analysis(self) -> str:
        """User-facing summary of link analysis."""
        links = self.extract_links(self.body)
        if not links:
            return "No links found"

        claimed_domain = self.extract_domain(self.sender_email)
        analysis = self.analyze_links(links, claimed_domain)

        return (
            f"Links found: {', '.join(links)}\n"
            f"Suspicious IP links: {analysis['ip_addresses']}\n"
            f"Mismatched domains: {analysis['mismatched_domains']}\n"
            f"Suspicious TLDs: {analysis['suspicious_tlds']}\n"
            f"URL shorteners: {analysis['url_shorteners']}"
        )

    def calculate_score(self, sender_email: str, subject: str, body: str) -> Dict:
        """
        Calculate total risk score and classification based on email analysis.
        Returns a dictionary with individual scores and final classification.
        """
        # Initialize results dictionary
        results = {
            'sender_email': sender_email,
            'subject': subject,
            'analysis': {},
            'total_score': 0,
            'classification': 'Safe'
        }

        # 1. Domain check
        domain_safe = self.is_domain_safe(sender_email)
        results['analysis']['domain_safe'] = domain_safe
        domain_score = 0 if domain_safe else 10  # adjust weight as needed

        # 2. Keyword analysis
        keyword_score = self.calculate_keyword_score(subject, body)
        results['analysis']['keyword_score'] = keyword_score

        # 3. Domain spoofing
        is_spoofed, similar_domain = self.detect_domain_spoofing(sender_email)
        results['analysis']['domain_spoofing'] = {
            'is_suspicious': is_spoofed,
            'similar_to': similar_domain
        }
        spoofing_score = 15 if is_spoofed else 0

        # 4. Link analysis
        sender_domain = self.extract_domain(sender_email)
        link_score = self.calculate_link_score(subject, body, sender_domain)
        results['analysis']['link_score'] = link_score

        # 5. Total score
        total_score = domain_score + keyword_score + spoofing_score + link_score
        results['total_score'] = total_score

        # 6. Classification
        if total_score >= 50:
            results['classification'] = 'Phishing'
        elif total_score >= 20:
            results['classification'] = 'Suspicious'
        else:
            results['classification'] = 'Safe'

        return results

    def analyze(self) -> Dict:
    """
    Perform full phishing email analysis using the class methods.
    Returns a dictionary with detailed analysis, scores, and classification.
    """
    # 1. Check domain safety
    domain_safe = self.check_domain()
    
    # 2. Keyword analysis
    keyword_score = self.calculate_keyword_score()
    
    # 3. Domain spoofing detection
    is_spoofed, similar_domain = self.detect_domain_spoofing()
    
    # 4. Link analysis
    link_analysis_summary = self.link_analysis()
    
    # 5. Total score and classification
    total_results = self.calculate_score(self.sender_email, self.subject, self.body)
    
    # 6. Prepare final analysis dictionary
    results = {
        "senderEmail": self.sender_email,
        "subjectMessage": self.subject,
        "bodyMessage": self.body,
        "domainStatus": domain_safe,
        "keywordScore": keyword_score,
        "domainSpoofing": {
            "isSuspicious": is_spoofed,
            "similarTo": similar_domain
        },
        "linkAnalysis": link_analysis_summary,
        "totalRiskScore": total_results['total_score'],
        "classification": total_results['classification']
    }
    
    return results

