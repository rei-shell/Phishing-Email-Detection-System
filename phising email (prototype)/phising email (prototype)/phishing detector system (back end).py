import re
import urllib.parse
from typing import List, Dict, Tuple
from difflib import SequenceMatcher
import ipaddress


class PhishingDetector:
    """
    A comprehensive phishing email detection system that analyzes emails
    for various suspicious patterns and assigns risk scores.
    """
    
    def __init__(self):
        # Predefined safe domains list
        self.safe_domains = {
            'gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com', 'aol.com',
            'icloud.com', 'protonmail.com', 'amazon.com', 'microsoft.com',
            'google.com', 'apple.com', 'facebook.com', 'twitter.com',
            'linkedin.com', 'github.com', 'stackoverflow.com', 'reddit.com',
            'paypal.com', 'ebay.com', 'netflix.com', 'spotify.com'
        }
        
        # Suspicious keywords categorized by risk level
        self.high_risk_keywords = {
            'urgent', 'immediate', 'suspended', 'verify', 'confirm', 'click here',
            'act now', 'limited time', 'expires', 'winner', 'congratulations',
            'prize', 'lottery', 'inheritance', 'transfer', 'beneficiary',
            'scam', 'fraud', 'phishing', 'security alert', 'account locked',
            'unauthorized', 'suspicious activity', 'update payment', 'billing issue'
        }
        
        self.medium_risk_keywords = {
            'free', 'offer', 'deal', 'discount', 'save money', 'cash',
            'investment', 'opportunity', 'guaranteed', 'risk-free',
            'no obligation', 'act fast', 'hurry', 'don\'t miss',
            'login', 'password', 'account', 'bank', 'credit card'
        }
        
        self.low_risk_keywords = {
            'promotion', 'newsletter', 'unsubscribe', 'marketing',
            'advertisement', 'sale', 'new product', 'update'
        }
        
        # Legitimate domains for similarity checking
        self.legitimate_domains = {
            'paypal.com', 'amazon.com', 'microsoft.com', 'google.com',
            'apple.com', 'facebook.com', 'twitter.com', 'linkedin.com',
            'github.com', 'netflix.com', 'spotify.com', 'ebay.com',
            'instagram.com', 'youtube.com', 'dropbox.com', 'adobe.com'
        }
    
    def extract_domain(self, email: str) -> str:
        """Extract domain from email address."""
        if '@' in email:
            return email.split('@')[1].lower()
        return email.lower()
    
    def is_domain_safe(self, email: str) -> bool:
        """Check if the sender's email domain is in the safe list."""
        domain = self.extract_domain(email)
        return domain in self.safe_domains
    
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
    
    def calculate_keyword_score(self, subject: str, body: str) -> int:
        """Calculate risk score based on keyword analysis."""
        subject_results = self.scan_keywords(subject, is_subject=True)
        body_results = self.scan_keywords(body, is_subject=False)
        
        # Check for keywords in early part of message (first 100 characters)
        early_body = body[:100] if len(body) > 100 else body
        early_results = self.scan_keywords(early_body, is_subject=False)
        
        # Calculate weighted score
        score = 0
        score += (subject_results['high'] + body_results['high']) * 1
        score += (subject_results['medium'] + body_results['medium']) * 1
        score += (subject_results['low'] + body_results['low']) * 1
        
        # Bonus for keywords appearing early in message
        score += early_results['high'] * 5
        score += early_results['medium'] * 3
        score += early_results['low'] * 1
        
        return score
    
    def similarity_ratio(self, a: str, b: str) -> float:
        """Calculate similarity ratio between two strings."""
        return SequenceMatcher(None, a, b).ratio()
    
    def detect_domain_spoofing(self, sender_email: str) -> Tuple[bool, str]:
        """
        Detect if sender domain is visually similar to legitimate domains.
        Returns (is_suspicious, similar_domain).
        """
        sender_domain = self.extract_domain(sender_email)
        
        for legit_domain in self.legitimate_domains:
            similarity = self.similarity_ratio(sender_domain, legit_domain)
            
            # Check for high similarity but not exact match
            if 0.7 <= similarity < 1.0:
                return True, legit_domain
            
            # Check for common character substitutions
            if self._check_character_substitution(sender_domain, legit_domain):
                return True, legit_domain
        
        return False, ""
    
    def _check_character_substitution(self, suspicious: str, legitimate: str) -> bool:
        """Check for common character substitutions in domain spoofing."""
        substitutions = {
            'o': '0', 'i': '1', 'l': '1', 'e': '3', 'a': '@',
            'g': '9', 's': '$', 'b': '6', 't': '7'
        }
        
        for char, replacement in substitutions.items():
            if char in legitimate and replacement in suspicious:
                test_domain = legitimate.replace(char, replacement)
                if test_domain == suspicious:
                    return True
        
        return False
    
    def extract_links(self, text: str) -> List[str]:
        """Extract all URLs from text."""
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
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
                    # Allow for subdomains of legitimate services
                    legitimate_services = {'google.com', 'microsoft.com', 'amazon.com'}
                    if not any(service in domain for service in legitimate_services):
                        results['mismatched_domains'] += 1
                
            except Exception:
                # If URL parsing fails, consider it suspicious
                results['mismatched_domains'] += 1
        
        return results
    
    def calculate_link_score(self, subject: str, body: str, sender_domain: str) -> int:
        """Calculate risk score based on link analysis."""
        all_text = subject + " " + body
        links = self.extract_links(all_text)
        
        if not links:
            return 0
        
        link_analysis = self.analyze_links(links, sender_domain)
        
        score = 0
        score += link_analysis['ip_addresses'] * 15
        score += link_analysis['mismatched_domains'] * 10
        score += link_analysis['suspicious_tlds'] * 8
        score += link_analysis['url_shorteners'] * 5
        
        return score
    
    def analyze_email(self, sender_email: str, subject: str, body: str) -> Dict:
        """
        Perform comprehensive analysis of an email.
        Returns detailed analysis results and classification.
        """
        results = {
            'sender_email': sender_email,
            'subject': subject,
            'analysis': {},
            'total_score': 0,
            'classification': 'Safe'
        }
        
        # 1. Check domain safety
        domain_safe = self.is_domain_safe(sender_email)
        results['analysis']['domain_safe'] = domain_safe
        domain_score = 0 if domain_safe else 20
        
        # 2. Keyword analysis
        keyword_score = self.calculate_keyword_score(subject, body)
        results['analysis']['keyword_score'] = keyword_score
        
        # 3. Domain spoofing detection
        is_spoofed, similar_domain = self.detect_domain_spoofing(sender_email)
        results['analysis']['domain_spoofing'] = {
            'is_suspicious': is_spoofed,
            'similar_to': similar_domain
        }
        spoofing_score = 25 if is_spoofed else 0
        
        # 4. Link analysis
        sender_domain = self.extract_domain(sender_email)
        link_score = self.calculate_link_score(subject, body, sender_domain)
        results['analysis']['link_score'] = link_score
        
        # 5. Calculate total score
        total_score = domain_score + keyword_score + spoofing_score + link_score
        results['total_score'] = total_score
        
        # 6. Classification
        if total_score >= 100:
            results['classification'] = 'Phishing'
        elif total_score >= 30:
            results['classification'] = 'Suspicious'
        else:
            results['classification'] = 'Safe'
        
        return results
    
    def print_analysis(self, results: Dict) -> None:
        """Print formatted analysis results."""
        print("=" * 60)
        print("PHISHING EMAIL ANALYSIS REPORT")
        print("=" * 60)
        print(f"Sender: {results['sender_email']}")
        print(f"Subject: {results['subject']}")
        print(f"Classification: {results['classification']}")
        print(f"Total Risk Score: {results['total_score']}")
        print("-" * 60)
        
        analysis = results['analysis']
        
        print(f"Domain Safety: {'✓ Safe' if analysis['domain_safe'] else '✗ Not in safe list'}")
        print(f"Keyword Risk Score: {analysis['keyword_score']}")
        
        spoofing = analysis['domain_spoofing']
        if spoofing['is_suspicious']:
            print(f"Domain Spoofing: ✗ Similar to {spoofing['similar_to']}")
        else:
            print("Domain Spoofing: ✓ No suspicious similarity detected")
        
        print(f"Link Risk Score: {analysis['link_score']}")
        
        print("-" * 60)
        if results['classification'] == 'Phishing':
            print("⚠️  HIGH RISK: This email appears to be a phishing attempt!")
        elif results['classification'] == 'Suspicious':
            print("⚠️  MEDIUM RISK: This email contains suspicious elements.")
        else:
            print("✅ LOW RISK: This email appears to be safe.")
        print("=" * 60)

'''
    def email_input():
        senderEmail = input("Enter email: ")
        subject = input("Enter subject: ")
        body = input("Enter body: ")
'''