from utils.domainAnalyzer import extractDomain, isDomainSafe, detectDomainSpoofing
from utils.keywordAnalyzer import scanKeywords, calculateKeywordScore
from utils.linkAnalyzer import extractLinks, analyzeLinks, calculateLinkScore
from config.keywords import highRiskkeywords, mediumRiskkeywords, lowRiskkeywords
from config.domains import whiteList, legitimateDomains
from typing import Dict

class phishingDetector:
    def __init__(self, senderEmail, subject, body):
        self.senderEmail = senderEmail
        self.subject = subject
        self.body = body
        self.whiteList = whiteList
        self.highRiskkeywords = highRiskkeywords
        self.mediumRiskkeywords = mediumRiskkeywords
        self.lowRiskkeywords = lowRiskkeywords
        self.legitimateDomains = legitimateDomains

    def analyze(self) -> Dict:
        domainSafe = isDomainSafe(self.senderEmail)
        domainScore = 0 if domainSafe else 10

        keywordScore = calculateKeywordScore(self.subject, self.body)

        isSpoofed, similar_domain = detectDomainSpoofing(self.senderEmail)
        spoofingScore = 15 if isSpoofed else 0

        senderDomain = extractDomain(self.senderEmail)
        linkScore = calculateLinkScore(self.subject, self.body, senderDomain)

        totalScore = domainScore + keywordScore + spoofingScore + linkScore

        classification = "✅ LOW RISK: This email appears to be safe."
        if totalScore >= 30:
            classification = "🚨  HIGH RISK: This email appears to be a phishing attempt!"
        elif totalScore >= 15:
            classification = "⚠️  MEDIUM RISK: This email contains suspicious elements."

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
            "linkAnalysis": analyzeLinks(extractLinks(self.body), extractDomain(self.senderEmail)),
            "totalRiskScore": totalScore,
            "classification": classification
        }

        return results