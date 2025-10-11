from domainAnalyzer import extractDomain, isDomainSafe, detectDomainSpoofing
from keywordAnalyzer import calculateKeywordScore
from linkAnalyzer import extractLinks, analyzeLinks, calculateLinkScore
from keywords import highRiskKeywords, mediumRiskKeywords, lowRiskKeywords
from domains import whiteList, legitimateDomains
from typing import Dict

''' This class is responsible for analyzing emails to detect potential phishing attempts. 
It uses various modules to evaluate the sender's domain, keywords in the email content, and links within the email.'''
class phishingDetector:
    '''When initializing the class, the sender's email, subject, and body are place as input, 
    when then placed into class variables, as well call upon our modules to import the keyword list and the domain list'''
    def __init__(self, senderEmail, subject, body):
        self.senderEmail = senderEmail
        self.subject = subject
        self.body = body
        self.whiteList = whiteList
        self.highRiskKeywords = highRiskKeywords
        self.mediumRiskKeywords = mediumRiskKeywords
        self.lowRiskKeywords = lowRiskKeywords
        self.legitimateDomains = legitimateDomains

    ''' This function is the main function that analyzes the email, the email is first placed into a dictionary format. 
    After which it is use to call other modules to perform the analysis and return the results'''
    def analyze(self) -> Dict:
        domainSafe = isDomainSafe(self.senderEmail, self.whiteList)
        domainScore = 0 if domainSafe else 10

        keywordScore = calculateKeywordScore(self.subject, self.body, self.highRiskKeywords, self.mediumRiskKeywords, self.lowRiskKeywords)

        isSpoofed, similarDomain = detectDomainSpoofing(self.senderEmail,self.legitimateDomains)
        spoofingScore = 15 if isSpoofed else 0

        senderDomain = extractDomain(self.senderEmail)
        linkScore = calculateLinkScore(self.subject, self.body, senderDomain)

        totalScore = domainScore + keywordScore + spoofingScore + linkScore

        classification = "LOW RISK: This email appears to be safe."
        if totalScore >= 30:
            classification = "HIGH RISK: This email appears to be a phishing attempt!"
        elif totalScore >= 15:
            classification = "MEDIUM RISK: This email contains suspicious elements."

        results = {
            "senderEmail": self.senderEmail,
            "subjectMessage": self.subject,
            "bodyMessage": self.body,
            "domainSafe": domainSafe,
            "keywordScore": keywordScore,
            "domainSpoofing": {
                "isSuspicious": isSpoofed,
                "similarTo": similarDomain
            },
            "linkAnalysis": analyzeLinks(extractLinks(self.subject + " " + self.body), extractDomain(self.senderEmail)),
            "totalRiskScore": totalScore,
            "classification": classification
        }

        return results
    
#def analyzeEmail(senderEmail: str, subject: str, body: str) -> Dict:
#    """function for callers that don't want to instantiate the class."""
#    return phishingDetector(senderEmail, subject, body).analyze()