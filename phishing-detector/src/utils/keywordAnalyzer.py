import re 
def scanKeywords(text: str, keywords: set, isSubject: bool = False) -> int:
    textLower = text.lower()
    count = 0
    multiplier = 2 if isSubject else 1
    
    for keyword in keywords:
        count += len(re.findall(r'\b' + re.escape(keyword) + r'\b', textLower)) * multiplier
        
    return count

def calculateKeywordScore(subject: str, body: str, highRiskkeywords: set, mediumRiskkeywords: set, lowRiskkeywords: set) -> int:
    subjectScore = scanKeywords(subject, highRiskkeywords, isSubject=True)
    bodyScore = scanKeywords(body, highRiskkeywords) + scanKeywords(body, mediumRiskkeywords) + scanKeywords(body, lowRiskkeywords)
    
    earlyBody = body[:100] if len(body) > 100 else body
    earlyScore = scanKeywords(earlyBody, highRiskkeywords) * 5
    
    totalScore = 1 + subjectScore + bodyScore + earlyScore
    return totalScore