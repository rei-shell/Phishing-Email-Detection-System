import re 

'''Extract URLs from text using regex.'''
def scanKeywords(text: str, keywords: set, isSubject: bool = False) -> int:
    # Convert text to lowercase so that we wont be affected by case sensitivity
    textLower = text.lower()
    count = 0
    multiplier = 2 if isSubject else 1
    
    #create a loop to go through each keyword in the set and count how many times it appears.
    for keyword in keywords:
        count += len(re.findall(r'\b' + re.escape(keyword) + r'\b', textLower)) * multiplier
        
    return count

'''Calculate a risk score based on the presence of keywords in the subject and body of the email.'''
def calculateKeywordScore(subject: str, body: str, highRiskkeywords: set, mediumRiskkeywords: set, lowRiskkeywords: set) -> int:
    #using the scanKeywords function to get the score for each section of the email
    subjectScore = scanKeywords(subject, highRiskkeywords, isSubject=True)
    bodyScore = scanKeywords(body, highRiskkeywords) + scanKeywords(body, mediumRiskkeywords) + scanKeywords(body, lowRiskkeywords)
    
    # Scan the first 100 characters of the body for high-risk keywords and then using scanKeywords function to find the sus words and then multiply the score by 5
    earlyBody = body[:100] if len(body) > 100 else body
    earlyScore = scanKeywords(earlyBody, highRiskkeywords) * 5
    
    totalScore = 1 + subjectScore + bodyScore + earlyScore
    return totalScore