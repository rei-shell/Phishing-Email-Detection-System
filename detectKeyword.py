import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import re
import csv

class detectionKeyword:

    def __init__(self, data):
        self.data = data
        self.unique_subject = set()
        self.unique_message = set()
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

    def extract_messageBody(self):
        self.unique_subject = set()
        self.unique_message = set()

        if self.data:
            for row in self.data:  # Changed from 'sender' to 'row' for clarity
                try:
                    # Assuming your CSV structure has subject at index 3 and message at index 4
                    subject = str(row[3]) if len(row) > 3 else ""
                    message = str(row[4]) if len(row) > 4 else ""

                    self.unique_subject.add(subject)
                    self.unique_message.add(message)
                except Exception as e:
                    print(f"Error processing row: {row}, error: {e}")
                    continue

        # Return both subject and message data
        return {
            'subjects': list(self.unique_subject),
            'messages': list(self.unique_message)
        }

    def check_for_keywords(self, text: str, is_subject: bool):
        """Check if any keywords are present in the given text"""
        text_lower = text.lower()
        found_keywords = {'high': 0, 'medium': 0, 'low': 0}
        multiplier = 2 if is_subject else 1
        for keyword in self.highRiskkeywords:
            if keyword.lower() in text_lower:
                count = len(re.findall(r'\b' + re.escape(keyword) + r'\b', text_lower))
                found_keywords['high'] += count * multiplier
        for keyword in self.mediumRiskkeywords:
            if keyword.lower() in text_lower:
                count = len(re.findall(r'\b' + re.escape(keyword) + r'\b', text_lower))
                found_keywords['medium'] += count * multiplier
        for keyword in self.lowRiskkeywords:
            if keyword.lower() in text_lower:
                count = len(re.findall(r'\b' + re.escape(keyword) + r'\b', text_lower))
                found_keywords['low'] += count * multiplier
        return found_keywords

    def analyze_subject(self):
        subjectScore = 0
        for subject in self.unique_subject:
            anslyzeSubject = self.check_for_keywords(subject, True)
            subjectScore += anslyzeSubject['high'] * 10
            subjectScore += anslyzeSubject['medium'] * 5
            subjectScore += anslyzeSubject['low'] * 2
        return subjectScore
 
    def analyze_message(self):
        messageScore = 0
        for message in self.unique_message:
            anslyzeSubject = self.check_for_keywords(message, False)
            messageScore += anslyzeSubject['high'] * 5
            messageScore += anslyzeSubject['medium'] * 3
            messageScore += anslyzeSubject['low'] * 1
        return messageScore