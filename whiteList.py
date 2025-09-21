from flask import Flask, request, render_template
import re
import csv

class whitelistCheck:

    def __init__(self, data):
        self.data = data
        self.unique_domains = set()
        self.whiteList = {'gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com', 'aol.com',
                        'icloud.com', 'protonmail.com', 'amazon.com', 'microsoft.com',
                        'google.com', 'apple.com', 'facebook.com', 'twitter.com',
                        'linkedin.com', 'github.com', 'stackoverflow.com', 'reddit.com',
                        'paypal.com', 'ebay.com', 'netflix.com', 'spotify.com'
                        }

        # Add counters
        self.whitelisted_count = 0
        self.non_whitelisted_count = 0
        self.total_domains = 0

    #Extract sender's email domain only (after @)
    def extract_emailDomain(self):
        self.unique_domains = set()

        # Normalize input: make sure it's a list of lists
        if isinstance(self.data, str):
            data_list = [[self.data]]
        elif isinstance(self.data, list):
            # If it's a list of strings, wrap each string
            if all(isinstance(item, str) for item in self.data):
                data_list = [[item] for item in self.data]
            else:
                data_list = self.data
        else:
            data_list = []

        for sender in data_list:
            try:
                sender_str = str(sender[0]).encode('utf-8', errors='replace').decode('utf-8')
                email_pattern = r'[a-zA-Z0-9._%+-]+@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})'
                match = re.search(email_pattern, sender_str)
                if match:
                    domain = match.group(1).lower()
                    self.unique_domains.add(domain)
            except Exception as e:
                print(f"Error processing: {sender}, error: {e}")
                continue

        return list(self.unique_domains)


    def check_against_whitelist(self):
        """Check domains against whitelist"""
        if not self.unique_domains:
            self.extract_emailDomain()

         # Reset counters
        self.whitelisted_count = 0
        self.non_whitelisted_count = 0
        self.total_domains = len(self.unique_domains)  # Use unique count

        

        # Check each unique domain against whitelist
        for domain in self.unique_domains:
            is_whitelisted = domain in self.whiteList
            
            if is_whitelisted:
                self.whitelisted_count += 1
            else:
                self.non_whitelisted_count += 1
                
            # results.append({
            #     'domain': domain,
            #     'status': '✅ Whitelisted' if is_whitelisted else '❌ Not Whitelisted'
            # })
            results = "✅ Whitelisted" if is_whitelisted else "❌ Not Whitelisted"
        
        return results

    def get_stats(self):
        """Get statistics about the check"""
        return {
            'total': self.total_domains,
            'whitelisted': self.whitelisted_count,
            'non_whitelisted': self.non_whitelisted_count,
            'whitelisted_percentage': (self.whitelisted_count / self.total_domains * 100) if self.total_domains > 0 else 0
        }