#!/usr/bin/env python3
"""
Example usage of the Phishing Detection System
Demonstrates various test cases including safe emails, suspicious emails, and phishing attempts.
"""

import importlib.util
import sys

# Load the module with spaces in filename
spec = importlib.util.spec_from_file_location("phishing_detector_backend", "phishing detector system (back end).py")
phishing_detector_backend = importlib.util.module_from_spec(spec)
sys.modules["phishing_detector_backend"] = phishing_detector_backend
spec.loader.exec_module(phishing_detector_backend)

PhishingDetector = phishing_detector_backend.PhishingDetector


def main():
    # Initialize the phishing detector
    detector = PhishingDetector()
    
    print("🛡️  PHISHING EMAIL DETECTION SYSTEM DEMO")
    print("This demo shows various email examples and their analysis results.\n")
    
    # Test cases
    test_emails = [
        {
            "name": "Safe Email - Gmail Newsletter",
            "sender": "newsletter@gmail.com",
            "subject": "Weekly Tech Updates",
            "body": "Here are this week's latest technology news and updates. Click unsubscribe if you no longer wish to receive these emails."
        },
        {
            "name": "Suspicious Email - Urgent Request",
            "sender": "support@company-updates.com",
            "subject": "URGENT: Account Verification Required",
            "body": "Your account has been suspended due to suspicious activity. Please verify your account immediately by clicking here: http://verify-account.com/login"
        },
        {
            "name": "Phishing Email - PayPal Fake",
            "sender": "security@payp4l.com",
            "subject": "Security Alert: Unauthorized Access Detected",
            "body": "We detected unauthorized access to your PayPal account. Click here immediately to secure your account: http://192.168.1.100/paypal-security. Verify your credit card details now or your account will be permanently suspended."
        },
        {
            "name": "Phishing Email - Prize Scam",
            "sender": "winner@lottery-international.tk",
            "subject": "Congratulations! You've Won $1,000,000!",
            "body": "You are the lucky winner of our international lottery! To claim your prize of $1,000,000, click here: http://bit.ly/claim-prize and provide your bank account details for the transfer."
        },
        {
            "name": "Safe Email - Amazon Order",
            "sender": "orders@amazon.com",
            "subject": "Your Order Confirmation",
            "body": "Thank you for your recent purchase. Your order will be delivered within 2-3 business days. Track your package at https://amazon.com/track-package"
        },
        {
            "name": "Suspicious Email - Domain Spoofing",
            "sender": "security@microsft.com",
            "subject": "Microsoft Account Security Update",
            "body": "We need to update your Microsoft account security settings. Please login at http://account-security.microsft.com to continue using our services."
        }
    ]
    
    # Analyze each test email
    for i, email in enumerate(test_emails, 1):
        print(f"\n📧 TEST CASE {i}: {email['name']}")
        
        # Perform analysis
        results = detector.analyze_email(
            sender_email=email['sender'],
            subject=email['subject'],
            body=email['body']
        )
        
        # Print results
        detector.print_analysis(results)
        
        # Add some spacing between test cases
        if i < len(test_emails):
            print("\n" + "🔄" * 20 + " NEXT TEST CASE " + "🔄" * 20)
    
    # Summary statistics
    print("\n" + "📊" * 30)
    print("DETECTION SYSTEM SUMMARY")
    print("📊" * 30)
    
    classifications = {}
    for email in test_emails:
        results = detector.analyze_email(
            sender_email=email['sender'],
            subject=email['subject'],
            body=email['body']
        )
        classification = results['classification']
        classifications[classification] = classifications.get(classification, 0) + 1
    
    print(f"Total emails analyzed: {len(test_emails)}")
    for classification, count in classifications.items():
        print(f"{classification}: {count} emails")
    
    print("\n✅ Demo completed! The system successfully identified various types of threats.")


def interactive_mode():
    """Interactive mode for testing custom emails."""
    detector = PhishingDetector()
    
    print("\n🔍 INTERACTIVE MODE")
    print("Enter your own email details for analysis:")
    print("(Press Ctrl+C to exit)\n")
    
    try:
        while True:
            print("-" * 50)
            sender = input("Enter sender email: ").strip()
            if not sender:
                print("Sender email cannot be empty!")
                continue
            
            subject = input("Enter email subject: ").strip()
            if not subject:
                print("Subject cannot be empty!")
                continue
            
            print("Enter email body (press Enter twice when done):")
            body_lines = []
            while True:
                line = input()
                if line == "":
                    if body_lines and body_lines[-1] == "":
                        break
                body_lines.append(line)
            
            body = "\n".join(body_lines[:-1])  # Remove the last empty line
            
            # Analyze the email
            results = detector.analyze_email(sender, subject, body)
            detector.print_analysis(results)
            
            # Ask if user wants to continue
            continue_analysis = input("\nAnalyze another email? (y/n): ").strip().lower()
            if continue_analysis != 'y':
                break
    
    except KeyboardInterrupt:
        print("\n\nExiting interactive mode...")


if __name__ == "__main__":
    # Run the demo
    main()
    
    # Ask if user wants to try interactive mode
    print("\n" + "🎮" * 20)
    try_interactive = input("Would you like to try interactive mode? (y/n): ").strip().lower()
    if try_interactive == 'y':
        interactive_mode()
    
    print("\nThank you for using the Phishing Detection System! 🛡️")
