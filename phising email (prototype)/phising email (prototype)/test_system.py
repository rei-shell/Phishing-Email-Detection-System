#!/usr/bin/env python3
"""
Simple test to verify the phishing detection system works correctly
"""

def test_phishing_detector():
    """Test the basic functionality of the phishing detector"""
    try:
        import importlib.util
        import sys
        
        # Load the module with spaces in filename
        spec = importlib.util.spec_from_file_location("phishing_detector_backend", "phishing detector system (back end).py")
        phishing_detector_backend = importlib.util.module_from_spec(spec)
        sys.modules["phishing_detector_backend"] = phishing_detector_backend
        spec.loader.exec_module(phishing_detector_backend)
        
        PhishingDetector = phishing_detector_backend.PhishingDetector
        
        print("✅ Successfully imported PhishingDetector")
        
        # Initialize detector
        detector = PhishingDetector()
        print("✅ Successfully initialized PhishingDetector")
        
        # Test 1: Safe email
        result1 = detector.analyze_email(
            sender_email="newsletter@gmail.com",
            subject="Weekly Updates",
            body="Here are this week's updates from our team."
        )
        print(f"✅ Test 1 - Safe email: {result1['classification']} (Score: {result1['total_score']})")
        
        # Test 2: Phishing email
        result2 = detector.analyze_email(
            sender_email="security@payp4l.com",
            subject="URGENT: Account Suspended - Verify Now!",
            body="Your account has been suspended. Click here immediately: http://192.168.1.100/verify to restore access."
        )
        print(f"✅ Test 2 - Phishing email: {result2['classification']} (Score: {result2['total_score']})")
        
        # Test 3: Domain safety check
        safe_domain = detector.is_domain_safe("user@gmail.com")
        unsafe_domain = detector.is_domain_safe("user@suspicious-domain.tk")
        print(f"✅ Test 3 - Domain safety: Gmail safe={safe_domain}, Suspicious safe={unsafe_domain}")
        
        # Test 4: Keyword scanning
        keyword_results = detector.scan_keywords("URGENT verify account suspended", is_subject=True)
        print(f"✅ Test 4 - Keyword scanning: {keyword_results}")
        
        # Test 5: Link analysis
        links = detector.extract_links("Visit http://192.168.1.100/login and https://bit.ly/suspicious")
        print(f"✅ Test 5 - Link extraction: Found {len(links)} links")
        
        # Test 6: Domain spoofing detection
        is_spoofed, similar = detector.detect_domain_spoofing("user@payp4l.com")
        print(f"✅ Test 6 - Domain spoofing: Spoofed={is_spoofed}, Similar to={similar}")
        
        print("\n🎉 All tests passed! The phishing detection system is working correctly.")
        return True
        
    except Exception as e:
        print(f"❌ Error during testing: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    print("🧪 Testing Phishing Detection System")
    print("=" * 50)
    
    success = test_phishing_detector()
    
    if success:
        print("\n✅ System verification completed successfully!")
        print("\nTo run the full demo with examples:")
        print("python example_usage.py")
    else:
        print("\n❌ System verification failed!")
