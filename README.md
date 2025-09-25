# 🛡️ Phishing Email Detection System

A comprehensive Python-based system for detecting phishing emails using multiple analysis techniques and risk scoring.

## ✨ Features

- **Domain Whitelist Verification**: Checks if sender domains are on a predefined safe list
- **Keyword Analysis**: Scans subject and body for suspicious keywords with weighted scoring
- **Position-Based Risk Assessment**: Higher scores for suspicious keywords in subject lines or early in messages
- **Domain Spoofing Detection**: Identifies visually similar fake domains using similarity algorithms
- **Suspicious Link Detection**: Detects IP addresses, mismatched domains, and suspicious TLDs
- **Comprehensive Risk Scoring**: Combines all analysis results for final classification
- **Multiple Classification Levels**: Safe, Suspicious, or Phishing

## 🚀 Quick Start

### Prerequisites
- Python 3.7 or higher
- No external dependencies required (uses only built-in Python modules)

### Installation

1. Clone or download the files to your local machine
2. Navigate to the project directory
3. Choose your preferred interface:

**Graphical Interface (Recommended):**
```bash
python "start phishing detector.py"
# Or on Windows, double-click: start_gui.bat
```

**Command Line Interface:**
```bash
python example_usage.py
```

### Basic Usage

```python
import importlib.util
import sys

# Load the backend module
spec = importlib.util.spec_from_file_location("phishing_detector_backend", "phishing detector system (back end).py")
phishing_detector_backend = importlib.util.module_from_spec(spec)
sys.modules["phishing_detector_backend"] = phishing_detector_backend
spec.loader.exec_module(phishing_detector_backend)

PhishingDetector = phishing_detector_backend.PhishingDetector

# Initialize the detector
detector = PhishingDetector()

# Analyze an email
results = detector.analyze_email(
    sender_email="suspicious@fake-paypal.com",
    subject="URGENT: Account Suspended",
    body="Click here to verify your account: http://192.168.1.100/login"
)

# Print detailed analysis
detector.print_analysis(results)

# Access results programmatically
print(f"Classification: {results['classification']}")
print(f"Risk Score: {results['total_score']}")
```

## 📊 Analysis Components

### 1. Domain Safety Check
- Verifies sender domain against whitelist of known safe domains
- Includes major email providers and legitimate services
- **Score Impact**: +20 points if domain not in safe list

### 2. Keyword Analysis
- **High Risk Keywords** (10 points each): urgent, suspended, verify, click here, etc.
- **Medium Risk Keywords** (5 points each): free, deal, login, password, etc.  
- **Low Risk Keywords** (2 points each): promotion, newsletter, sale, etc.
- **Subject Line Bonus**: Keywords in subject get 2x multiplier
- **Early Message Bonus**: Keywords in first 100 characters get additional points

### 3. Domain Spoofing Detection
- Uses similarity algorithms to detect fake domains
- Checks for character substitutions (o→0, i→1, etc.)
- Compares against known legitimate domains
- **Score Impact**: +25 points if spoofing detected

### 4. Link Analysis
- **IP Address Links**: +15 points each
- **Mismatched Domains**: +10 points each  
- **Suspicious TLDs**: +8 points each (.tk, .ml, etc.)
- **URL Shorteners**: +5 points each

### 5. Classification Thresholds
- **Safe**: Score < 15
- **Suspicious**: Score 15-29
- **Phishing**: Score ≥ 30

## 🖥️ User Interface

### Graphical Interface (GUI)
The system includes a user-friendly graphical interface built with tkinter:

**Features:**
- 📧 Easy input fields for sender, subject, and body
- 🔍 One-click email analysis
- 🎨 Color-coded results (Green=Safe, Orange=Suspicious, Red=Phishing)
- 📊 Detailed analysis breakdown
- 📝 Pre-loaded example templates
- 🗑️ Clear/reset functionality
- ⚡ Real-time progress indicators

**Launch GUI:**
```bash
python "start phishing detector.py"
# Or on Windows: double-click start_gui.bat
```

### Command Line Interface
For users who prefer command-line interaction:
```bash
python example_usage.py  # Demo with test cases
python test_system.py    # Quick verification
```

## 🧪 Test Cases

The system includes comprehensive test cases demonstrating:

- ✅ Safe emails from legitimate sources
- ⚠️ Suspicious emails with concerning elements
- 🚨 Clear phishing attempts with multiple red flags

Available in both GUI (example templates) and command-line versions.

## 🎮 Interactive Mode

The example script includes an interactive mode where you can test your own emails:

```bash
python example_usage.py
# Follow prompts to enter interactive mode
```

## 🔧 Customization

### Adding Safe Domains
```python
detector.safe_domains.add('your-domain.com')
```

### Modifying Keywords
```python
# Add high-risk keywords
detector.high_risk_keywords.add('new-suspicious-term')

# Add legitimate domains for spoofing detection
detector.legitimate_domains.add('your-company.com')
```

### Adjusting Scoring
Modify the scoring weights in the respective methods:
- `calculate_keyword_score()`: Keyword scoring weights
- `calculate_link_score()`: Link analysis weights
- `analyze_email()`: Overall classification thresholds

## 📈 Performance Characteristics

- **Speed**: Analyzes emails in milliseconds
- **Memory**: Minimal memory footprint
- **Accuracy**: Multi-layered approach reduces false positives
- **Scalability**: Can process thousands of emails efficiently

## 🛠️ Advanced Features

### Extending the System

The modular design allows easy extension:

```python
class CustomPhishingDetector(PhishingDetector):
    def custom_analysis(self, email_data):
        # Add your custom analysis logic
        pass
    
    def analyze_email(self, sender_email, subject, body):
        # Call parent analysis
        results = super().analyze_email(sender_email, subject, body)
        
        # Add custom analysis
        custom_score = self.custom_analysis({'sender': sender_email, 'subject': subject, 'body': body})
        results['total_score'] += custom_score
        
        return results
```

## 📝 Example Output

```
============================================================
PHISHING EMAIL ANALYSIS REPORT
============================================================
Sender: security@payp4l.com
Subject: Security Alert: Unauthorized Access Detected
Classification: Phishing
Total Risk Score: 85
------------------------------------------------------------
Domain Safety: ✗ Not in safe list
Keyword Risk Score: 35
Domain Spoofing: ✗ Similar to paypal.com
Link Risk Score: 25
------------------------------------------------------------
⚠️  HIGH RISK: This email appears to be a phishing attempt!
============================================================
```

## 🤝 Contributing

Feel free to enhance the system by:
- Adding more sophisticated analysis techniques
- Improving keyword detection
- Enhancing domain spoofing detection
- Adding machine learning capabilities
- Implementing email parsing for real email files

## 📄 License

This project is open source and available under the MIT License.

## 📁 File Structure

**Core System Files:**
- `phishing detector system (back end).py` - Main detection system with all analysis features
- `phishing_gui.py` - Graphical user interface (tkinter-based)
- `start phishing detector.py` - Main GUI launcher script
- `start_gui.bat` - Windows batch file for easy GUI launch

**Testing & Examples:**
- `example_usage.py` - Interactive demo with test cases
- `test_system.py` - Simple verification tests
- `manual_test_example.py` - Expected output demonstration

**Documentation:**
- `README.md` - This comprehensive documentation
- `requirements.txt` - Dependencies (uses only built-in Python modules)

## ⚠️ Disclaimer

This system is designed for educational and demonstration purposes. While it implements industry-standard detection techniques, it should be used as part of a comprehensive email security strategy, not as the sole protection mechanism.
