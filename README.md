# Phishing-Email-Detection-System (TEAM P15-1)

## Team Members: 
- Pek Qi Feng, 2502624, 2502624@sit.singaporetech.edu.sg
- Jomond Lim Zi Kang, 2500340, 2500340@sit.singaporetech.edu.sg
- Raphael Ang, 2500632, 2500632@sit.singaporetech.edu.sg
- Rachelle Ang, 2503641, 2503641@sit.singaporetech.edu.sg	

## Project Title: 
Phishing Email Detection System

## Short description: 
A comprehensive Python-based system for detecting phishing emails using multiple analysis techniques and risk scoring.

## Team Allocation:
- Qi Feng: Suspicious URL Detection, Edit Distance Check
- Jomond: Final Risk Score
- Raphael: Whitelist Check, Keyword Detection
- Rachelle: Keyword Position Scoring, WebPage

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
python "startPhishingDetector.py"
# Or on Windows, double-click: start_gui.bat
```

**Command Line Interface:**
```bash
python example_usage.py
```

### Basic Usage

```python
from flask import Flask, render_template, request, jsonify
import importlib.util
import sys

# Dynamically import phishingDetectorBackEnd.py
spec = importlib.util.spec_from_file_location("phishingDetectorBackEnd", "./phishingDetectorBackEnd.py")
phishing_module = importlib.util.module_from_spec(spec)
sys.modules["phishingDetectorBackEnd"] = phishing_module
spec.loader.exec_module(phishing_module)

# Now you can use phishingDetector from the loaded module
phishingDetector = phishing_module.phishingDetector  

app = Flask(__name__)

# Serve the HTML form
@app.route('/')
def home():
    return render_template("index.html")

# Handle the form submission
@app.route('/submit', methods=['POST'])
def submit():
    if request.method != "POST":
        return render_template("index.html", result="Error: Invalid request method.")
    else:
        senderEmail = request.form['senderEmail']
        subject = request.form['subject']
        body = request.form['body']

        # Initialize phishing checker
        checker = phishingDetector(senderEmail, subject, body)
        results = checker.analyze()

        return jsonify(results)

if __name__ == "__main__":
    app.run(debug=True)

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
The system includes a user-friendly graphical interface built with html, css and javascript:

**Features:**
- 📧 Easy input fields for sender, subject, and body
- 🔍 One-click email analysis
- 🎨 Color-coded results (Green=Safe, Orange=Suspicious, Red=Phishing)
- 📊 Detailed analysis breakdown

**Launch GUI:**
```bash
python "startPhishingDetector.py"
# Or on Windows: double-click start_gui.bat
```

### Command Line Interface
For users who prefer command-line interaction:
```bash
python exampleUsage.py  # Demo with test cases
python testSystem.py    # Quick verification
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
- `calculateKeywordScore()`: Keyword scoring weights
- `calculateLinkScore()`: Link analysis weights
- `analyze()`: Overall classification thresholds

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
    def customAnalysis(self, emailData):
        # Add your custom analysis logic
        pass
    
    def analyze(self, senderEmail, subject, body):
        # Call parent analysis
        results = super().analyzeEmail(senderEmail, subject, body)
        
        # Add custom analysis
        customScore = self.customAnalysis({'sender': senderEmail, 'subject': subject, 'body': body})
        results['totalScore'] += customScore
        
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
- `phishingDetectorBackEnd.py` - Main detection system with all analysis features
- `phishingGui.py` - Graphical user interface (html-based)
- `startPhishingDetector.py` - Main GUI launcher script
- `startGui.bat` - Windows batch file for easy GUI launch

**Testing & Examples:**
- `exampleUsage.py` - Interactive demo with test cases
- `testSystem.py` - Simple verification tests
- `manualTestExample.py` - Expected output demonstration

**Documentation:**
- `README.md` - This comprehensive documentation
- `requirements.txt` - Dependencies (uses only built-in Python modules)

## ⚠️ Disclaimer

This system is designed for educational and demonstration purposes. While it implements industry-standard detection techniques, it should be used as part of a comprehensive email security strategy, not as the sole protection mechanism.