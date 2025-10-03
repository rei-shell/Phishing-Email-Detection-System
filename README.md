# Phishing Email Detection System (INF1002 P15-1)

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

### Prerequisites
- Python 3.7 or higherjjjjjjj
- No external dependencies required (uses only built-in Python modules)

### Installation

1. Clone or download the files to your local machine
2. Navigate to the project directory
3. Choose your preferred interface:

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

## PhisingDetector Components

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

## 🧪 Test Cases

The system includes comprehensive test cases demonstrating:

-  Safe emails from legitimate sources
-  Suspicious emails with concerning elements
-  Clear phishing attempts with multiple red flags

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
score is adjusted in the respective methods:
- `calculateKeywordScore()`: Keyword scoring weights
- `calculateLinkScore()`: Link analysis weights
- `analyze()`: Overall classification thresholds

## 📝 Example Output

![alt text](https://github.com/rei-shell/Phishing-Email-Detection-System/blob/main/outCome.png "Example Output")
