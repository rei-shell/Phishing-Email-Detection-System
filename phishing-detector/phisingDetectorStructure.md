# README.md

# Phishing Email Detection System

## Overview

The Phishing Email Detection System is a Python-based application designed to analyze and detect potential phishing emails. It utilizes various algorithms to assess the risk associated with incoming emails based on sender information, subject lines, body content, and embedded links.

## Features

- **Domain Analysis**: Checks if the sender's email domain is safe and detects domain spoofing.
- **Keyword Analysis**: Scans email content for suspicious keywords that are commonly associated with phishing attempts.
- **Link Analysis**: Extracts and analyzes links within the email to identify potential threats.

## Project Structure

```
phishing-detector
├── src
│   ├── __init__.py
│   ├── phishingDetectorBackEnd.py
│   ├── utils
│   │   ├── __init__.py
│   │   ├── domain_analyzer.py
│   │   ├── keyword_analyzer.py
│   │   └── link_analyzer.py
│   └── config
│       ├── __init__.py
│       ├── keywords.py
│       └── domains.py
├── requirements.txt
└── README.md
```

## Installation

1. Clone the repository:
   ```
   git clone <repository-url>
   ```
2. Navigate to the project directory:
   ```
   cd phishing-detector
   ```
3. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

## Usage

To use the Phishing Email Detection System, instantiate the `phishingDetector` class from the `phishingDetectorBackEnd.py` file and provide the sender's email, subject, and body of the email to be analyzed.

```python
from src.phishingDetectorBackEnd import phishingDetector

detector = phishingDetector(senderEmail, subject, body)
results = detector.analyze()
print(results)
```

## Contributing

Contributions are welcome! Please feel free to submit a pull request or open an issue for any enhancements or bug fixes.

## License

This project is licensed under the MIT License. See the LICENSE file for more details.