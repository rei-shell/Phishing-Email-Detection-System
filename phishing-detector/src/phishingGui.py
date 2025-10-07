#import sys
#import os
#sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from flask import Flask, render_template, request, jsonify
from phishingDetectorBackEnd import phishingDetector  

app = Flask(__name__)

# Serve the HTML form
@app.route('/')
def home():
    return render_template("index.html")

# Handle the form submission
@app.route('/submit', methods=['POST'])
def submit():
    if request.method != "POST":
        return jsonify({"error": "Invalid request method"}), 400
    
    try:
        # Handle both JSON and form data
        if request.is_json:
            data = request.get_json()
            senderEmail = data.get('senderEmail')
            subject = data.get('subject')
            body = data.get('body')
        else:
            senderEmail = request.form.get('senderEmail')
            subject = request.form.get('subject')
            body = request.form.get('body')
        
        # Validate that all fields are present
        if not senderEmail or not subject or not body:
            return jsonify({"error": "Missing required fields"}), 400

        # Initialize phishing checker
        checker = phishingDetector(senderEmail, subject, body)
        results = checker.analyze()

        return jsonify(results)
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True)