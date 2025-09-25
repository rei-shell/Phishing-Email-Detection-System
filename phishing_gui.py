from flask import Flask, render_template, request, jsonify
from phishing_checker import PhishingDetector  # Make sure class name matches

app = Flask(__name__)

# Serve the HTML form
@app.route('/')
def home():
    return render_template("index.html")

# Handle the form submission
@app.route('/submit', methods=['POST'])
def submit():
    sender_email = request.form.get('sender_email', '')
    subject = request.form.get('subject', '')
    body = request.form.get('body', '')

    # Initialize phishing checker
    checker = PhishingDetector(sender_email, subject, body)
    results = checker.analyze()  # Returns structured analysis

    return jsonify(results)

if __name__ == "__main__":
    app.run(debug=True)
