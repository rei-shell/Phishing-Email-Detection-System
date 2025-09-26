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