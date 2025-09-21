from inspect import getblock
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import re
import csv
from flask import Flask, render_template, request, jsonify

from openData import readFile
from whiteList import whitelistCheck
from detectKeyword import detectionKeyword

# Load phishing email datasets
paths = "dataSets/CEAS_08.csv"

# Read CSV file
readCsv = readFile(paths)            #Input csv file
readCsv.read_csv()                     #Read csv file
#readCsv.print_data()

# Phishing detection
getEmail = whitelistCheck(readCsv.data)
getEmail.extract_emailDomain()        #Print sender's domain
getEmail.check_against_whitelist()
print(getEmail.get_stats())

# Analyze email subject and body
getBody = detectionKeyword(readCsv.data)
getBody.extract_messageBody()
print('subject:', getBody.analyze_subject(), '\nbody:', getBody.analyze_message())

#Link to Flask web application
app = Flask(__name__)

# Define routes
@app.route('/')
def index():
    return render_template('index.html')

# Handle form submission
@app.route('/submit', methods=['POST'])
def submit_data():
    if request.method == 'POST':
        sender_email = request.form['sender_email']
        message_data = {
            'subject': request.form['subject'],
            'body': request.form['body']
        }
        url = request.form['url']

    # Run phishing detection
        getEmail = whitelistCheck(sender_email)
        getEmail.extract_emailDomain()        #Print sender's domain
        emailStats = getEmail.check_against_whitelist()
        getEmail.get_stats()

        getBody = detectionKeyword(message_data)
        getBody.extract_messageBody()
        getBody.check_for_keywords(message_data['subject'], is_subject=True)
        getBody.check_for_keywords(message_data['body'], is_subject=False)
        subject_analysis = getBody.analyze_subject()
        body_analysis = getBody.analyze_message()
     
        return jsonify({
            'senderEmail': f"{sender_email}",
            'subjectMessage': f"{message_data['subject']}",
            'bodyMessage': f"{message_data['body']}",
            'url': f"{url}",
            'email': f"{emailStats}",
            'subject_score': subject_analysis,
            'body_score': body_analysis
        })
    else:
        return render_template("index.html", result="Error: Invalid request method.")
# Run the Flask app
# When testing your python code, delete this line first.
if __name__ == '__main__':
    app.run(debug=True)
