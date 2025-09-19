from inspect import getblock
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import re
import csv
from flask import Flask, render_template, request

from openData import readFile
from whiteList import whitelistCheck
from detectKeyword import detectionKeyword

# Load phishing email datasets
paths = "dataSets/CEAS_08.csv"

readCsv = readFile(paths)            #Input csv file
readCsv.read_csv()                     #Read csv file
#readCsv.print_data()

getEmail = whitelistCheck(readCsv.data)
getEmail.extract_emailDomain()        #Print sender's domain
getEmail.check_against_whitelist()
print(getEmail.get_stats())

getBody = detectionKeyword(readCsv.data)
getBody.extract_messageBody()
print('subject:', getBody.analyze_subject(), '\nbody:', getBody.analyze_message())

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/submit', methods=['POST'])
def submit_data():
    sender_email = request.form['sender_email']
    receiver_email = request.form['receiver_email']
    subject = request.form['subject']
    body = request.form['body']
    url = request.form['url']

   # Run phishing detection
    getEmail = whitelistCheck(sender_email)
    emailStats = getEmail.extract_emailDomain()        #Print sender's domain
    getEmail.check_against_whitelist()
    getEmail.get_stats()

    getBody = detectionKeyword(subject + body)
    getBody.extract_messageBody()
    subject_analysis = getBody.analyze_subject()
    body_analysis = getBody.analyze_message()
    
    result = f"Email Stats: {sender_email}, \nSubject Analysis: {subject}, \nBody Analysis: {body}"
    return render_template("index.html", result=result)

if __name__ == '__main__':
    app.run(debug=True)
