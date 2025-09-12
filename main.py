from inspect import getblock
import pandas as pd
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from email_validator import validate_email, EmailNotValidError
import re
import csv

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
