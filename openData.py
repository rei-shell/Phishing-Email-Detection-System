import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import re
import csv

class readFile:
    def __init__(self, path):
        self.path = path
        self.data = []

    #Read csv file
    def read_csv(self):
        try:
            with open(self.path, 'r', newline='') as csvfile:
                reader = csv.reader(csvfile)
                self.header = next(reader)      #Read csv header
                for row in reader:
                    self.data.append(row)    #Read csv without header only data
            print(f"Successfully read data from {self.path}")
        except FileNotFoundError:
            print(f"Error: The file '{self.path}' was not found.")
        except Exception as e:
            print(f"An error occurred: {e}")

    #Print data for check
    def print_data(self):
        if self.data:
            print("CSV Header:", self.header)   #Print just header
            print("CSV Data:")
            for row in self.data:
                print(row)                      #Print just the data
        else:
            print("No data loaded. Please call read_csv_data() first.")