#!/usr/bin/env python3
"""
Phishing Email Detection System - Graphical User Interface
A simple and intuitive GUI for analyzing emails for phishing attempts.
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from tkinter import font as tkFont
import threading
import importlib.util
import sys

# Load the module with spaces in filename
spec = importlib.util.spec_from_file_location("phishing_detector_backend", "phishing detector system (back end).py")
phishing_detector_backend = importlib.util.module_from_spec(spec)
sys.modules["phishing_detector_backend"] = phishing_detector_backend
spec.loader.exec_module(phishing_detector_backend)

PhishingDetector = phishing_detector_backend.PhishingDetector


class PhishingDetectorGUI:
    """GUI application for the Phishing Email Detection System."""
    
    def __init__(self, root):
        self.root = root
        self.detector = PhishingDetector()
        self.setup_gui()
        
    def setup_gui(self):
        """Initialize and configure the GUI components."""
        # Configure main window
        self.root.title("🛡️ Phishing Email Detection System")
        self.root.geometry("900x700")
        self.root.minsize(800, 600)
        
        # Configure styles
        style = ttk.Style()
        style.theme_use('clam')
        
        # Create main container with padding
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights for responsive design
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        
        # Title
        title_font = tkFont.Font(family="Arial", size=16, weight="bold")
        title_label = ttk.Label(main_frame, text="🛡️ Phishing Email Detection System", font=title_font)
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 20))
        
        # Input section
        self.create_input_section(main_frame)
        
        # Buttons section
        self.create_buttons_section(main_frame)
        
        # Results section
        self.create_results_section(main_frame)
        
        # Example templates section
        self.create_examples_section(main_frame)
        
    def create_input_section(self, parent):
        """Create the email input fields section."""
        # Input frame
        input_frame = ttk.LabelFrame(parent, text="📧 Email Details", padding="10")
        input_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        input_frame.columnconfigure(1, weight=1)
        
        # Sender email
        ttk.Label(input_frame, text="Sender Email:").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.sender_var = tk.StringVar()
        sender_entry = ttk.Entry(input_frame, textvariable=self.sender_var, width=50)
        sender_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(10, 0), pady=2)
        
        # Subject
        ttk.Label(input_frame, text="Subject:").grid(row=1, column=0, sticky=tk.W, pady=2)
        self.subject_var = tk.StringVar()
        subject_entry = ttk.Entry(input_frame, textvariable=self.subject_var, width=50)
        subject_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), padx=(10, 0), pady=2)
        
        # Email body
        ttk.Label(input_frame, text="Email Body:").grid(row=2, column=0, sticky=(tk.W, tk.N), pady=2)
        self.body_text = scrolledtext.ScrolledText(input_frame, height=8, width=60, wrap=tk.WORD)
        self.body_text.grid(row=2, column=1, sticky=(tk.W, tk.E), padx=(10, 0), pady=2)
        
    def create_buttons_section(self, parent):
        """Create the action buttons section."""
        button_frame = ttk.Frame(parent)
        button_frame.grid(row=2, column=0, columnspan=3, pady=10)
        
        # Analyze button
        self.analyze_btn = ttk.Button(
            button_frame, 
            text="🔍 Analyze Email", 
            command=self.analyze_email,
            style="Accent.TButton"
        )
        self.analyze_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        # Clear button
        clear_btn = ttk.Button(
            button_frame, 
            text="🗑️ Clear All", 
            command=self.clear_all
        )
        clear_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        # Progress bar (initially hidden)
        self.progress = ttk.Progressbar(button_frame, mode='indeterminate')
        self.progress.pack(side=tk.LEFT, padx=(20, 0))
        self.progress.pack_forget()  # Hide initially
        
    def create_results_section(self, parent):
        """Create the analysis results display section."""
        # Results frame
        results_frame = ttk.LabelFrame(parent, text="📊 Analysis Results", padding="10")
        results_frame.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        results_frame.columnconfigure(0, weight=1)
        parent.rowconfigure(3, weight=1)
        
        # Classification display
        self.classification_frame = ttk.Frame(results_frame)
        self.classification_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        
        self.classification_label = ttk.Label(
            self.classification_frame, 
            text="Classification: Not analyzed yet",
            font=tkFont.Font(size=12, weight="bold")
        )
        self.classification_label.pack()
        
        # Score display
        self.score_label = ttk.Label(
            self.classification_frame, 
            text="Risk Score: -",
            font=tkFont.Font(size=11)
        )
        self.score_label.pack()
        
        # Detailed results
        self.results_text = scrolledtext.ScrolledText(
            results_frame, 
            height=15, 
            width=80, 
            wrap=tk.WORD,
            state=tk.DISABLED
        )
        self.results_text.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure text tags for colored output
        self.results_text.tag_configure("safe", foreground="green", font=tkFont.Font(weight="bold"))
        self.results_text.tag_configure("suspicious", foreground="orange", font=tkFont.Font(weight="bold"))
        self.results_text.tag_configure("phishing", foreground="red", font=tkFont.Font(weight="bold"))
        self.results_text.tag_configure("header", foreground="blue", font=tkFont.Font(weight="bold"))
        self.results_text.tag_configure("detail", foreground="gray")
        
    def create_examples_section(self, parent):
        """Create the example templates section."""
        examples_frame = ttk.LabelFrame(parent, text="📝 Example Templates", padding="10")
        examples_frame.grid(row=4, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # Example buttons
        button_frame = ttk.Frame(examples_frame)
        button_frame.pack(fill=tk.X)
        
        examples = [
            ("Safe Email", self.load_safe_example),
            ("Suspicious Email", self.load_suspicious_example),
            ("Phishing Email", self.load_phishing_example)
        ]
        
        for i, (text, command) in enumerate(examples):
            btn = ttk.Button(button_frame, text=text, command=command)
            btn.pack(side=tk.LEFT, padx=(0, 10) if i < len(examples)-1 else 0)
    
    def load_safe_example(self):
        """Load a safe email example."""
        self.sender_var.set("newsletter@gmail.com")
        self.subject_var.set("Weekly Tech Updates")
        self.body_text.delete(1.0, tk.END)
        self.body_text.insert(1.0, 
            "Dear Subscriber,\n\n"
            "Here are this week's latest technology news and updates from our team. "
            "We hope you find these articles interesting and informative.\n\n"
            "Featured articles:\n"
            "• Latest developments in AI technology\n"
            "• New software development tools\n"
            "• Industry trends and analysis\n\n"
            "Visit our website at https://gmail.com for more content.\n\n"
            "Best regards,\n"
            "The Tech Newsletter Team\n\n"
            "If you no longer wish to receive these emails, you can unsubscribe at any time."
        )
    
    def load_suspicious_example(self):
        """Load a suspicious email example."""
        self.sender_var.set("support@account-security.com")
        self.subject_var.set("URGENT: Account Verification Required")
        self.body_text.delete(1.0, tk.END)
        self.body_text.insert(1.0, "We need to update your Microsoft account security settings. Please login at http://account-security.microsft.com to continue using our services."

        )
    
    def load_phishing_example(self):
        """Load a clear phishing email example."""
        self.sender_var.set("security@payp4l.com")
        self.subject_var.set("Security Alert: Unauthorized Access Detected!")
        self.body_text.delete(1.0, tk.END)
        self.body_text.insert(1.0,
            "URGENT SECURITY ALERT!\n\n"
            "We have detected unauthorized access attempts on your PayPal account. "
            "Your account has been temporarily suspended to protect your funds.\n\n"
            "IMMEDIATE ACTION REQUIRED:\n"
            "Click here to verify your account: http://192.168.1.100/paypal-security\n\n"
            "You must verify your credit card details and password within 2 hours "
            "or your account will be permanently closed and funds transferred to "
            "our security department.\n\n"
            "Congratulations! You have also been selected as a winner in our "
            "customer loyalty program and are eligible for a $500 cash prize.\n\n"
            "Act now - this offer expires soon!\n\n"
            "PayPal Security Team"
        )
    
    def clear_all(self):
        """Clear all input fields and results."""
        self.sender_var.set("")
        self.subject_var.set("")
        self.body_text.delete(1.0, tk.END)
        
        # Clear results
        self.classification_label.config(text="Classification: Not analyzed yet", foreground="black")
        self.score_label.config(text="Risk Score: -", foreground="black")
        
        self.results_text.config(state=tk.NORMAL)
        self.results_text.delete(1.0, tk.END)
        self.results_text.config(state=tk.DISABLED)
    
    def analyze_email(self):
        """Analyze the email and display results."""
        # Validate input
        if not self.sender_var.get().strip():
            messagebox.showwarning("Missing Input", "Please enter a sender email address.")
            return
        
        if not self.subject_var.get().strip():
            messagebox.showwarning("Missing Input", "Please enter an email subject.")
            return
        
        body_text = self.body_text.get(1.0, tk.END).strip()
        if not body_text:
            messagebox.showwarning("Missing Input", "Please enter email body content.")
            return
        
        # Show progress and disable button
        self.progress.pack(side=tk.LEFT, padx=(20, 0))
        self.progress.start()
        self.analyze_btn.config(state=tk.DISABLED)
        
        # Run analysis in separate thread to prevent GUI freezing
        def analyze_thread():
            try:
                results = self.detector.analyze_email(
                    sender_email=self.sender_var.get().strip(),
                    subject=self.subject_var.get().strip(),
                    body=body_text
                )
                
                # Update GUI in main thread
                self.root.after(0, lambda: self.display_results(results))
                
            except Exception as e:
                self.root.after(0, lambda: self.show_error(str(e)))
        
        threading.Thread(target=analyze_thread, daemon=True).start()
    
    def display_results(self, results):
        """Display the analysis results in the GUI."""
        # Hide progress and re-enable button
        self.progress.stop()
        self.progress.pack_forget()
        self.analyze_btn.config(state=tk.NORMAL)
        
        # Update classification display
        classification = results['classification']
        score = results['total_score']
        
        # Set classification with appropriate color
        color_map = {
            'Safe': 'green',
            'Suspicious': 'orange', 
            'Phishing': 'red'
        }
        
        self.classification_label.config(
            text=f"Classification: {classification}",
            foreground=color_map.get(classification, 'black')
        )
        
        self.score_label.config(
            text=f"Risk Score: {score}",
            foreground=color_map.get(classification, 'black')
        )
        
        # Display detailed results
        self.results_text.config(state=tk.NORMAL)
        self.results_text.delete(1.0, tk.END)
        
        # Format and insert results
        self.insert_formatted_results(results)
        
        self.results_text.config(state=tk.DISABLED)
    
    def insert_formatted_results(self, results):
        """Insert formatted analysis results into the text widget."""
        analysis = results['analysis']
        
        # Header
        self.results_text.insert(tk.END, "DETAILED ANALYSIS REPORT\n", "header")
        self.results_text.insert(tk.END, "=" * 50 + "\n\n")
        
        # Basic info
        self.results_text.insert(tk.END, f"Sender: {results['sender_email']}\n")
        self.results_text.insert(tk.END, f"Subject: {results['subject']}\n\n")
        
        # Domain safety
        domain_status = "✓ Safe domain" if analysis['domain_safe'] else "✗ Domain not in safe list"
        self.results_text.insert(tk.END, f"Domain Safety: {domain_status}\n")
        
        # Keyword analysis
        keyword_score = analysis['keyword_score']
        self.results_text.insert(tk.END, f"Keyword Risk Score: {keyword_score}\n")
        
        # Domain spoofing
        spoofing = analysis['domain_spoofing']
        if spoofing['is_suspicious']:
            spoofing_text = f"✗ Domain similar to {spoofing['similar_to']}"
        else:
            spoofing_text = "✓ No suspicious domain similarity"
        self.results_text.insert(tk.END, f"Domain Spoofing: {spoofing_text}\n")
        
        # Link analysis
        link_score = analysis['link_score']
        self.results_text.insert(tk.END, f"Link Risk Score: {link_score}\n\n")
        
        # Risk assessment
        self.results_text.insert(tk.END, "RISK ASSESSMENT:\n", "header")
        self.results_text.insert(tk.END, "-" * 20 + "\n")
        
        total_score = results['total_score']
        classification = results['classification']
        
        if classification == 'Phishing':
            self.results_text.insert(tk.END, "⚠️  HIGH RISK: This email appears to be a phishing attempt!\n", "phishing")
            self.results_text.insert(tk.END, "Recommendation: Do NOT click any links or provide personal information.\n", "detail")
        elif classification == 'Suspicious':
            self.results_text.insert(tk.END, "⚠️  MEDIUM RISK: This email contains suspicious elements.\n", "suspicious")
            self.results_text.insert(tk.END, "Recommendation: Exercise caution and verify sender through other means.\n", "detail")
        else:
            self.results_text.insert(tk.END, "✅ LOW RISK: This email appears to be safe.\n", "safe")
            self.results_text.insert(tk.END, "Recommendation: Email appears legitimate, but always stay vigilant.\n", "detail")
        
        # Scoring breakdown
        self.results_text.insert(tk.END, f"\nTotal Risk Score: {total_score}\n")
        self.results_text.insert(tk.END, "Score ranges: Safe (0-14), Suspicious (15-29), Phishing (30+)\n", "detail")
    
    def show_error(self, error_message):
        """Display error message."""
        # Hide progress and re-enable button
        self.progress.stop()
        self.progress.pack_forget()
        self.analyze_btn.config(state=tk.NORMAL)
        
        messagebox.showerror("Analysis Error", f"An error occurred during analysis:\n{error_message}")


def main():
    """Main function to run the GUI application."""
    root = tk.Tk()
    app = PhishingDetectorGUI(root)
    
    # Center window on screen
    root.update_idletasks()
    x = (root.winfo_screenwidth() // 2) - (root.winfo_width() // 2)
    y = (root.winfo_screenheight() // 2) - (root.winfo_height() // 2)
    root.geometry(f"+{x}+{y}")
    
    # Start the GUI event loop
    root.mainloop()


if __name__ == "__main__":
    main()
