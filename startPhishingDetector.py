#!/usr/bin/env python3
"""
Simple launcher for the Phishing Detection System GUI
Run this file to start the graphical user interface.
"""

import sys
import os

def main():
    """Launch the Phishing Detection System GUI."""
    try:
        print("🛡️ Starting Phishing Detection System GUI...")
        print("Loading interface components...")
        
        # Import and run the GUI
        from phishingGui import app
        app.run()
        
    except ImportError as e:
        print(f"❌ Import Error: {e}")
        print("\nTroubleshooting:")
        print("1. Make sure all files are in the same directory:")
        print("   - phishing_detector.py")
        print("   - phishing_gui.py") 
        print("   - run_gui.py")
        print("2. Ensure Python 3.7+ is installed")
        print("3. Verify tkinter is available (usually included with Python)")
        
    except Exception as e:
        print(f"❌ Error starting GUI: {e}")
        print("\nIf you're having issues with the GUI, you can use the command-line version:")
        print("python example_usage.py")
        
    finally:
        input("\nPress Enter to exit...")

if __name__ == "__main__":
    main()
