# File Upload Scanner

This is a simple **Flask-based file upload scanner** that checks files against the **VirusTotal API** to detect malware.

## Features
- Upload and scan files (PDF, DOCX, ZIP, EXE, etc.).
- Checks file hashes against VirusTotal.
- Displays scan results (Safe, Suspicious, Malicious).
- Implements security measures (file type restriction, upload validation).

## Installation
1. Install Python dependencies:
   ```sh
   pip install flask requests
   ```
2. Replace `YOUR_VIRUSTOTAL_API_KEY` in `app.py` with your actual VirusTotal API key.
3. Run the app:
   ```sh
   python app.py
   ```
4. Open `http://127.0.0.1:5000` in your browser.

## Notes
- You need to register at **https://www.virustotal.com/** to get an API key.
- Use responsibly for educational purposes only.
