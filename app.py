import os
import hashlib
import requests
from flask import Flask, render_template, request, jsonify

# Configure Flask app
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads/'
app.config['ALLOWED_EXTENSIONS'] = {'exe', 'pdf', 'docx', 'zip', 'rar', 'png', 'jpg', 'txt'}

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# VirusTotal API Key (Replace with your own API Key)
VIRUSTOTAL_API_KEY = "543f736d20bdb22025b3105fb9c15804912e1c5340113bffb1ba68a2e06a9a61"
VIRUSTOTAL_SCAN_URL = "https://www.virustotal.com/api/v3/files"
VIRUSTOTAL_HASH_URL = "https://www.virustotal.com/api/v3/files/{}"

# Function to check allowed file extensions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# Function to get file hash
def get_file_hash(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

# Function to check file hash on VirusTotal
def check_virustotal(file_hash):
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    response = requests.get(VIRUSTOTAL_HASH_URL.format(file_hash), headers=headers)
    if response.status_code == 200:
        return response.json()
    return None

# Route for uploading and scanning file
@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            return jsonify({"error": "No file uploaded"}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({"error": "No selected file"}), 400
        
        if file and allowed_file(file.filename):
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
            file.save(file_path)
            file_hash = get_file_hash(file_path)
            
            # Check if file hash is known on VirusTotal
            result = check_virustotal(file_hash)
            
            if result:
                return jsonify({"message": "File scan result", "result": result}), 200
            else:
                return jsonify({"message": "File uploaded, but not found in VirusTotal. Consider manual submission."}), 200
        else:
            return jsonify({"error": "Invalid file type"}), 400
    
    return render_template('index.html')

# Run the Flask app
if __name__ == '__main__':
    app.run(debug=True)
