#!/usr/bin/env python3
"""
AutoMotionTools - Flask Web Interface (Render Fixed)
"""

# ========== প্রথমে সব import ==========
import os
import threading
import time
import warnings

# Suppress SSL warnings (scanner এ verify=False ব্যবহার করি)
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore")

from flask import Flask, render_template, request, jsonify
from scanner import AutoMotionScanner

# ========== Flask App ==========
app = Flask(__name__)

scan_results = {}
scan_status = {}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def start_scan():
    """Start a new scan in background thread."""
    data = request.get_json()
    target = data.get('target', '').strip()
    
    if not target:
        return jsonify({"error": "Target URL is required"}), 400
    
    if not target.startswith(('http://', 'https://')):
        target = 'https://' + target
    
    scan_id = str(int(time.time()))
    scan_status[scan_id] = {"status": "running", "progress": 0, "message": "Initializing..."}
    
    def run_scan():
        try:
            scanner = AutoMotionScanner(target)
            scan_status[scan_id] = {"status": "running", "progress": 10, "message": "Discovering admin panels..."}
            results = scanner.full_scan()
            scan_results[scan_id] = results
            scan_status[scan_id] = {"status": "complete", "progress": 100, "message": "Scan complete"}
        except Exception as e:
            scan_status[scan_id] = {"status": "error", "progress": 0, "message": str(e)}
    
    thread = threading.Thread(target=run_scan, daemon=True)
    thread.start()
    
    return jsonify({"scan_id": scan_id, "status": "started"})

@app.route('/status/<scan_id>')
def get_status(scan_id):
    status = scan_status.get(scan_id, {"status": "not_found"})
    return jsonify(status)

@app.route('/results/<scan_id>')
def get_results(scan_id):
    results = scan_results.get(scan_id, None)
    if results is None:
        return jsonify({"error": "Results not found or scan still running"}), 404
    return jsonify(results)

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=port, debug=False)
