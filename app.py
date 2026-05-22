#!/usr/bin/env python3
"""
AutoMotionTools - Flask Web Interface (Render Optimized)
"""

from flask import Flask, render_template, request, jsonify
import threading
import os
import warnings
warnings.filterwarnings('ignore', category=requests.packages.urllib3.exceptions.InsecureRequestWarning)

# 👇 এই লাইন scanner.py ইমপোর্ট করার আগে বসাতে হবে
import requests
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

from scanner import AutoMotionScanner

app = Flask(__name__)

scan_results = {}
scan_status = {}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def start_scan():
    """Start a new scan."""
    data = request.get_json()
    target = data.get('target', '').strip()
    
    if not target:
        return jsonify({"error": "Target URL is required"}), 400
    
    if not target.startswith(('http://', 'https://')):
        target = 'https://' + target
    
    import time
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
    # 👇 Render-এর PORT env variable ব্যবহার করুন
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
