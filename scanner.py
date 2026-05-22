#!/usr/bin/env python3
"""
AutoMotionTools - Flask Web Interface
Deploy on Render.com as a Web Service
"""

from flask import Flask, render_template, request, jsonify
from scanner import AutoMotionScanner
import threading
import json
import time

app = Flask(__name__)

# Store scan results in memory
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
    
    scan_id = str(int(time.time()))
    scan_status[scan_id] = {"status": "running", "progress": 0, "message": "Initializing..."}
    
    # Run scan in background thread
    def run_scan():
        try:
            scanner = AutoMotionScanner(target)
            
            def update_progress(pct):
                scan_status[scan_id] = {
                    "status": "running",
                    "progress": pct,
                    "message": f"Scanning... {pct}%"
                }
            
            scan_status[scan_id] = {"status": "running", "progress": 5, "message": "Discovering admin panels..."}
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
    """Get scan status."""
    status = scan_status.get(scan_id, {"status": "not_found"})
    return jsonify(status)

@app.route('/results/<scan_id>')
def get_results(scan_id):
    """Get scan results."""
    results = scan_results.get(scan_id, None)
    if results is None:
        return jsonify({"error": "Results not found or scan still running"}), 404
    return jsonify(results)

@app.route('/scan-history')
def scan_history():
    """Return list of completed scan IDs."""
    return jsonify({
        "scans": [
            {"id": sid, "status": scan_status[sid]}
            for sid in scan_results.keys()
        ]
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
