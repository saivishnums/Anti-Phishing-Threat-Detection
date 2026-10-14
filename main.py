from fastapi import FastAPI, Form, Request, Response, UploadFile, File
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
import sqlite3
import re
import csv
import math
import ipaddress
import numpy as np
import email
from email import policy
import pypdf
import docx
import io
from urllib.parse import urlparse, unquote

# Machine Learning Imports (scikit-learn)
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler

app = FastAPI(title="Threat Detection Suite (GBDT + DBSCAN Hybrid)")
templates = Jinja2Templates(directory="templates")

# --- DATABASE SETUP (ACID Compliant & Auto-Migration Safe) ---
def init_db():
    with sqlite3.connect("threat_suite.db") as conn:
        cursor = conn.cursor()
        cursor.execute("PRAGMA journal_mode=WAL;")
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                target TEXT,
                status TEXT,
                risk_score INTEGER,
                vector TEXT,
                flags TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("PRAGMA table_info(scan_logs);")
        columns = [col[1] for col in cursor.fetchall()]
        if "vector" not in columns:
            cursor.execute("ALTER TABLE scan_logs ADD COLUMN vector TEXT;")
        if "flags" not in columns:
            cursor.execute("ALTER TABLE scan_logs ADD COLUMN flags TEXT;")
        conn.commit()

init_db()

# --- HYBRID ML MODEL INITIALIZATION (GBDT + DBSCAN) ---
gbdt_model = GradientBoostingClassifier(n_estimators=100, learning_rate=0.1, random_state=42)
scaler = StandardScaler()

X_seed = np.array([
    [15, 10, 1, 0, 1, 2.5, 0, 0, 0, 0],
    [85, 25, 4, 3, 3, 4.2, 5, 1, 3, 0],
    [22, 12, 2, 0, 1, 2.1, 0, 0, 1, 0],
    [65, 18, 2, 2, 2, 3.9, 2, 1, 4, 1],
    [30, 15, 2, 1, 2, 3.1, 0, 0, 2, 0],
    [95, 30, 5, 4, 4, 4.6, 8, 1, 5, 1]
])
y_seed = np.array([0, 1, 0, 1, 0, 1])

X_seed_scaled = scaler.fit_transform(X_seed)
gbdt_model.fit(X_seed_scaled, y_seed)

def extract_url_features(raw_url: str) -> list:
    try:
        decoded_url = unquote(raw_url)
    except Exception:
        decoded_url = raw_url

    full_url = decoded_url if "://" in decoded_url else "http://" + decoded_url
    parsed = urlparse(full_url)
    netloc = parsed.netloc.split("@")[-1]
    host = netloc.split(":")[0].lower()
    path = parsed.path
    query = parsed.query

    url_len = len(raw_url)
    domain_len = len(host)
    dot_count = host.count(".")
    hyphen_count = host.count("-")
    subdomain_count = len(host.split("."))
    
    entropy = 0.0
    if host:
        for x in range(256):
            p_x = host.count(chr(x)) / len(host)
            if p_x > 0:
                entropy += -p_x * math.log2(p_x)

    digit_count = sum(c.isdigit() for c in raw_url)
    
    harvesting_keywords = ["login", "signin", "verify", "update", "secure", "account", "auth", "banking", "wallet", "confirm", "password", "webscr", "loading", "customer", "paypal", "apple", "microsoft", "google", "netflix", "amazon", "bank"]
    has_keywords = 1 if any(kw in (path + query + host).lower() for kw in harvesting_keywords) else 0

    path_segments = [seg for seg in path.split("/") if seg]
    path_depth = len(path_segments)

    embedded_domain_pattern = r"(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}"
    has_embedded_domain = 1 if any(re.search(embedded_domain_pattern, seg) and seg.lower() not in host for seg in path_segments) else 0

    return [url_len, domain_len, dot_count, hyphen_count, subdomain_count, entropy, digit_count, has_keywords, path_depth, has_embedded_domain]

def run_hybrid_ml_analysis(raw_url: str):
    flags = []
    vector = "General Heuristic"

    features = extract_url_features(raw_url)
    X_sample = scaler.transform([features])

    gbdt_prob = gbdt_model.predict_proba(X_sample)[0][1]
    gbdt_score = int(gbdt_prob * 100)

    full_url = unquote(raw_url) if "://" in unquote(raw_url) else "http://" + unquote(raw_url)
    parsed = urlparse(full_url)
    host = parsed.netloc.split("@")[-1].split(":")[0].lower()
    path_and_query = (parsed.path + parsed.query).lower()

    trusted_brands = ["paypal", "apple", "microsoft", "google", "netflix", "amazon", "bank", "secure", "login", "webscr", "americanexpress"]
    found_brands = [b for b in trusted_brands if b in path_and_query and b not in host]
    if found_brands:
        gbdt_score = max(gbdt_score, 85)
        flags.append(f"Deceptive Path Spoofing: Trusted brand token(s) '{', '.join(found_brands)}' embedded in path while host domain is '{host}'")
        vector = "Credential Harvesting"

    harvesting_keywords = ["login", "signin", "verify", "update", "secure", "account", "auth", "banking", "wallet", "confirm", "password", "track", "parcel"]
    matched_keywords = [kw for kw in harvesting_keywords if kw in path_and_query or kw in host]
    if matched_keywords:
        gbdt_score = max(gbdt_score, 75)
        flags.append(f"High-Risk Intent Keywords Identified: {', '.join(set(matched_keywords))}")
        vector = "Credential Harvesting"

    domain_part = host.split(".")[0] if "." in host else host
    vowels = sum(1 for c in domain_part if c in "aeiou")
    if len(domain_part) >= 5 and (vowels == 0 or features[5] > 3.2):
        gbdt_score = max(gbdt_score, 75)
        flags.append(f"Gibberish / DGA Domain Anomaly: Host domain '{host}' exhibits abnormal entropy ({features[5]:.2f})")
        if vector == "General Heuristic":
            vector = "Typosquatting & Obfuscation"

    if host.startswith("xn--") or ".xn--" in host:
        gbdt_score = max(gbdt_score, 90)
        flags.append("Punycode Internationalized Domain Name detected (homograph impersonation risk)")
        vector = "Typosquatting & Obfuscation"

    with sqlite3.connect("threat_suite.db") as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT target FROM scan_logs ORDER BY id DESC LIMIT 50")
        recent_targets = cursor.fetchall()
    
    cluster_dataset = [features]
    for (target,) in recent_targets:
        cluster_dataset.append(extract_url_features(target))
    
    if len(cluster_dataset) >= 3:
        X_cluster = scaler.transform(np.array(cluster_dataset))
        dbscan = DBSCAN(eps=1.2, min_samples=2)
        clusters = dbscan.fit_predict(X_cluster)
        if clusters[0] == -1:
            gbdt_score = max(gbdt_score, 70)
            flags.append("DBSCAN Anomaly Detection: Sample classified as structural cluster outlier (zero-day anomaly)")

    if gbdt_score >= 40 and not flags:
        flags.append(f"Heuristic Risk Score Elevated ({gbdt_score}%) based on structural and lexical anomaly analysis.")
        if gbdt_score >= 70:
            vector = "Credential Harvesting"

    if not flags and gbdt_score < 40:
        flags.append("Standard heuristic evaluation passed. No anomalies detected.")

    return min(gbdt_score, 100), flags, vector

# --- AUTH HELPERS ---
def is_valid_email(email: str):
    pattern = r"^[a-zA-Z0-9_.+-]+@(gmail\.com|outlook\.com|hotmail\.com|live\.com|yahoo\.com|icloud\.com|ac\.in|mariattech\.ac\.in)$"
    return re.match(pattern, email.lower()) is not None

def register_user(username, email, password):
    try:
        with sqlite3.connect("threat_suite.db") as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)", (username, email, password))
            conn.commit()
        return True, "Success"
    except sqlite3.IntegrityError as e:
        if "email" in str(e):
            return False, "Email address is already registered!"
        return False, "Username already exists!"

def verify_user(username, password):
    with sqlite3.connect("threat_suite.db") as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
        return cursor.fetchone() is not None

def save_user_scan(username, target, status, risk_score, vector, flags_str):
    init_db()
    with sqlite3.connect("threat_suite.db") as conn:
        cursor = conn.cursor()
        cursor.execute("INSERT INTO scan_logs (username, target, status, risk_score, vector, flags) VALUES (?, ?, ?, ?, ?, ?)",
                       (username, target, status, risk_score, vector, flags_str))
        conn.commit()

def get_user_logs(username):
    init_db()
    with sqlite3.connect("threat_suite.db") as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT target, status, risk_score, vector, flags FROM scan_logs WHERE username = ? ORDER BY id DESC", (username,))
        return cursor.fetchall()

# --- ROUTES ---
@app.get("/", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse(request, "login.html", {"error": None})

@app.post("/login", response_class=HTMLResponse)
async def handle_login(request: Request, username: str = Form(...), password: str = Form(...)):
    if verify_user(username, password):
        resp = RedirectResponse(url="/dashboard", status_code=303)
        resp.set_cookie(key="current_user", value=username, httponly=True, samesite="lax")
        return resp
    return templates.TemplateResponse(request, "login.html", {"error": "Invalid username or password"})

@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    return templates.TemplateResponse(request, "register.html", {"error": None})

@app.post("/register", response_class=HTMLResponse)
async def handle_register(request: Request, username: str = Form(...), email: str = Form(...), password: str = Form(...)):
    if not is_valid_email(email):
        return templates.TemplateResponse(request, "register.html", {"error": "Invalid or unauthorized email provider!"})
    
    success, message = register_user(username, email, password)
    if success:
        return RedirectResponse(url="/", status_code=303)
    return templates.TemplateResponse(request, "register.html", {"error": message})

@app.get("/logout")
async def logout():
    resp = RedirectResponse(url="/", status_code=303)
    resp.delete_cookie(key="current_user")
    return resp

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request):
    username = request.cookies.get("current_user")
    if not username:
        return RedirectResponse(url="/", status_code=303)
    return templates.TemplateResponse(request, "dashboard.html", {"username": username})

@app.get("/scanner", response_class=HTMLResponse)
async def scanner_page(request: Request):
    username = request.cookies.get("current_user")
    if not username:
        return RedirectResponse(url="/", status_code=303)
    
    user_logs = get_user_logs(username)
    return templates.TemplateResponse(request, "scanner.html", {"result": None, "username": username, "logs": user_logs})

@app.post("/scanner", response_class=HTMLResponse)
async def scan_url(request: Request, url: str = Form(...)):
    username = request.cookies.get("current_user")
    if not username:
        return RedirectResponse(url="/", status_code=303)

    risk_score, flags, vector = run_hybrid_ml_analysis(url)
    status = "SAFE" if risk_score < 40 else ("SUSPICIOUS" if risk_score < 70 else "MALICIOUS")
    
    if risk_score >= 40 and "Standard heuristic evaluation passed. No anomalies detected." in flags:
        flags.remove("Standard heuristic evaluation passed. No anomalies detected.")

    flags_str = " | ".join(flags) if flags else "No anomalies detected."
    save_user_scan(username, url, status, risk_score, vector, flags_str)

    result = {
        "status": status,
        "risk_score": risk_score,
        "source": "Hybrid GBDT Classifier & Advanced Heuristic Engine",
        "details": flags if flags else ["No anomalies detected."]
    }
    
    user_logs = get_user_logs(username)
    return templates.TemplateResponse(request, "scanner.html", {"result": result, "input_val": url, "username": username, "logs": user_logs})

@app.get("/document-scanner", response_class=HTMLResponse)
async def doc_scanner_page(request: Request):
    username = request.cookies.get("current_user")
    if not username:
        return RedirectResponse(url="/", status_code=303)
    return templates.TemplateResponse(request, "document_scanner.html", {"username": username})

@app.post("/document-scanner", response_class=HTMLResponse)
async def analyze_document(request: Request, file: UploadFile = File(...)):
    username = request.cookies.get("current_user")
    if not username:
        return RedirectResponse(url="/", status_code=303)
    return templates.TemplateResponse(request, "document_scanner.html", {"username": username})

@app.get("/sms-scanner", response_class=HTMLResponse)
async def sms_scanner(request: Request):
    username = request.cookies.get("current_user")
    if not username:
        return RedirectResponse(url="/", status_code=303)
    return templates.TemplateResponse(request, "sms_smishing_inspector.html", {"username": username})

@app.get("/analyst-profile", response_class=HTMLResponse)
async def analyst_profile_page(request: Request):
    username = request.cookies.get("current_user")
    if not username:
        return RedirectResponse(url="/", status_code=303)
    user_logs = get_user_logs(username)
    return templates.TemplateResponse(request, "user_profile.html", {"username": username, "logs": user_logs})

@app.get("/threat-reports", response_class=HTMLResponse)
async def threat_reports_page(request: Request):
    username = request.cookies.get("current_user")
    if not username:
        return RedirectResponse(url="/", status_code=303)
        
    init_db()
    stats_data = []
    try:
        with sqlite3.connect("threat_suite.db") as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT vector, COUNT(*) FROM scan_logs GROUP BY vector")
            stats_data = cursor.fetchall()
    except Exception:
        stats_data = []
    
    stats_dict = {
        "Credential Harvesting": 0, 
        "Typosquatting & Obfuscation": 0, 
        "Document Analyzer": 0,
        "SMS Smishing": 0, 
        "General Heuristic": 0
    }
    for vec, count in stats_data:
        if vec in stats_dict:
            stats_dict[vec] = count
        else:
            stats_dict[vec] = count

    return templates.TemplateResponse(request, "threat_reports.html", {"stats": stats_dict.items(), "username": username})

@app.get("/statistics", response_class=HTMLResponse)
async def stats_redirect(request: Request):
    return RedirectResponse(url="/threat-reports", status_code=303)

@app.get("/vector-details/{vector_name}", response_class=HTMLResponse)
async def vector_details(request: Request, vector_name: str):
    username = request.cookies.get("current_user")
    if not username:
        return RedirectResponse(url="/", status_code=303)
        
    init_db()
    detections = []
    try:
        with sqlite3.connect("threat_suite.db") as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT target, status, risk_score, flags FROM scan_logs WHERE vector = ? ORDER BY id DESC", (vector_name,))
            detections = cursor.fetchall()
    except Exception:
        detections = []

    return templates.TemplateResponse(request, "vector_details.html", {"vector_name": vector_name, "detections": detections, "username": username})
