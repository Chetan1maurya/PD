"""
FastAPI backend: /predict (cascade model), /report (community flag),
/stats (dashboard numbers). SQLite for storage -- zero setup needed.
Run: uvicorn main:app --reload
"""
import sqlite3
import joblib
import pandas as pd
from datetime import datetime
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from feature_extractor import extract_lexical_features
from feature_extractor import extract_lexical_features, _tld_extractor
from feature_extractor import generate_reasons

app = FastAPI(title="Phishing Detector API")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

stage1_model = joblib.load("models/stage1_model.pkl")
stage2_model = joblib.load("models/stage2_model.pkl")
lexical_features = joblib.load("models/lexical_features.pkl")
CONFIDENCE_THRESHOLD = 0.90

# ---- tiny SQLite setup ----
conn = sqlite3.connect("phishing.db", check_same_thread=False)
conn.execute("""CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT, url TEXT, verdict TEXT,
    confidence REAL, stage_used TEXT, ts TEXT)""")
conn.execute("""CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT, domain TEXT, reason TEXT, ts TEXT)""")
conn.commit()


class URLRequest(BaseModel):
    url: str


class ReportRequest(BaseModel):
    domain: str
    reason: str = "user reported"

ALLOWLIST_DOMAINS = {
    'google.com', 'youtube.com', 'github.com', 'chatgpt.com', 'openai.com',
    'wikipedia.org', 'amazon.com', 'amazon.in', 'microsoft.com', 'apple.com',
    'facebook.com', 'instagram.com', 'linkedin.com', 'twitter.com', 'x.com',
    'geeksforgeeks.org', 'stackoverflow.com', 'netflix.com', 'reddit.com',
    'atlassian.net',
}


@app.post("/predict")
def predict(req: URLRequest):
    ext = _tld_extractor(req.url)
    base_domain = f"{ext.domain}.{ext.suffix}"

    if base_domain in ALLOWLIST_DOMAINS:
        label = "legitimate"
        confidence = 0.99
        stage_used = "allowlist"

        reasons = [
            "The domain is present in the trusted allowlist"
        ]
    else:
        raw = extract_lexical_features(req.url)

        # Generate human-readable explanations
        reasons = generate_reasons(raw, req.url)

        lex_row = pd.DataFrame(
            [[raw.get(f, 0) for f in lexical_features]],
            columns=lexical_features
        )

        proba1 = stage1_model.predict_proba(lex_row)[0][1]

        confident = (
            proba1 >= CONFIDENCE_THRESHOLD
            or proba1 <= (1 - CONFIDENCE_THRESHOLD)
        )

        if confident:
            verdict_proba, stage_used = proba1, "stage1_fast"
        else:
            verdict_proba = stage2_model.predict_proba(lex_row)[0][1]
            stage_used = "stage2_deep"

        label = "phishing" if verdict_proba >= 0.5 else "legitimate"

        confidence = float(
            verdict_proba if label == "phishing"
            else 1 - verdict_proba
        )

        conn.execute("INSERT INTO logs (url, verdict, confidence, stage_used, ts) VALUES (?,?,?,?,?)",
                    (req.url, label, confidence, stage_used, datetime.utcnow().isoformat()))
        conn.commit()
    return {
        "url": req.url,
        "verdict": label,
        "confidence": round(confidence, 4),
        "stage_used": stage_used,
        "reasons": reasons
    }

@app.post("/report")
def report(req: ReportRequest):
    conn.execute("INSERT INTO reports (domain, reason, ts) VALUES (?,?,?)",
                 (req.domain, req.reason, datetime.utcnow().isoformat()))
    conn.commit()
    count = conn.execute("SELECT COUNT(*) FROM reports WHERE domain=?", (req.domain,)).fetchone()[0]
    return {"domain": req.domain, "total_reports": count, "blocklisted": count >= 3}


@app.get("/stats")
def stats():
    total = conn.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
    phishing = conn.execute("SELECT COUNT(*) FROM logs WHERE verdict='phishing'").fetchone()[0]
    recent = conn.execute("SELECT url, verdict, confidence, ts FROM logs ORDER BY id DESC LIMIT 10").fetchall()
    top_reports = conn.execute("""SELECT domain, COUNT(*) c FROM reports
                                   GROUP BY domain ORDER BY c DESC LIMIT 5""").fetchall()
    return {
        "total_scans": total,
        "phishing_blocked": phishing,
        "recent": [{"url": r[0], "verdict": r[1], "confidence": r[2], "ts": r[3]} for r in recent],
        "top_reported": [{"domain": r[0], "count": r[1]} for r in top_reports],
    }


@app.get("/")
def root():
    return {"status":"running"}