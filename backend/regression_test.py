"""
Reusable regression test -- run this any time after retraining or changing
feature_extractor.py to check for false positives/negatives across a
diverse set of URL categories, instead of testing one URL at a time.

Usage: python regression_test.py
"""
"""
Reusable regression test -- run this any time after retraining or changing
feature_extractor.py to check for false positives/negatives across a
diverse set of URL categories, instead of testing one URL at a time.
This mirrors the EXACT logic main.py uses (allowlist + cascade), so results
here reflect what the deployed system will actually do.

Usage: python regression_test.py
"""
import joblib
import pandas as pd
from urllib.parse import urlparse
from feature_extractor import extract_lexical_features, _tld_extractor

lexical_features = joblib.load('models/lexical_features.pkl')
stage1_model = joblib.load('models/stage1_model.pkl')
stage2_model = joblib.load('models/stage2_model.pkl')

# Base registrable domains (not full hostnames) -- so subdomains and any
# path on these domains are all covered, e.g. docs.google.com,
# github.com/anything, www.amazon.in/anything all match 'google.com' etc.
ALLOWLIST_DOMAINS = {
    'google.com', 'youtube.com', 'github.com', 'chatgpt.com', 'openai.com',
    'wikipedia.org', 'amazon.com', 'amazon.in', 'microsoft.com', 'apple.com',
    'facebook.com', 'instagram.com', 'linkedin.com', 'twitter.com', 'x.com',
    'geeksforgeeks.org', 'stackoverflow.com', 'netflix.com', 'reddit.com',
    'atlassian.net',
}


def full_predict(url):
    ext = _tld_extractor(url)
    base_domain = f"{ext.domain}.{ext.suffix}"
    if base_domain in ALLOWLIST_DOMAINS:
        return "legitimate", 0.99, "allowlist"

    raw = extract_lexical_features(url)
    lex_row = pd.DataFrame([[raw.get(f, 0) for f in lexical_features]], columns=lexical_features)
    p1 = stage1_model.predict_proba(lex_row)[0][1]
    confident = p1 >= 0.9 or p1 <= 0.1
    if confident:
        final, stage = p1, "stage1"
    else:
        final, stage = stage2_model.predict_proba(lex_row)[0][1], "stage2"
    label = "phishing" if final >= 0.5 else "legitimate"
    conf = final if label == "phishing" else 1 - final
    return label, conf, stage


# (url, expected_label) -- diverse categories on purpose
TEST_CASES = [
    ("https://www.google.com", "legitimate"),
    ("https://github.com", "legitimate"),
    ("https://chatgpt.com", "legitimate"),
    ("https://www.youtube.com/watch?v=DQePNw_WZQ4", "legitimate"),
    ("https://sentinel-mmmut-getpostlabs.atlassian.net/wiki/spaces/SF/pages/5046273/Problem+Understanding+Sneha+Initial+Draft", "legitimate"),
    ("https://docs.google.com/document/d/1a2B3c4D5e6F7g8H9i0J/edit", "legitimate"),
    ("https://github.com/facebook/react/pull/12345/files", "legitimate"),
    ("https://www.geeksforgeeks.org/courses?source=google", "legitimate"),
    ("https://www.amazon.in/gp/css/order-history", "legitimate"),
    ("http://rgipt.ac.in", "legitimate"),
    ("http://secure-login.paypal-verify.xyz", "phishing"),
    ("http://192.168.1.1/paypal/login.php", "phishing"),
    ("http://paypal-account-verify.tk/signin", "phishing"),
    ("http://bit.ly/3xK9zP2", "phishing"),
    ("http://appleid.apple.com.verify-account.security-update.info/login", "phishing"),
    ("http://www.faceb00k-security-check.com/login.php?verify=1&id=93827465", "phishing"),
]

correct = 0
print(f"{'URL':65s} {'Expected':12s} {'Got':12s} {'Conf':7s} {'Stage':12s} {'OK?'}")
print("-" * 120)
for url, expected in TEST_CASES:
    got, conf, stage = full_predict(url)
    ok = "OK" if got == expected else "WRONG"
    if got == expected:
        correct += 1
    print(f"{url[:65]:65s} {expected:12s} {got:12s} {conf*100:5.1f}%  {stage:12s} {ok}")

print("-" * 120)
print(f"Score: {correct}/{len(TEST_CASES)} ({correct/len(TEST_CASES)*100:.0f}%)")
