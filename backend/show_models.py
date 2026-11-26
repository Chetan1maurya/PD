import joblib
import pandas as pd
from feature_extractor import extract_lexical_features

stage1 = joblib.load("models/stage1_model.pkl")
stage2 = joblib.load("models/stage2_model.pkl")
features = joblib.load("models/lexical_features.pkl")

print("=== STAGE 1 (fast screening) ===")
print("Algorithm      :", type(stage1).__name__)
for k in ["n_estimators", "max_depth", "learning_rate"]:
    print(f"{k:15s}:", stage1.get_params()[k])
print("Input features :", len(features), "(all computed from the URL text only)")

print("\nTop 10 features Stage 1 relies on:")
imp = pd.Series(stage1.feature_importances_, index=features).sort_values(ascending=False)
print(imp.head(10).round(3).to_string())

print("\n=== STAGE 2 (deep verification, stacking ensemble) ===")
for name, est in stage2.named_estimators_.items():
    print(f"base learner '{name}':", type(est).__name__, "| trees:", getattr(est, "n_estimators", "-"))
print("meta-learner   :", type(stage2.final_estimator_).__name__)
print("weights it gives to [RF, XGB, LGB]:", stage2.final_estimator_.coef_[0].round(2).tolist())

print("\n=== LIVE PREDICTIONS (cascade, no allowlist) ===")
THRESH = 0.90
tests = [
    "https://www.google.com",
    "https://www.youtube.com/watch?v=DQePNw_WZQ4",
    "https://www.geeksforgeeks.org/courses",
    "http://secure-login.paypal-verify.xyz",
    "http://192.168.1.1/paypal/login.php",
    "http://paypal-account-verify.tk/signin",
]
for url in tests:
    row = pd.DataFrame([extract_lexical_features(url)])[features]
    p1 = stage1.predict_proba(row)[0, 1]
    if p1 >= THRESH or p1 <= 1 - THRESH:
        p, stage = p1, "Stage 1"
    else:
        p, stage = stage2.predict_proba(row)[0, 1], "Stage 2"
    print(f"{url[:50]:50s} -> {'PHISHING' if p >= 0.5 else 'legitimate':10s} (phishing prob {p:.2f}, decided by {stage})")