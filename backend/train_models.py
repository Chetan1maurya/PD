# %% 1. Imports
import os, time, joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.ensemble import RandomForestClassifier, StackingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, precision_score, recall_score,
                             f1_score, roc_auc_score)
from xgboost import XGBClassifier
from lightgbm import LGBMClassifier
from feature_extractor import extract_lexical_features

RANDOM_STATE = 42
RUN_BASELINES = True      # False karo to paper-style comparison skip hoga (time bachega)
os.makedirs("models", exist_ok=True)

def report(name, y_true, proba, thr=0.5):
    pred = (proba >= thr).astype(int)
    row = dict(Model=name,
               Accuracy=accuracy_score(y_true, pred),
               Precision=precision_score(y_true, pred),
               Recall=recall_score(y_true, pred),
               F1=f1_score(y_true, pred),
               AUC=roc_auc_score(y_true, proba))
    print(f"{name:42s} acc={row['Accuracy']:.4f} prec={row['Precision']:.4f} "
          f"rec={row['Recall']:.4f} f1={row['F1']:.4f} auc={row['AUC']:.4f}")
    return row

# %% 2. Load dataset (Hannousse & Yahiouche, 11,430 URLs, 87 features)
df = pd.read_csv("phishing_dataset.csv")
y = (df["status"] == "phishing").astype(int)
print("Rows:", len(df), "| phishing:", y.sum(), "| legitimate:", (1 - y).sum())

all_cols = [c for c in df.columns if c not in ("url", "status")]
external_7 = ["whois_registered_domain", "domain_registration_length", "domain_age",
              "web_traffic", "dns_record", "google_index", "page_rank"]
content_24 = all_cols[all_cols.index("nb_hyperlinks"):all_cols.index("domain_with_copyright") + 1]

# Deployed features: sirf wo jo URL ke text se nikal sakte hain
lexical = [c for c in all_cols if c not in external_7 and c not in content_24]
lexical = [c for c in lexical if c != "nb_www"] + ["word_vowel_ratio"]
print("Deployed (URL-only) features:", len(lexical))

# %% 3. Features raw URL se apne extractor se dobara nikalo
# (wahi function jo live backend use karta hai -> training/serving mismatch nahi)
t = time.time()
feats = df["url"].apply(extract_lexical_features).apply(pd.Series)
X = feats[lexical].apply(pd.to_numeric, errors="coerce").fillna(0)
X_full = df[all_cols].apply(pd.to_numeric, errors="coerce").fillna(0)  # sirf paper-style baselines ke liye
print(f"Feature extraction done in {time.time() - t:.0f}s")

# %% 4. Train / test split (80/20, stratified, fixed seed)
X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.2, stratify=y, random_state=RANDOM_STATE)
Xf_tr, Xf_te = X_full.loc[X_tr.index], X_full.loc[X_te.index]
print("Train:", len(X_tr), "| Test:", len(X_te))

results = []

# %% 5. (Optional) Paper-style baselines, FULL 87 features
if RUN_BASELINES:
    print("\n--- Offline baselines, 87 features (reference paper se comparison) ---")
    rf = RandomForestClassifier(n_estimators=300, random_state=RANDOM_STATE, n_jobs=-1).fit(Xf_tr, y_tr)
    results.append(report("Random Forest (87 feat, offline)", y_te, rf.predict_proba(Xf_te)[:, 1]))
    xg = XGBClassifier(n_estimators=300, random_state=RANDOM_STATE, eval_metric="logloss", n_jobs=-1).fit(Xf_tr, y_tr)
    results.append(report("XGBoost (87 feat, offline)", y_te, xg.predict_proba(Xf_te)[:, 1]))
    lg = LGBMClassifier(n_estimators=300, random_state=RANDOM_STATE, verbose=-1, n_jobs=-1).fit(Xf_tr, y_tr)
    results.append(report("LightGBM (87 feat, offline)", y_te, lg.predict_proba(Xf_te)[:, 1]))

# %% 6. STAGE 1 - fast XGBoost, sirf URL features (5-fold CV se tune)
print("\n--- Stage 1: XGBoost (URL-only) ---")
t = time.time()
grid = {"max_depth": [4, 6, 8], "n_estimators": [80, 100, 150], "learning_rate": [0.05, 0.1, 0.2]}
search = GridSearchCV(XGBClassifier(random_state=RANDOM_STATE, eval_metric="logloss", n_jobs=-1),
                      grid, cv=5, scoring="f1", n_jobs=-1)
search.fit(X_tr, y_tr)
stage1 = search.best_estimator_
print("Best parameters:", search.best_params_, f"({time.time() - t:.0f}s)")
p1 = stage1.predict_proba(X_te)[:, 1]
results.append(report("Stage 1 (XGBoost, URL-only)", y_te, p1))

# %% 7. STAGE 2 - stacking ensemble (3 base models + Logistic Regression meta-learner)
print("\n--- Stage 2: Stacking ensemble (URL-only) ---")
t = time.time()
base_learners = [
    ("rf",  RandomForestClassifier(n_estimators=400, max_depth=25, random_state=RANDOM_STATE, n_jobs=-1)),
    ("xgb", XGBClassifier(n_estimators=400, max_depth=8, learning_rate=0.08,
                          random_state=RANDOM_STATE, eval_metric="logloss", n_jobs=-1)),
    ("lgb", LGBMClassifier(n_estimators=400, max_depth=10, learning_rate=0.08,
                           random_state=RANDOM_STATE, verbose=-1, n_jobs=-1)),
]
stage2 = StackingClassifier(estimators=base_learners,
                            final_estimator=LogisticRegression(max_iter=1000), cv=5, n_jobs=-1)
stage2.fit(X_tr, y_tr)
print(f"Stage 2 trained in {time.time() - t:.0f}s")
p2 = stage2.predict_proba(X_te)[:, 1]
results.append(report("Stage 2 (Stacking, URL-only)", y_te, p2))

# %% 8. CASCADE - Stage 1 confident (>=0.90 ya <=0.10) to wahi final, warna Stage 2
THRESHOLD = 0.90
confident = (p1 >= THRESHOLD) | (p1 <= 1 - THRESHOLD)
p_cascade = np.where(confident, p1, p2)
print(f"\nStage 1 se resolve (fast path): {confident.mean()*100:.1f}% | Stage 2 ko gaya: {100 - confident.mean()*100:.1f}%")
results.append(report("Final Cascade (deployed)", y_te, p_cascade))

# %% 9. Backend ke liye sab save karo
joblib.dump(stage1, "models/stage1_model.pkl")
joblib.dump(stage2, "models/stage2_model.pkl")
joblib.dump(lexical, "models/lexical_features.pkl")
pd.DataFrame(results).to_csv("training_results.csv", index=False)
print("\nSaved: models/stage1_model.pkl, stage2_model.pkl, lexical_features.pkl, training_results.csv")