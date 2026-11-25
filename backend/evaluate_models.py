import os
import joblib
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.metrics import (accuracy_score, precision_score, recall_score,
                             f1_score, roc_auc_score, roc_curve,
                             confusion_matrix, ConfusionMatrixDisplay)
from feature_extractor import extract_lexical_features

CONF_THRESHOLD = 0.90
os.makedirs("report_outputs", exist_ok=True)

df = pd.read_csv("phishing_dataset.csv")
y = (df["status"] == "phishing").astype(int)
lexical_features = joblib.load("models/lexical_features.pkl")
stage1 = joblib.load("models/stage1_model.pkl")
stage2 = joblib.load("models/stage2_model.pkl")

print("Extracting features from URLs (takes ~30 seconds)...")
feats = df["url"].apply(extract_lexical_features).apply(pd.Series)
X = feats[lexical_features].apply(pd.to_numeric, errors="coerce").fillna(0)

# Same split as training: 80% train / 20% test, random_state=42
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, stratify=y, random_state=42)
print(f"Test set size: {len(X_test)}")

p1 = stage1.predict_proba(X_test)[:, 1]
p2 = stage2.predict_proba(X_test)[:, 1]
confident = (p1 >= CONF_THRESHOLD) | (p1 <= 1 - CONF_THRESHOLD)
p_cascade = np.where(confident, p1, p2)
fast_path_pct = confident.mean() * 100

models = {
    "Stage 1 (XGBoost, fast)": p1,
    "Stage 2 (Stacking ensemble)": p2,
    "Final Cascade (deployed)": p_cascade,
}

rows = []
for name, proba in models.items():
    pred = (proba >= 0.5).astype(int)
    cm = confusion_matrix(y_test, pred)
    tn, fp, fn, tp = cm.ravel()
    rows.append({
        "Model": name,
        "Accuracy": accuracy_score(y_test, pred),
        "Precision": precision_score(y_test, pred),
        "Recall": recall_score(y_test, pred),
        "F1-score": f1_score(y_test, pred),
        "AUC": roc_auc_score(y_test, proba),
        "Specificity": tn / (tn + fp),
        "TN": tn, "FP": fp, "FN": fn, "TP": tp,
    })
    fig, ax = plt.subplots(figsize=(5, 4.5))
    ConfusionMatrixDisplay(cm, display_labels=["Legitimate", "Phishing"]).plot(
        cmap="Blues", ax=ax, colorbar=False)
    ax.set_title(f"Confusion matrix - {name}")
    safe = name.split(" (")[0].replace(" ", "_").lower()
    fig.savefig(f"report_outputs/confusion_matrix_{safe}.png", dpi=200, bbox_inches="tight")
    plt.close(fig)

fig, ax = plt.subplots(figsize=(7, 6))
for name, proba in models.items():
    fpr, tpr, _ = roc_curve(y_test, proba)
    ax.plot(fpr, tpr, label=f"{name} (AUC = {roc_auc_score(y_test, proba):.3f})")
ax.plot([0, 1], [0, 1], "k--", label="Random guess")
ax.set_xlabel("False Positive Rate")
ax.set_ylabel("True Positive Rate")
ax.set_title("ROC curve")
ax.legend(loc="lower right")
ax.grid(alpha=0.3)
fig.savefig("report_outputs/roc_curve.png", dpi=200, bbox_inches="tight")
plt.close(fig)

table = pd.DataFrame(rows)
table.to_csv("report_outputs/metrics_table.csv", index=False)

pd.set_option("display.width", 200)
print("\n=== RESULTS (held-out 20% test set) ===")
print(table.round(4).to_string(index=False))
print(f"\nCascade: {fast_path_pct:.1f}% of requests resolved by Stage 1 (fast path), "
      f"{100 - fast_path_pct:.1f}% escalated to Stage 2")
print("\nSaved in report_outputs/: metrics_table.csv, roc_curve.png, confusion_matrix_*.png")