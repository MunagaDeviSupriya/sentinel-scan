"""
MCOGAN+ — XGBoost Model Training Script
========================================
Run this script once to train the classifier and save model artefacts.
Artefacts produced:
  model.pkl         — trained XGBClassifier
  label_encoder.pkl — fitted LabelEncoder

Usage:
  python train_model.py [--data path/to/dataset.csv] [--test-size 0.2]

Column convention:
  Uses the 'Malware' column as the target label (0 = Benign, 1 = Malware).
  Features are selected by name (see FEATURE_NAMES below).
"""

import argparse
import pickle
import sys

import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
from sklearn.preprocessing import LabelEncoder
from xgboost import XGBClassifier

# ── Feature names — must match backend.py ────────────────────────────────────
FEATURE_NAMES = [
    "File Size",
    "Entropy Score",
    "Section Count",
    "API Call Count",
    "Import Table Size",
]

# Mapping from dataset column names to our feature names
DATASET_FEATURE_COLS = [
    "SizeOfImage",              # File Size proxy
    "SectionMaxEntropy",        # Entropy Score
    "NumberOfSections",         # Section Count
    "SuspiciousImportFunctions",# API Call Count (suspicious APIs)
    "DirectoryEntryImportSize", # Import Table Size
]

# ── Target label column ───────────────────────────────────────────────────────
LABEL_COL = "Malware"   # 0 = Benign, 1 = Malware

# ── CLI args ──────────────────────────────────────────────────────────────────
parser = argparse.ArgumentParser(description="Train MCOGAN+ XGBoost model")
parser.add_argument("--data",        default="dataset_malwares.csv", help="CSV dataset path")
parser.add_argument("--test-size",   default=0.2,  type=float, help="Test split fraction (default: 0.2)")
parser.add_argument("--cv-folds",    default=5,    type=int,   help="Cross-validation folds (default: 5)")
parser.add_argument("--estimators",  default=300,  type=int,   help="XGBoost n_estimators (default: 300)")
parser.add_argument("--max-depth",   default=6,    type=int,   help="XGBoost max_depth (default: 6)")
parser.add_argument("--lr",          default=0.05, type=float, help="XGBoost learning_rate (default: 0.05)")
parser.add_argument("--seed",        default=42,   type=int,   help="Random seed (default: 42)")
args = parser.parse_args()

# ── [1/5] Load data ───────────────────────────────────────────────────────────
print(f"\n[1/5] Loading dataset: {args.data}")
try:
    df = pd.read_csv(args.data)
except FileNotFoundError:
    sys.exit(f"[ERROR] Dataset not found at: {args.data}")

print(f"      Shape : {df.shape[0]:,} rows x {df.shape[1]} cols")
print(f"      Memory: {df.memory_usage(deep=True).sum() / 1e6:.1f} MB")

# Validate required columns exist
missing = [c for c in DATASET_FEATURE_COLS + [LABEL_COL] if c not in df.columns]
if missing:
    sys.exit(f"[ERROR] Missing columns in dataset: {missing}")

# ── [2/5] Prepare features & labels ──────────────────────────────────────────
X     = df[DATASET_FEATURE_COLS].values.astype(float)
y_raw = df[LABEL_COL].values  # 0 or 1

# Map numeric labels to human-readable names
label_map   = {0: "Benign", 1: "Malware"}
y_str       = np.array([label_map.get(int(v), str(v)) for v in y_raw])

le = LabelEncoder()
y  = le.fit_transform(y_str)
n_classes = len(le.classes_)

print(f"\n[2/5] Labels: {n_classes} unique classes  |  {X.shape[0]:,} total samples")
for cls, cnt in zip(*np.unique(y_str, return_counts=True)):
    print(f"      {str(cls):<25} {cnt:>6,} samples")

# ── [3/5] Train / test split ──────────────────────────────────────────────────
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=args.test_size, random_state=args.seed, stratify=y
)
print(f"\n[3/5] Split (stratified): {len(X_train):,} train  /  {len(X_test):,} test")

# ── [4/5] Train model ─────────────────────────────────────────────────────────
print(f"\n[4/5] Training XGBClassifier ...")
scale_pos_weight = (y_train == 0).sum() / max((y_train == 1).sum(), 1)
model = XGBClassifier(
    n_estimators      = args.estimators,
    max_depth         = args.max_depth,
    learning_rate     = args.lr,
    subsample         = 0.85,
    colsample_bytree  = 0.85,
    min_child_weight  = 3,
    gamma             = 0.1,
    reg_alpha         = 0.05,
    reg_lambda        = 1.0,
    scale_pos_weight  = scale_pos_weight,
    eval_metric       = "logloss",
    use_label_encoder = False,
    random_state      = args.seed,
    n_jobs            = -1,
    verbosity         = 0,
)
model.fit(X_train, y_train, eval_set=[(X_test, y_test)], verbose=False)

# ── [5/5] Evaluation ──────────────────────────────────────────────────────────
y_pred = model.predict(X_test)
acc    = accuracy_score(y_test, y_pred)

print(f"\n[5/5] Evaluation results")
print(f"      Holdout accuracy : {acc * 100:.2f}%")

cv        = StratifiedKFold(n_splits=args.cv_folds, shuffle=True, random_state=args.seed)
cv_scores = cross_val_score(model, X, y, cv=cv, scoring="accuracy", n_jobs=-1)
print(f"      {args.cv_folds}-fold CV accuracy : {cv_scores.mean() * 100:.2f}% "
      f"+/- {cv_scores.std() * 100:.2f}%")

print(f"\n      Classification report:")
report = classification_report(y_test, y_pred, target_names=le.classes_.astype(str))
for line in report.split("\n"):
    print(f"      {line}")

# Top feature importance
importances = model.feature_importances_
top5 = sorted(zip(FEATURE_NAMES, importances), key=lambda x: -x[1])
print(f"      Feature importance (gain):")
for name, imp in top5:
    print(f"        {name:<30} {imp:.4f}")

# ── Save artefacts ────────────────────────────────────────────────────────────
pickle.dump(model, open("model.pkl",         "wb"), protocol=4)
pickle.dump(le,    open("label_encoder.pkl", "wb"), protocol=4)
print("\n  Saved: model.pkl  &  label_encoder.pkl")
print("   You can now start backend.py\n")
