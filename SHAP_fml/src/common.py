"""Shared data loading, model pipelines and SHAP helpers for the churn study.

Everything here is deterministic given SEED. All preprocessing is fitted inside
sklearn Pipelines, so a pipeline fitted on the training split never sees
validation or test rows (no leakage).
"""
from __future__ import annotations

import hashlib
import os
import urllib.request

import numpy as np
import pandas as pd
import shap
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from xgboost import XGBClassifier

SEED = 20261004
DATA_URL = (
    "https://raw.githubusercontent.com/IBM/telco-customer-churn-on-icp4d/"
    "master/data/Telco-Customer-Churn.csv"
)
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DATA_PATH = os.path.join(ROOT, "data", "Telco-Customer-Churn.csv")
RESULTS = os.path.join(ROOT, "results")
FIGURES = os.path.join(ROOT, "figures")

NUMERIC = ["tenure", "MonthlyCharges", "TotalCharges"]
CATEGORICAL = [
    "gender", "SeniorCitizen", "Partner", "Dependents", "PhoneService",
    "MultipleLines", "InternetService", "OnlineSecurity", "OnlineBackup",
    "DeviceProtection", "TechSupport", "StreamingTV", "StreamingMovies",
    "Contract", "PaperlessBilling", "PaymentMethod",
]
FEATURES = NUMERIC + CATEGORICAL
MODELS = ["LR", "RF", "XGB"]


def sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        h.update(f.read())
    return h.hexdigest()


def load_data() -> tuple[pd.DataFrame, pd.Series, dict]:
    """Download (if needed) and clean the IBM Telco churn data."""
    if not os.path.exists(DATA_PATH):
        os.makedirs(os.path.dirname(DATA_PATH), exist_ok=True)
        urllib.request.urlretrieve(DATA_URL, DATA_PATH)
    df = pd.read_csv(DATA_PATH)
    info = {"rows_raw": len(df), "sha256": sha256(DATA_PATH)}

    # TotalCharges is read as text because 11 rows hold a blank string.
    tc = pd.to_numeric(df["TotalCharges"].str.strip().replace("", np.nan))
    blank = tc.isna()
    info["blank_TotalCharges"] = int(blank.sum())
    info["blank_TotalCharges_tenure_values"] = sorted(df.loc[blank, "tenure"].unique().tolist())
    # Every blank row has tenure == 0: the customer has not been billed yet, so
    # the true value is 0. This is a row-local fact, not a statistic estimated
    # from the data, so imputing it before the split cannot leak.
    df["TotalCharges"] = tc.fillna(0.0)
    df["SeniorCitizen"] = df["SeniorCitizen"].map({0: "No", 1: "Yes"})
    df["tenure"] = df["tenure"].astype(float)  # sklearn partial_dependence rejects int columns
    info["duplicate_customerIDs"] = int(df["customerID"].duplicated().sum())

    y = (df["Churn"] == "Yes").astype(int)
    X = df[FEATURES].copy()
    info["n"] = len(X)
    info["churn_rate"] = float(y.mean())
    return X, y, info


def split(X, y, seed=SEED):
    """Stratified 60/20/20 train/validation/test split."""
    X_tmp, X_te, y_tmp, y_te = train_test_split(X, y, test_size=0.2, stratify=y, random_state=seed)
    X_tr, X_va, y_tr, y_va = train_test_split(X_tmp, y_tmp, test_size=0.25, stratify=y_tmp, random_state=seed)
    return X_tr, X_va, X_te, y_tr, y_va, y_te


def preprocessor(numeric=None, categorical=None) -> ColumnTransformer:
    numeric = NUMERIC if numeric is None else numeric
    categorical = CATEGORICAL if categorical is None else categorical
    return ColumnTransformer(
        [
            ("num", StandardScaler(), numeric),
            ("cat", OneHotEncoder(handle_unknown="ignore", sparse_output=False), categorical),
        ]
    )


def make_pipeline(name: str, params: dict | None = None, seed: int = SEED, features=None) -> Pipeline:
    feats = FEATURES if features is None else features
    num = [f for f in NUMERIC if f in feats] + [f for f in feats if f not in FEATURES and f not in CATEGORICAL]
    cat = [f for f in CATEGORICAL if f in feats]
    params = dict(params or {})
    if name == "LR":
        clf = LogisticRegression(max_iter=5000, **params)
    elif name == "RF":
        clf = RandomForestClassifier(n_estimators=300, n_jobs=1, random_state=seed, **params)
    elif name == "XGB":
        clf = XGBClassifier(
            tree_method="hist", n_jobs=1, random_state=seed, eval_metric="logloss",
            subsample=0.8, colsample_bytree=0.8, **params,
        )
    else:
        raise ValueError(name)
    return Pipeline([("pre", preprocessor(num, cat)), ("clf", clf)])


def column_groups(pipe: Pipeline) -> tuple[list[str], list[str]]:
    """Return (transformed column names, original feature of each column)."""
    pre = pipe.named_steps["pre"]
    names, owners = [], []
    for tname, trans, cols in pre.transformers_:
        if tname == "num":
            names += list(cols)
            owners += list(cols)
        elif tname == "cat":
            for col, cats in zip(cols, trans.categories_):
                for c in cats:
                    names.append(f"{col}={c}")
                    owners.append(col)
    return names, owners


def aggregate(phi: np.ndarray, owners: list[str], features: list[str]) -> np.ndarray:
    """Sum per-column SHAP values into per-original-feature values.

    By additivity, the sum over a feature's one-hot columns is that feature's
    total contribution to f(x) - E[f(X)].
    """
    out = np.zeros((phi.shape[0], len(features)))
    idx = {f: i for i, f in enumerate(features)}
    for j, o in enumerate(owners):
        out[:, idx[o]] += phi[:, j]
    return out


def shap_values(pipe: Pipeline, X_bg, X_explain, method: str = "interventional", n_bg: int = 100,
                seed: int = SEED) -> tuple[np.ndarray, np.ndarray, float]:
    """SHAP values for the positive (churn) class in the model's raw output units
    (log-odds for LR and XGB; probability for sklearn RF).

    Returns (phi [n, p_transformed], Z_explain, base_value).
    method: 'interventional' (marginal / background-based, "true to the model")
            or 'path' (tree_path_dependent, conditional-ish, trees only).
    """
    pre, clf = pipe.named_steps["pre"], pipe.named_steps["clf"]
    Z = pre.transform(X_explain)
    rng = np.random.RandomState(seed)
    bg_idx = rng.choice(len(X_bg), size=min(n_bg, len(X_bg)), replace=False)
    Zbg = pre.transform(X_bg.iloc[bg_idx])
    if isinstance(clf, LogisticRegression):
        ex = shap.LinearExplainer(clf, shap.maskers.Independent(Zbg, max_samples=n_bg))
        phi = ex.shap_values(Z)
        base = float(np.ravel(ex.expected_value)[0])
    else:
        if method == "interventional":
            ex = shap.TreeExplainer(clf, data=Zbg, feature_perturbation="interventional", model_output="raw")
        else:
            ex = shap.TreeExplainer(clf, feature_perturbation="tree_path_dependent")
        phi = ex.shap_values(Z, check_additivity=False)
        base = np.ravel(ex.expected_value)
        if isinstance(clf, RandomForestClassifier):
            # sklearn RF raw output is the class-1 probability (averaged leaf proportions).
            phi = phi[:, :, 1] if phi.ndim == 3 else phi
            base = float(base[-1])
        else:
            base = float(base[0])
    return np.asarray(phi), Z, base
