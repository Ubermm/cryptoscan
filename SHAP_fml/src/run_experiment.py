"""Run the full churn / SHAP-stability experiment and write results to ../results.

Usage:  python run_experiment.py            (about 20-30 min on 4 cores)
"""
from __future__ import annotations

import itertools
import json
import os
import sys
import time
import warnings

import numpy as np
import pandas as pd
from joblib import Parallel, delayed
from scipy.stats import kendalltau, spearmanr
from sklearn.base import clone
from sklearn.inspection import partial_dependence, permutation_importance
from sklearn.metrics import (
    accuracy_score, average_precision_score, brier_score_loss, f1_score,
    precision_recall_curve, precision_score, recall_score, roc_auc_score,
)
from sklearn.model_selection import GridSearchCV, StratifiedKFold

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import (  # noqa: E402
    CATEGORICAL, FEATURES, MODELS, NUMERIC, RESULTS, SEED, aggregate, column_groups,
    load_data, make_pipeline, shap_values, split,
)

warnings.filterwarnings("ignore")
N_JOBS = 4
B = 20                 # bootstrap refits / seed refits
N_EXPLAIN_STAB = 500   # explanation subset for the stability study
N_BOOT_METRIC = 2000   # bootstrap resamples for test-metric CIs
T0 = time.time()


def log(msg):
    print(f"[{time.time() - T0:7.1f}s] {msg}", flush=True)


def save_json(obj, name):
    with open(os.path.join(RESULTS, name), "w") as f:
        json.dump(obj, f, indent=2, default=float)


def ranks(v):
    """Rank 1 = most important."""
    return pd.Series(v).rank(ascending=False, method="average").to_numpy()


def topk(v, k):
    return set(np.argsort(-np.asarray(v))[:k])


def jaccard(a, b):
    return len(a & b) / len(a | b)


def agreement(u, v, k=5):
    """Global-ranking agreement between two importance vectors."""
    ou, ov = np.argsort(-u)[:k], np.argsort(-v)[:k]
    return {
        "spearman": float(spearmanr(u, v)[0]),
        "kendall": float(kendalltau(u, v)[0]),
        f"top{k}_feature_agreement": len(set(ou) & set(ov)) / k,       # Krishna et al. (2022)
        f"top{k}_rank_agreement": float(np.mean(ou == ov)),             # same feature, same position
        "top1_same": bool(ou[0] == ov[0]),
    }


def kendalls_w(mat):
    """Kendall's coefficient of concordance for m raters (rows) x n items (cols)."""
    R = np.vstack([ranks(r) for r in mat])
    m, n = R.shape
    S = ((R.sum(0) - m * (n + 1) / 2) ** 2).sum()
    return float(12 * S / (m ** 2 * (n ** 3 - n)))


def raw_output(pipe, X):
    """Model output in the units SHAP explains (log-odds for LR/XGB, P(churn) for RF)."""
    name = type(pipe.named_steps["clf"]).__name__
    p = pipe.predict_proba(X)[:, 1]
    if name == "RandomForestClassifier":
        return p
    p = np.clip(p, 1e-12, 1 - 1e-12)
    return np.log(p / (1 - p))


# --------------------------------------------------------------------------- data
os.makedirs(RESULTS, exist_ok=True)
X, y, info = load_data()
X_tr, X_va, X_te, y_tr, y_va, y_te = split(X, y)
info.update({
    "n_train": len(X_tr), "n_val": len(X_va), "n_test": len(X_te),
    "churn_rate_train": float(y_tr.mean()), "churn_rate_val": float(y_va.mean()),
    "churn_rate_test": float(y_te.mean()),
    "index_overlap_train_test": len(set(X_tr.index) & set(X_te.index)),
    "index_overlap_train_val": len(set(X_tr.index) & set(X_va.index)),
})
# Leakage audit: exact duplicate feature rows shared between train and test.
key = lambda d: d.astype(str).agg("|".join, axis=1)  # noqa: E731
info["duplicate_feature_rows_train_test"] = int(key(X_te).isin(set(key(X_tr))).sum())
save_json(info, "data_info.json")
log(f"data: {info}")

# --------------------------------------------------------------------------- 1. tuning
grids = {
    "LR": {"clf__C": list(np.logspace(-3, 2, 11))},
    "RF": {"clf__max_depth": [6, 10, 14], "clf__min_samples_leaf": [5, 10, 20],
           "clf__max_features": ["sqrt", 0.3]},
    "XGB": {"clf__n_estimators": [200, 400, 800], "clf__learning_rate": [0.02, 0.05],
            "clf__max_depth": [2, 3, 4]},
}
cv = StratifiedKFold(5, shuffle=True, random_state=SEED)
best, cv_rows = {}, []
for m in MODELS:
    gs = GridSearchCV(make_pipeline(m), grids[m], scoring="roc_auc", cv=cv, n_jobs=N_JOBS)
    gs.fit(X_tr, y_tr)
    best[m] = {k.replace("clf__", ""): (v.item() if hasattr(v, "item") else v) for k, v in gs.best_params_.items()}
    i = gs.best_index_
    cv_rows.append({"model": m, "params": json.dumps(best[m]),
                    "cv_auc_mean": gs.cv_results_["mean_test_score"][i],
                    "cv_auc_sd": gs.cv_results_["std_test_score"][i],
                    "n_configs": len(gs.cv_results_["params"])})
    log(f"tuned {m}: {best[m]} cv auc={gs.best_score_:.4f}")
pd.DataFrame(cv_rows).to_csv(os.path.join(RESULTS, "cv_tuning.csv"), index=False)
save_json(best, "best_params.json")

# --------------------------------------------------------------------------- 2. evaluation
pipes = {m: make_pipeline(m, best[m]).fit(X_tr, y_tr) for m in MODELS}
rng = np.random.RandomState(SEED)
boot_idx = [rng.randint(0, len(y_te), len(y_te)) for _ in range(N_BOOT_METRIC)]
yt = y_te.to_numpy()


def metrics_at(yv, p, thr):
    yhat = (p >= thr).astype(int)
    return {"roc_auc": roc_auc_score(yv, p), "pr_auc": average_precision_score(yv, p),
            "f1": f1_score(yv, yhat), "precision": precision_score(yv, yhat, zero_division=0),
            "recall": recall_score(yv, yhat), "accuracy": accuracy_score(yv, yhat),
            "brier": brier_score_loss(yv, p)}


probs, thresholds, eval_rows = {}, {}, []
for m in MODELS:
    pv = pipes[m].predict_proba(X_va)[:, 1]
    pr, rc, th = precision_recall_curve(y_va, pv)
    f1s = 2 * pr[:-1] * rc[:-1] / np.clip(pr[:-1] + rc[:-1], 1e-12, None)
    thresholds[m] = float(th[np.argmax(f1s)])          # threshold chosen on validation only
    probs[m] = pipes[m].predict_proba(X_te)[:, 1]
    point = metrics_at(yt, probs[m], thresholds[m])
    boots = [metrics_at(yt[b], probs[m][b], thresholds[m]) for b in boot_idx]
    row = {"model": m, "threshold": thresholds[m]}
    for k, v in point.items():
        arr = np.array([d[k] for d in boots])
        row[k], row[k + "_lo"], row[k + "_hi"] = v, np.percentile(arr, 2.5), np.percentile(arr, 97.5)
    eval_rows.append(row)
# Majority-class baseline for context.
eval_rows.append({"model": "Always-stay baseline", "roc_auc": 0.5, "pr_auc": float(yt.mean()),
                  "accuracy": float(1 - yt.mean()), "f1": 0.0})
eval_df = pd.DataFrame(eval_rows)
eval_df.to_csv(os.path.join(RESULTS, "model_comparison.csv"), index=False)

paired = []
for a, b in itertools.combinations(MODELS, 2):
    d = [roc_auc_score(yt[i], probs[a][i]) - roc_auc_score(yt[i], probs[b][i]) for i in boot_idx]
    d_pr = [average_precision_score(yt[i], probs[a][i]) - average_precision_score(yt[i], probs[b][i]) for i in boot_idx]
    paired.append({"pair": f"{a}-{b}",
                   "d_roc_auc": roc_auc_score(yt, probs[a]) - roc_auc_score(yt, probs[b]),
                   "d_roc_auc_lo": np.percentile(d, 2.5), "d_roc_auc_hi": np.percentile(d, 97.5),
                   "d_pr_auc": average_precision_score(yt, probs[a]) - average_precision_score(yt, probs[b]),
                   "d_pr_auc_lo": np.percentile(d_pr, 2.5), "d_pr_auc_hi": np.percentile(d_pr, 97.5)})
pd.DataFrame(paired).to_csv(os.path.join(RESULTS, "paired_differences.csv"), index=False)
np.savez_compressed(os.path.join(RESULTS, "test_probs.npz"), y=yt, **probs)
log("evaluation:\n" + eval_df.round(4).to_string())

# --------------------------------------------------------------------------- 3. main SHAP
shap_main, shap_cols, imp_shap, checks = {}, {}, {}, {}
for m in MODELS:
    phi, Z, base = shap_values(pipes[m], X_tr, X_te, "interventional", n_bg=100)
    names, owners = column_groups(pipes[m])
    agg = aggregate(phi, owners, FEATURES)
    shap_main[m] = {"phi_cols": phi, "Z": Z, "base": base, "agg": agg}
    shap_cols[m] = names
    imp_shap[m] = np.abs(agg).mean(0)
    recon = base + phi.sum(1)
    checks[m] = {"max_additivity_error": float(np.max(np.abs(recon - raw_output(pipes[m], X_te))))}
    log(f"SHAP {m}: additivity err {checks[m]['max_additivity_error']:.2e}")
# LR identity check: interventional linear SHAP = beta_j * (z_j - mean_bg(z_j)).
lr = pipes["LR"].named_steps["clf"]
rng = np.random.RandomState(SEED)
Zbg = pipes["LR"].named_steps["pre"].transform(X_tr.iloc[rng.choice(len(X_tr), 100, replace=False)])
manual = lr.coef_[0] * (shap_main["LR"]["Z"] - Zbg.mean(0))
checks["LR"]["max_err_vs_beta_x_minus_mean"] = float(np.max(np.abs(manual - shap_main["LR"]["phi_cols"])))
save_json(checks, "shap_checks.json")
np.savez_compressed(os.path.join(RESULTS, "shap_main.npz"),
                    **{f"{m}_{k}": v for m in MODELS for k, v in shap_main[m].items()})
save_json(shap_cols, "shap_columns.json")

imp_df = pd.DataFrame({f"shap_{m}": imp_shap[m] for m in MODELS}, index=FEATURES)
for m in MODELS:
    imp_df[f"rank_shap_{m}"] = ranks(imp_shap[m])

# LR coefficients (numerics standardised, one-hot columns unscaled).
coef = pd.DataFrame({"column": shap_cols["LR"], "coef": lr.coef_[0]})
coef["abs"] = coef["coef"].abs()
coef.sort_values("abs", ascending=False).to_csv(os.path.join(RESULTS, "lr_coefficients.csv"), index=False)

# --------------------------------------------------------------------------- RQ1 agreement
rq1 = {f"{a}_vs_{b}": agreement(imp_shap[a], imp_shap[b]) for a, b in itertools.combinations(MODELS, 2)}
# Direction agreement at one-hot-column level: sign of corr(column value, its SHAP value).
direction = {}
for m in MODELS:
    Zm, Pm = shap_main[m]["Z"], shap_main[m]["phi_cols"]
    direction[m] = {c: float(np.sign(np.corrcoef(Zm[:, j], Pm[:, j])[0, 1])) if Zm[:, j].std() > 0 and Pm[:, j].std() > 0 else 0.0
                    for j, c in enumerate(shap_cols[m])}
col_imp = {m: dict(zip(shap_cols[m], np.abs(shap_main[m]["phi_cols"]).mean(0))) for m in MODELS}
union_top = set()
for m in MODELS:
    union_top |= set(sorted(col_imp[m], key=col_imp[m].get, reverse=True)[:10])
dir_rows = [{"column": c, **{f"dir_{m}": direction[m][c] for m in MODELS},
             **{f"imp_{m}": col_imp[m][c] for m in MODELS}} for c in sorted(union_top)]
dir_df = pd.DataFrame(dir_rows)
dir_df["all_agree"] = dir_df[[f"dir_{m}" for m in MODELS]].nunique(axis=1) == 1
dir_df.to_csv(os.path.join(RESULTS, "direction_agreement.csv"), index=False)
rq1["direction_agreement_top10_union"] = {"n_columns": len(dir_df), "n_all_agree": int(dir_df["all_agree"].sum())}
# Local (per-customer) cross-model agreement.
loc = {}
for a, b in itertools.combinations(MODELS, 2):
    A, Bm = np.abs(shap_main[a]["agg"]), np.abs(shap_main[b]["agg"])
    rho = np.array([spearmanr(A[i], Bm[i])[0] for i in range(len(A))])
    top1 = np.mean(A.argmax(1) == Bm.argmax(1))
    loc[f"{a}_vs_{b}"] = {"median_spearman": float(np.median(rho)), "q25": float(np.percentile(rho, 25)),
                          "q75": float(np.percentile(rho, 75)), "top1_agreement": float(top1)}
rq1["local_cross_model"] = loc
save_json(rq1, "rq1_agreement.json")
log("RQ1 done")

# --------------------------------------------------------------------------- RQ3 permutation & drop-column
imp_perm, perm_sd = {}, {}
for m in MODELS:
    r = permutation_importance(pipes[m], X_te, y_te, scoring="roc_auc", n_repeats=30,
                               random_state=SEED, n_jobs=N_JOBS)
    imp_perm[m], perm_sd[m] = r.importances_mean, r.importances_std
    imp_df[f"perm_{m}"], imp_df[f"perm_sd_{m}"] = r.importances_mean, r.importances_std
    imp_df[f"rank_perm_{m}"] = ranks(r.importances_mean)
log("permutation importance done")


def drop_col_auc(m, feat):
    feats = [f for f in FEATURES if f != feat]
    p = make_pipeline(m, best[m], features=feats).fit(X_tr[feats], y_tr)
    return m, feat, roc_auc_score(y_te, p.predict_proba(X_te[feats])[:, 1])


res = Parallel(n_jobs=N_JOBS)(delayed(drop_col_auc)(m, f) for m in MODELS for f in FEATURES)
base_auc = {m: roc_auc_score(y_te, probs[m]) for m in MODELS}
imp_drop = {m: np.zeros(len(FEATURES)) for m in MODELS}
for m, f, auc in res:
    imp_drop[m][FEATURES.index(f)] = base_auc[m] - auc
for m in MODELS:
    imp_df[f"drop_{m}"] = imp_drop[m]
    imp_df[f"rank_drop_{m}"] = ranks(imp_drop[m])
imp_df.index.name = "feature"
imp_df.to_csv(os.path.join(RESULTS, "global_importance.csv"))

methods = {f"SHAP-{m}": imp_shap[m] for m in MODELS}
methods.update({f"Perm-{m}": imp_perm[m] for m in MODELS})
methods.update({f"Drop-{m}": imp_drop[m] for m in MODELS})
keys = list(methods)
sp = pd.DataFrame([[spearmanr(methods[a], methods[b])[0] for b in keys] for a in keys], index=keys, columns=keys)
sp.to_csv(os.path.join(RESULTS, "method_agreement_spearman.csv"))
rq3 = {m: {"shap_vs_perm": agreement(imp_shap[m], imp_perm[m]),
           "shap_vs_drop": agreement(imp_shap[m], imp_drop[m]),
           "perm_vs_drop": agreement(imp_perm[m], imp_drop[m])} for m in MODELS}
# Features whose permutation importance CI includes zero (30 repeats, mean +- 2 sd/sqrt(30) is
# too narrow; we use the raw repeat sd as a conservative band).
rq3["perm_not_distinguishable_from_zero"] = {
    m: [FEATURES[j] for j in range(len(FEATURES)) if imp_perm[m][j] - 2 * perm_sd[m][j] <= 0] for m in MODELS}
rq3["drop_auc_negative_or_zero"] = {m: [FEATURES[j] for j in range(len(FEATURES)) if imp_drop[m][j] <= 0] for m in MODELS}
save_json(rq3, "rq3_methods.json")
log("RQ3 done")

# --------------------------------------------------------------------------- RQ2 stability
rng = np.random.RandomState(SEED + 1)
expl_idx = np.concatenate([
    rng.choice(np.where(yt == c)[0], int(round(N_EXPLAIN_STAB * np.mean(yt == c))), replace=False) for c in (0, 1)])
X_ex = X_te.iloc[np.sort(expl_idx)]
boot_rows = [np.random.RandomState(SEED + 100 + b).randint(0, len(X_tr), len(X_tr)) for b in range(B)]
bg_fixed = X_tr.iloc[np.random.RandomState(SEED).choice(len(X_tr), 100, replace=False)]


def stability_run(m, regime, b):
    if regime == "bootstrap":
        Xb, yb, seed = X_tr.iloc[boot_rows[b]], y_tr.iloc[boot_rows[b]], SEED + b
    else:
        Xb, yb, seed = X_tr, y_tr, SEED + 1000 + b
    p = make_pipeline(m, best[m], seed=seed).fit(Xb, yb)
    phi, _, _ = shap_values(p, bg_fixed, X_ex, "interventional", n_bg=100)
    _, owners = column_groups(p)
    agg = aggregate(phi, owners, FEATURES)
    auc = roc_auc_score(y_te, p.predict_proba(X_te)[:, 1])
    return m, regime, b, agg, auc


jobs = [(m, "bootstrap", b) for m in MODELS for b in range(B)] + \
       [(m, "seed", b) for m in ("RF", "XGB") for b in range(B)]
out = Parallel(n_jobs=N_JOBS, verbose=0)(delayed(stability_run)(*j) for j in jobs)
local = {}
aucs = {}
for m, regime, b, agg, auc in out:
    local.setdefault((m, regime), [None] * B)[b] = agg
    aucs.setdefault((m, regime), [None] * B)[b] = auc
np.savez_compressed(os.path.join(RESULTS, "stability_local.npz"),
                    **{f"{m}_{r}": np.stack(v) for (m, r), v in local.items()}, expl_idx=np.sort(expl_idx))

stab, rank_rows = {}, []
for (m, regime), arrs in local.items():
    L = np.stack(arrs)                     # B x n x p
    G = np.abs(L).mean(1)                  # B x p global importance
    pairs = list(itertools.combinations(range(B), 2))
    rho = np.array([spearmanr(G[i], G[j])[0] for i, j in pairs])
    j5 = np.array([jaccard(topk(G[i], 5), topk(G[j], 5)) for i, j in pairs])
    j3 = np.array([jaccard(topk(G[i], 3), topk(G[j], 3)) for i, j in pairs])
    top1 = pd.Series([FEATURES[g.argmax()] for g in G]).value_counts()
    R = np.vstack([ranks(g) for g in G])
    # Local stability: per customer, mean pairwise Spearman of |phi| across refits,
    # and how often the customer's top feature matches its modal top feature.
    absL = np.abs(L)
    n = L.shape[1]
    loc_rho = np.zeros(n)
    loc_top1 = np.zeros(n)
    for i in range(n):
        Ri = np.vstack([ranks(absL[b, i]) for b in range(B)])
        C = np.corrcoef(Ri)
        loc_rho[i] = C[np.triu_indices(B, 1)].mean()
        t = absL[:, i, :].argmax(1)
        loc_top1[i] = np.bincount(t).max() / B
    # Sign stability for each customer's material contributions: |median phi| >= 10% of its row max.
    med = np.median(L, 0)
    mat = np.abs(med) >= 0.1 * np.abs(med).max(1, keepdims=True)
    agree = (np.sign(L) == np.sign(med)[None]).mean(0)
    stab[f"{m}_{regime}"] = {
        "test_auc_mean": float(np.mean(aucs[(m, regime)])), "test_auc_sd": float(np.std(aucs[(m, regime)])),
        "global_spearman_median": float(np.median(rho)), "global_spearman_min": float(rho.min()),
        "global_spearman_q25": float(np.percentile(rho, 25)),
        "kendalls_w": kendalls_w(G),
        "top3_jaccard_mean": float(j3.mean()), "top5_jaccard_mean": float(j5.mean()),
        "top1_counts": top1.to_dict(),
        "local_spearman_median": float(np.median(loc_rho)), "local_spearman_q10": float(np.percentile(loc_rho, 10)),
        "local_top1_agreement_mean": float(loc_top1.mean()),
        "local_frac_customers_top1_unanimous": float(np.mean(loc_top1 == 1.0)),
        "local_sign_agreement_material": float(agree[mat].mean()),
        "local_frac_material_with_any_sign_flip": float(np.mean(agree[mat] < 1.0)),
    }
    for j, f in enumerate(FEATURES):
        rank_rows.append({"model": m, "regime": regime, "feature": f, "rank_mean": R[:, j].mean(),
                          "rank_sd": R[:, j].std(), "rank_min": R[:, j].min(), "rank_max": R[:, j].max(),
                          "imp_mean": G[:, j].mean(), "imp_cv": G[:, j].std() / max(G[:, j].mean(), 1e-12)})
    np.save(os.path.join(RESULTS, f"stab_global_{m}_{regime}.npy"), G)
# Cross-model vs within-model: paired bootstrap runs b of model A vs model B.
for a, b in itertools.combinations(MODELS, 2):
    Ga = np.abs(np.stack(local[(a, "bootstrap")])).mean(1)
    Gb = np.abs(np.stack(local[(b, "bootstrap")])).mean(1)
    cross = np.array([spearmanr(Ga[i], Gb[j])[0] for i in range(B) for j in range(B)])
    stab[f"cross_{a}_vs_{b}"] = {"spearman_median": float(np.median(cross)),
                                 "spearman_q25": float(np.percentile(cross, 25)),
                                 "spearman_q75": float(np.percentile(cross, 75))}
save_json(stab, "rq2_stability.json")
pd.DataFrame(rank_rows).to_csv(os.path.join(RESULTS, "rq2_rank_spread.csv"), index=False)
log("RQ2 done")

# --------------------------------------------------------------------------- RQ4 correlated features
rq4 = {}
num = X[NUMERIC]
rq4["spearman_numeric"] = num.corr("spearman").round(4).to_dict()
rq4["pearson_numeric"] = num.corr("pearson").round(4).to_dict()
rq4["pearson_TotalCharges_vs_tenure_x_Monthly"] = float(np.corrcoef(X["TotalCharges"], X["tenure"] * X["MonthlyCharges"])[0, 1])
svc = ["OnlineSecurity", "OnlineBackup", "DeviceProtection", "TechSupport", "StreamingTV", "StreamingMovies"]
rq4["no_internet_levels_identical_to_InternetService_No"] = bool(all(
    ((X[c] == "No internet service") == (X["InternetService"] == "No")).all() for c in svc))
rq4["no_phone_level_identical_to_PhoneService_No"] = bool(
    ((X["MultipleLines"] == "No phone service") == (X["PhoneService"] == "No")).all())

# (a) Remove TotalCharges: where does its SHAP credit go?
feats_wo = [f for f in FEATURES if f != "TotalCharges"]
redistrib = []
for m in MODELS:
    p = make_pipeline(m, best[m], features=feats_wo).fit(X_tr[feats_wo], y_tr)
    phi, _, _ = shap_values(p, X_tr[feats_wo], X_te[feats_wo], "interventional")
    _, owners = column_groups(p)
    imp_wo = np.abs(aggregate(phi, owners, feats_wo)).mean(0)
    for f in ["tenure", "MonthlyCharges", "TotalCharges", "Contract", "InternetService"]:
        redistrib.append({"model": m, "feature": f, "with_TotalCharges": imp_shap[m][FEATURES.index(f)],
                          "without_TotalCharges": imp_wo[feats_wo.index(f)] if f in feats_wo else 0.0})
    redistrib.append({"model": m, "feature": "_test_auc", "with_TotalCharges": base_auc[m],
                      "without_TotalCharges": roc_auc_score(y_te, p.predict_proba(X_te[feats_wo])[:, 1])})
pd.DataFrame(redistrib).to_csv(os.path.join(RESULTS, "rq4_drop_totalcharges.csv"), index=False)

# (b) Grouped vs individual permutation of the correlated billing trio.
grp_rows = []
for m in MODELS:
    rs = np.random.RandomState(SEED)
    joint = []
    for _ in range(30):
        Xp = X_te.copy()
        perm = rs.permutation(len(Xp))
        Xp[NUMERIC] = X_te[NUMERIC].to_numpy()[perm]
        joint.append(base_auc[m] - roc_auc_score(y_te, pipes[m].predict_proba(Xp)[:, 1]))
    indiv = sum(imp_perm[m][FEATURES.index(f)] for f in NUMERIC)
    grp_rows.append({"model": m, "joint_perm_drop": float(np.mean(joint)), "joint_sd": float(np.std(joint)),
                     "sum_individual_perm_drop": float(indiv),
                     "shap_sum_trio": float(sum(imp_shap[m][FEATURES.index(f)] for f in NUMERIC)),
                     "shap_trio_joint": float(np.abs(shap_main[m]["agg"][:, [FEATURES.index(f) for f in NUMERIC]].sum(1)).mean())})
pd.DataFrame(grp_rows).to_csv(os.path.join(RESULTS, "rq4_group_permutation.csv"), index=False)

# (c) Interventional vs tree-path-dependent SHAP on the tree models.
pd_rows = []
for m in ("RF", "XGB"):
    phi_p, _, _ = shap_values(pipes[m], X_tr, X_te, "path")
    _, owners = column_groups(pipes[m])
    imp_p = np.abs(aggregate(phi_p, owners, FEATURES)).mean(0)
    rq4[f"{m}_interventional_vs_path"] = agreement(imp_shap[m], imp_p)
    for j, f in enumerate(FEATURES):
        pd_rows.append({"model": m, "feature": f, "interventional": imp_shap[m][j], "path_dependent": imp_p[j]})
pd.DataFrame(pd_rows).to_csv(os.path.join(RESULTS, "rq4_interventional_vs_path.csv"), index=False)

# (d) Duplicate-feature test: add a near-copy of tenure and see how credit splits.
X_dup = X.copy()
X_dup["tenure_copy"] = X_dup["tenure"] + np.random.RandomState(SEED).normal(0, 0.01 * X["tenure"].std(), len(X))
Xd_tr, Xd_te = X_dup.loc[X_tr.index], X_dup.loc[X_te.index]
dup_rows = []
feats_dup = FEATURES + ["tenure_copy"]
for m in MODELS:
    p = make_pipeline(m, best[m], features=feats_dup).fit(Xd_tr[feats_dup], y_tr)
    phi, _, _ = shap_values(p, Xd_tr[feats_dup], Xd_te[feats_dup], "interventional")
    _, owners = column_groups(p)
    imp = np.abs(aggregate(phi, owners, feats_dup)).mean(0)
    dup_rows.append({"model": m, "tenure_original_model": imp_shap[m][0],
                     "tenure_with_copy": imp[feats_dup.index("tenure")],
                     "tenure_copy": imp[feats_dup.index("tenure_copy")],
                     "tenure_rank_original": int(ranks(imp_shap[m])[0]),
                     "tenure_rank_with_copy": int(ranks(imp)[feats_dup.index("tenure")]),
                     "test_auc_with_copy": roc_auc_score(y_te, p.predict_proba(Xd_te[feats_dup])[:, 1])})
pd.DataFrame(dup_rows).to_csv(os.path.join(RESULTS, "rq4_duplicate_feature.csv"), index=False)
save_json(rq4, "rq4_correlation.json")
log("RQ4 done")

# --------------------------------------------------------------------------- Sanity check: retrain without features (ROAR-style)
K = [1, 2, 3, 4, 5]
N_RAND = 10


def auc_without(m, removed):
    feats = [f for f in FEATURES if f not in removed]
    p = make_pipeline(m, best[m], features=feats).fit(X_tr[feats], y_tr)
    return roc_auc_score(y_te, p.predict_proba(X_te[feats])[:, 1])


roar_jobs = []
for m in MODELS:
    order_shap = [FEATURES[j] for j in np.argsort(-imp_shap[m])]
    order_perm = [FEATURES[j] for j in np.argsort(-imp_perm[m])]
    for k in K:
        roar_jobs.append((m, k, "top_shap", 0, tuple(order_shap[:k])))
        roar_jobs.append((m, k, "top_perm", 0, tuple(order_perm[:k])))
        roar_jobs.append((m, k, "bottom_shap", 0, tuple(order_shap[-k:])))
        for r in range(N_RAND):
            rs = np.random.RandomState(SEED + 7 * k + r)
            roar_jobs.append((m, k, "random", r, tuple(rs.choice(FEATURES, k, replace=False))))
roar_auc = Parallel(n_jobs=N_JOBS)(delayed(auc_without)(m, rem) for m, _, _, _, rem in roar_jobs)
roar = pd.DataFrame([{"model": m, "k": k, "strategy": s, "rep": r, "removed": "|".join(rem), "test_auc": a,
                      "auc_drop": base_auc[m] - a} for (m, k, s, r, rem), a in zip(roar_jobs, roar_auc)])
roar.to_csv(os.path.join(RESULTS, "sanity_roar.csv"), index=False)
log("ROAR done")

# PDP vs SHAP dependence for the top numeric features.
pdp_rows = []
for m in MODELS:
    for f in ["tenure", "MonthlyCharges", "TotalCharges"]:
        grid_vals = np.quantile(X_tr[f], np.linspace(0.02, 0.98, 20))
        r = partial_dependence(pipes[m], X_te, [f], grid_resolution=20, kind="average",
                               custom_values={f: grid_vals}, response_method="predict_proba")
        pdv = r["average"][0]
        j = FEATURES.index(f)
        xs, sv = X_te[f].to_numpy(), shap_main[m]["agg"][:, j]
        # Mean SHAP in bins centred on the PD grid.
        edges = np.concatenate([[-np.inf], (grid_vals[1:] + grid_vals[:-1]) / 2, [np.inf]])
        binned = [sv[(xs > lo) & (xs <= hi)].mean() if ((xs > lo) & (xs <= hi)).any() else np.nan
                  for lo, hi in zip(edges[:-1], edges[1:])]
        for g, a, s in zip(grid_vals, pdv, binned):
            pdp_rows.append({"model": m, "feature": f, "x": g, "pd_prob": a, "binned_mean_shap": s})
pdp = pd.DataFrame(pdp_rows)
pdp.to_csv(os.path.join(RESULTS, "sanity_pdp_vs_shap.csv"), index=False)
pdp_agree = {f"{m}_{f}": float(spearmanr(g["pd_prob"], g["binned_mean_shap"], nan_policy="omit")[0])
             for (m, f), g in pdp.groupby(["model", "feature"])}
# Categorical: PD per level vs mean SHAP per level for Contract and InternetService.
cat_rows = []
for m in MODELS:
    for f in ["Contract", "InternetService", "PaymentMethod"]:
        for lvl in sorted(X[f].unique()):
            Xc = X_te.copy()
            Xc[f] = lvl
            cat_rows.append({"model": m, "feature": f, "level": lvl,
                             "pd_prob": float(pipes[m].predict_proba(Xc)[:, 1].mean()),
                             "mean_shap_at_level": float(shap_main[m]["agg"][(X_te[f] == lvl).to_numpy(), FEATURES.index(f)].mean())})
pd.DataFrame(cat_rows).to_csv(os.path.join(RESULTS, "sanity_categorical_pd.csv"), index=False)
save_json(pdp_agree, "sanity_pdp_agreement.json")

# --------------------------------------------------------------------------- local case studies
p_x = probs["XGB"]
cases = {
    "highest_risk": int(np.argmax(p_x)),
    "true_positive_near_threshold": int(np.where((yt == 1) & (p_x >= thresholds["XGB"]))[0][
        np.argmin(p_x[(yt == 1) & (p_x >= thresholds["XGB"])])]),
    "false_negative_most_confident": int(np.where(yt == 1)[0][np.argmin(p_x[yt == 1])]),
}
case_rows = []
for cname, i in cases.items():
    for m in MODELS:
        for j, f in enumerate(FEATURES):
            case_rows.append({"case": cname, "test_pos": i, "model": m, "feature": f,
                              "value": str(X_te.iloc[i][f]), "shap": shap_main[m]["agg"][i, j],
                              "base": shap_main[m]["base"], "prob": probs[m][i], "y": int(yt[i])})
pd.DataFrame(case_rows).to_csv(os.path.join(RESULTS, "local_cases.csv"), index=False)
log("all done")
