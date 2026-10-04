"""E4: does discarding weak spectral directions stabilise explanations on the churn data?

The parent study found logistic regression's SHAP ranking unstable under bootstrap resampling
because MonthlyCharges is ~99.9% a linear function of the service dummies (a near-null direction
of Sigma). Kim et al. (2026) show PCR's advantage comes from zeroing such weak directions.
Here we refit linear-probability models (OLS, ridge, PCR, GD; each CV-tuned) on exactly the same
20 bootstrap training samples, explanation subset and background rows as the parent study, and
compare linear-SHAP rank stability (phi_ij = beta_j (z_ij - mean_bg z_j), grouped by feature).
"""
from __future__ import annotations

import itertools
import json
import os
import sys

import numpy as np
import pandas as pd
from scipy.stats import spearmanr
from sklearn.metrics import roc_auc_score

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(HERE)), "src"))
from common import FEATURES, SEED, load_data, preprocessor, split  # noqa: E402
from spectral import eig_sample, filter_grid, gd_stepsize  # noqa: E402

RESULTS = os.path.join(os.path.dirname(HERE), "results")
PARENT = os.path.join(os.path.dirname(os.path.dirname(HERE)), "results")
B = 20
METHODS = ["OLS", "Ridge", "PCR", "GD", "PCR_k20", "PCR_k22"]   # PCR_kK: k fixed, not CV-tuned


def owners_of(pre):
    owners = []
    for tname, trans, cols in pre.transformers_:
        if tname == "num":
            owners += list(cols)
        elif tname == "cat":
            for col, cats in zip(cols, trans.categories_):
                owners += [col] * len(cats)
    return owners


def fit_cv(Z, y, family, rng, folds=5):
    """CV-tune one spectral family on centred (Z, y); return coefficients and chosen hp."""
    n = len(Z)
    lh, Uh = eig_sample(Z)
    eta = gd_stepsize(lh[0], lh.sum(), n)
    kmax = int((lh > 0).sum())
    fam = "PCR" if family == "OLS" or family.startswith("PCR_k") else family
    fold_of = np.empty(n, int)
    fold_of[rng.permutation(n)] = np.arange(n) % folds
    sse = 0.0
    for f in range(folds):
        tr, va = fold_of != f, fold_of == f
        lf, Uf = eig_sample(Z[tr])
        bf = Uf.T @ (Z[tr].T @ y[tr]) / tr.sum()
        inv = np.where(lf > 0, 1 / np.where(lf > 0, lf, 1), 0)
        _, G = filter_grid(fam, lf, lh[0], eta, kmax=kmax if fam == "PCR" else None)
        pred = (Z[va] @ Uf) @ (G * (inv * bf)[None, :]).T
        err = ((pred - y[va][:, None]) ** 2).sum(0)
        sse = sse + np.where(np.isfinite(err), err, np.inf)
    hp, G = filter_grid(fam, lh, lh[0], eta, kmax=kmax if fam == "PCR" else None)
    if family == "OLS":
        j = len(hp) - 1                                   # OLS = PCR keeping every PC
    elif family.startswith("PCR_k"):
        j = int(family[5:])                               # fixed number of components
    else:
        j = int(np.argmin(sse))
    inv = np.where(lh > 0, 1 / np.where(lh > 0, lh, 1), 0)
    beta = Uh @ (G[j] * inv * (Uh.T @ (Z.T @ y) / n))
    return beta, float(hp[j])


def main():
    X, y, _ = load_data()
    X_tr, X_va, X_te, y_tr, y_va, y_te = split(X, y)
    expl_idx = np.load(os.path.join(PARENT, "stability_local.npz"))["expl_idx"]
    X_ex = X_te.iloc[expl_idx]
    bg = X_tr.iloc[np.random.RandomState(SEED).choice(len(X_tr), 100, replace=False)]
    boot_rows = [np.random.RandomState(SEED + 100 + b).randint(0, len(X_tr), len(X_tr)) for b in range(B)]
    imp = {m: [] for m in METHODS}
    hps, aucs, ranks_rows = {m: [] for m in METHODS}, {m: [] for m in METHODS}, []
    for b in range(B):
        Xb, yb = X_tr.iloc[boot_rows[b]], y_tr.iloc[boot_rows[b]].to_numpy(float)
        pre = preprocessor().fit(Xb)
        Zb = pre.transform(Xb)
        mu, ybar = Zb.mean(0), yb.mean()
        owners = owners_of(pre)
        Zex = pre.transform(X_ex) - pre.transform(bg).mean(0)
        Zte = pre.transform(X_te) - mu
        for m in METHODS:
            beta, hp = fit_cv(Zb - mu, yb - ybar, m, np.random.default_rng(SEED + b))
            phi = Zex * beta[None, :]
            agg = np.zeros((len(Zex), len(FEATURES)))
            for j, o in enumerate(owners):
                agg[:, FEATURES.index(o)] += phi[:, j]
            imp[m].append(np.abs(agg).mean(0))
            hps[m].append(hp)
            aucs[m].append(roc_auc_score(y_te, Zte @ beta))
    out = {}
    lr_parent = json.load(open(os.path.join(PARENT, "rq2_stability.json")))["LR_bootstrap"]
    out["parent_logistic_regression"] = {k: lr_parent[k] for k in
                                         ["global_spearman_median", "global_spearman_min", "kendalls_w", "top1_counts"]}
    for m in METHODS:
        G = np.array(imp[m])
        rho = [spearmanr(G[i], G[j])[0] for i, j in itertools.combinations(range(B), 2)]
        mc = G[:, FEATURES.index("MonthlyCharges")]
        out[m] = {"global_spearman_median": float(np.median(rho)), "global_spearman_min": float(np.min(rho)),
                  "global_spearman_q25": float(np.percentile(rho, 25)),
                  "top1_counts": pd.Series([FEATURES[g.argmax()] for g in G]).value_counts().to_dict(),
                  "MonthlyCharges_importance_min": float(mc.min()), "MonthlyCharges_importance_max": float(mc.max()),
                  "MonthlyCharges_max_over_min": float(mc.max() / max(mc.min(), 1e-12)),
                  "test_auc_mean": float(np.mean(aucs[m])), "test_auc_sd": float(np.std(aucs[m])),
                  "chosen_hp_median": float(np.median(hps[m])), "chosen_hp_min": float(np.min(hps[m])),
                  "chosen_hp_max": float(np.max(hps[m]))}
        R = np.vstack([pd.Series(g).rank(ascending=False).to_numpy() for g in G])
        for j, f in enumerate(FEATURES):
            ranks_rows.append({"method": m, "feature": f, "rank_mean": R[:, j].mean(), "rank_sd": R[:, j].std(),
                               "rank_min": R[:, j].min(), "rank_max": R[:, j].max()})
        np.save(os.path.join(RESULTS, f"churn_global_{m}.npy"), G)
    json.dump(out, open(os.path.join(RESULTS, "churn_stability.json"), "w"), indent=2)
    pd.DataFrame(ranks_rows).to_csv(os.path.join(RESULTS, "churn_rank_spread.csv"), index=False)
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
