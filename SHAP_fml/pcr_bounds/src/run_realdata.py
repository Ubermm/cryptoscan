"""E1 + E2: dominance and bound tightness on real-world designs (finite-population protocol).

For every dataset, signal and sample size n we draw R training samples from the population and,
for every filter family, compute the exact excess risk over its whole hyperparameter grid.

  * semi-synthetic signals: y = x'w* + N(0, sigma2) with x drawn from the real data; we record
    the exact conditional risk E[ E(w_g) | X ] (the quantity in Theorems 2.1-4.1);
  * real labels: y is the dataset's own target; w* is the population least-squares solution and
    E(w) = ||w - w*||_Sigma^2 exactly. Hyperparameters are tuned both by oracle and by 5-fold CV.

Usage: python run_realdata.py [--quick]
"""
from __future__ import annotations

import json
import os
import sys
import time

os.environ.setdefault("OMP_NUM_THREADS", "1")
os.environ.setdefault("OPENBLAS_NUM_THREADS", "1")

import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
from joblib import Parallel, delayed  # noqa: E402

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from data import LOADERS, design_diagnostics  # noqa: E402
from spectral import (FAMILIES, eig_sample, filter_grid, gd_bound_shape, gd_stepsize,  # noqa: E402
                      pcr_bound_shapes, realized_risk, wellspec_risk)

QUICK = "--quick" in sys.argv
SEED = 20261004
N_GRID = [50, 100, 200, 500, 1000, 2000, 5000]
R_SYN = 6 if QUICK else 40
R_REAL = 6 if QUICK else 60
RESULTS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "results")
SIGNALS = ["real", "head", "powerlaw", "isotropic", "tail"]
T0 = time.time()


def log(m):
    print(f"[{time.time() - T0:7.1f}s] {m}", flush=True)


def make_signal(kind, lam, U, rng):
    """Return w* (original coordinates) with ||w*||_Sigma^2 = 1 for synthetic signals."""
    pos = np.where(lam > 0)[0]
    e = np.zeros(len(lam))                         # Sigma-energy per population eigen-direction
    if kind == "head":
        e[pos[:5]] = 1.0
    elif kind == "powerlaw":
        e[pos] = (np.arange(len(pos)) + 1.0) ** -1.5
    elif kind == "tail":
        m = max(3, len(pos) // 10)
        e[pos[-m:]] = 1.0
    elif kind == "isotropic":
        w = rng.normal(size=U.shape[0])
        c = U.T @ w
        c[lam == 0] = 0.0
        e = lam * c ** 2
        e /= e.sum()
        return U @ c / np.sqrt((lam * c ** 2).sum())
    e /= e.sum()
    c = np.zeros(len(lam))
    c[pos] = np.sqrt(e[pos] / lam[pos])
    return U @ c


def run_task(name, X, y, Sigma, lam, U, w_star, sigma2, signal, n, R, seed):
    rng = np.random.default_rng(seed)
    N, d = X.shape
    lam1, trace = lam[0], lam.sum()
    eta = gd_stepsize(lam1, trace, n)
    rows, bound_rows, cv_rows = [], [], []
    wc = U.T @ w_star
    rho_grid = lam1 * np.logspace(-6, 0.3, 36)
    for r in range(R):
        idx = rng.integers(0, N, n)
        Xs = X[idx]
        lh, Uh = eig_sample(Xs)
        A = Uh.T @ Sigma @ Uh
        a = Uh.T @ w_star
        grids = {}
        for fam in FAMILIES:
            hp, G = filter_grid(fam, lh, lam1, eta)
            if signal == "real_labels":
                ys = y[idx]
                b = Uh.T @ (Xs.T @ ys) / n
                risk = realized_risk(G, lh, a, A, b)
                bias = var = np.full_like(risk, np.nan)
            else:
                bias, var = wellspec_risk(G, lh, a, A, sigma2, n)
                risk = bias + var
            risk = np.where(np.isfinite(risk), risk, np.inf)
            j = int(np.argmin(risk))
            rows.append({"dataset": name, "signal": signal, "n": n, "draw": r, "family": fam,
                         "risk": risk[j], "bias": bias[j], "var": var[j], "best_hp": float(hp[j]),
                         "eta_lhmax": float(eta * lh[0])})
            grids[fam] = (hp, risk)
        # Ordinary least squares (min-norm) and the zero predictor, for reference.
        pcr_hp, pcr_risk = grids["PCR"]
        rows.append({"dataset": name, "signal": signal, "n": n, "draw": r, "family": "OLS",
                     "risk": pcr_risk[-1], "bias": np.nan, "var": np.nan, "best_hp": np.nan})
        rows.append({"dataset": name, "signal": signal, "n": n, "draw": r, "family": "Zero",
                     "risk": pcr_risk[0], "bias": np.nan, "var": np.nan, "best_hp": np.nan})
        if signal != "real_labels" and r < 15:
            for rho in rho_grid:
                khat = int((lh > rho).sum())
                sh = pcr_bound_shapes(lam, wc, sigma2, n, rho, khat)
                bound_rows.append({"dataset": name, "signal": signal, "n": n, "draw": r, "method": "PCR",
                                   "hp": rho / lam1, "risk": pcr_risk[khat], **sh})
            gd_hp, gd_risk = grids["GD"]
            for j in range(0, len(gd_hp), 8):
                sh = gd_bound_shape(lam, wc, sigma2, n, eta, gd_hp[j])
                bound_rows.append({"dataset": name, "signal": signal, "n": n, "draw": r, "method": "GD",
                                   "hp": gd_hp[j], "risk": gd_risk[j], "upper": sh["shape"],
                                   "lower": sh["shape"], "kstar": sh["kstar"], "valid_upper": sh["valid"]})
        if signal == "real_labels":
            cv_rows += cv_tune(name, n, r, Xs, y[idx], lh, Uh, A, a, rng)
    return rows, bound_rows, cv_rows


def cv_tune(name, n, r, Xs, ys, lh, Uh, A, a, rng, folds=5):
    """5-fold CV over each family's grid using only the training sample; return true risk."""
    lam1_hat = lh[0]
    eta_hat = gd_stepsize(lam1_hat, lh.sum(), n)       # sample plug-in for the stepsize rule
    kmax = int((lh > 0).sum())
    perm = rng.permutation(n)
    fold_of = np.empty(n, int)
    fold_of[perm] = np.arange(n) % folds
    sse = {fam: 0.0 for fam in FAMILIES}
    for f in range(folds):
        tr, va = fold_of != f, fold_of == f
        lf, Uf = eig_sample(Xs[tr])
        bf = Uf.T @ (Xs[tr].T @ ys[tr]) / tr.sum()
        Zva = Xs[va] @ Uf
        inv = np.where(lf > 0, 1.0 / np.where(lf > 0, lf, 1.0), 0.0)
        for fam in FAMILIES:
            hp, G = filter_grid(fam, lf, lam1_hat, eta_hat, kmax=kmax if fam == "PCR" else None)
            pred = Zva @ (G * (inv * bf)[None, :]).T
            err = ((pred - ys[va][:, None]) ** 2).sum(0)
            sse[fam] = sse[fam] + np.where(np.isfinite(err), err, np.inf)
    b = Uh.T @ (Xs.T @ ys) / n
    out = []
    for fam in FAMILIES:
        hp, G = filter_grid(fam, lh, lam1_hat, eta_hat, kmax=kmax if fam == "PCR" else None)
        j = int(np.argmin(sse[fam]))
        risk = realized_risk(G[j:j + 1], lh, a, A, b)[0]
        out.append({"dataset": name, "n": n, "draw": r, "family": fam, "cv_risk": risk, "cv_hp": float(hp[j])})
    return out


def main():
    os.makedirs(RESULTS, exist_ok=True)
    all_rows, all_bounds, all_cv, diags = [], [], [], {}
    for di, (name, loader) in enumerate(LOADERS.items()):
        pop = loader()
        diags[name] = design_diagnostics(pop)
        N = len(pop.X)
        ns = [n for n in N_GRID if n <= N // 4]
        if QUICK:
            ns = ns[:3]
        tasks = []
        sigs = SIGNALS if pop.y is not None else [s for s in SIGNALS if s != "real"]
        for si, sig in enumerate(sigs):
            if sig == "real":
                w, s2 = pop.w_star, pop.sigma2
            else:
                w, s2 = make_signal(sig, pop.lam, pop.U, np.random.default_rng(SEED + di)), 1.0
            for n in ns:
                tasks.append((sig, w, s2, n, R_SYN, SEED + 1000 * di + 100 * si + n))
        if pop.y is not None:
            for n in ns:
                tasks.append(("real_labels", pop.w_star, pop.sigma2, n, R_REAL, SEED + 1000 * di + 999 + n))
        log(f"{name}: {len(tasks)} tasks, d={pop.X.shape[1]}, N={N}")
        out = Parallel(n_jobs=4, max_nbytes="1M")(
            delayed(run_task)(name, pop.X, pop.y, pop.Sigma, pop.lam, pop.U, w, s2, sig, n, R, seed)
            for sig, w, s2, n, R, seed in tasks)
        for rows, b, c in out:
            all_rows += rows
            all_bounds += b
            all_cv += c
        log(f"{name}: done")
        del pop
    suffix = "_quick" if QUICK else ""
    pd.DataFrame(all_rows).to_csv(os.path.join(RESULTS, f"oracle_risks{suffix}.csv.gz"), index=False)
    pd.DataFrame(all_bounds).to_csv(os.path.join(RESULTS, f"bound_tracking{suffix}.csv.gz"), index=False)
    pd.DataFrame(all_cv).to_csv(os.path.join(RESULTS, f"cv_risks{suffix}.csv.gz"), index=False)
    with open(os.path.join(RESULTS, f"design_diagnostics{suffix}.json"), "w") as f:
        json.dump(diags, f, indent=2)
    log("all done")


if __name__ == "__main__":
    main()
