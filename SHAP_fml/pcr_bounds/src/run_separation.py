"""E3: reproduce the strong-dominance construction of Theorem 2.2 (positive control).

Instance (paper, Appendix D.4), with eps = 1 so (1 + a)^4 = 2:
    Sigma_n = diag(1/2, (1+a)^2 s_n, s_n I_{m_n}),  m_n = floor(sqrt n),  s_n = 1 / (2((1+a)^2 + m_n)),
    w*_n = sqrt(2 (1 - 1/m_n)) e_1 + sqrt(1 / ((1+a)^2 s_n m_n)) e_2,      sigma = 1, Gaussian design.
Claim: PCR at rho_n = (1+a) s_n has conditional risk O(1/n), while every (eps, delta)-non-step monotone
filter (ridge, GD, gradient flow, iterated ridge, ridge-PCR) has risk Omega(n^{-1/2}) even when tuned.
We compute exact conditional risks (no noise Monte Carlo) and fit log-log slopes.
"""
from __future__ import annotations

import os
import sys

import numpy as np
import pandas as pd
from joblib import Parallel, delayed

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from spectral import FAMILIES, eig_sample, filter_grid, gd_stepsize, wellspec_risk  # noqa: E402

SEED = 20261004
NS = [100, 316, 1000, 3162, 10000, 31623, 100000]
R = 12
RESULTS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "results")


def instance(n):
    a = 2 ** 0.25 - 1
    m = int(np.floor(np.sqrt(n)))
    s = 1 / (2 * ((1 + a) ** 2 + m))
    lam = np.concatenate([[0.5, (1 + a) ** 2 * s], np.full(m, s)])
    w = np.zeros(m + 2)
    w[0] = np.sqrt(2 * (1 - 1 / m))
    w[1] = np.sqrt(1 / ((1 + a) ** 2 * s * m))
    return lam, w, (1 + a) * s


def one(n, r):
    lam, w, rho_n = instance(n)
    rng = np.random.default_rng(SEED + 7 * n + r)
    X = rng.standard_normal((n, len(lam))) * np.sqrt(lam)
    lh, Uh = eig_sample(X)
    A = Uh.T @ np.diag(lam) @ Uh
    a = Uh.T @ w
    eta = gd_stepsize(lam[0], lam.sum(), n)
    out = []
    for fam in FAMILIES:
        hp, G = filter_grid(fam, lh, lam[0], eta)
        bias, var = wellspec_risk(G, lh, a, A, 1.0, n)
        risk = np.where(np.isfinite(bias + var), bias + var, np.inf)
        j = int(np.argmin(risk))
        out.append({"n": n, "draw": r, "family": fam, "risk": risk[j], "bias": bias[j], "var": var[j]})
    # PCR at the paper's prescribed threshold rho_n (not oracle-tuned)
    khat = int((lh > rho_n).sum())
    hp, G = filter_grid("PCR", lh, lam[0], eta)
    bias, var = wellspec_risk(G[khat:khat + 1], lh, a, A, 1.0, n)
    out.append({"n": n, "draw": r, "family": "PCR@rho_n", "risk": bias[0] + var[0], "bias": bias[0],
                "var": var[0], "khat": khat})
    return out


if __name__ == "__main__":
    rows = Parallel(n_jobs=4)(delayed(one)(n, r) for n in NS for r in range(R))
    df = pd.DataFrame([x for rs in rows for x in rs])
    df.to_csv(os.path.join(RESULTS, "separation_instance.csv"), index=False)
    med = df.groupby(["family", "n"])["risk"].median().unstack("n")
    slopes = {f: float(np.polyfit(np.log(NS), np.log(med.loc[f, NS].to_numpy()), 1)[0]) for f in med.index}
    print(med.to_string())
    print("log-log slopes:", {k: round(v, 3) for k, v in slopes.items()})
    pd.Series(slopes, name="slope").to_csv(os.path.join(RESULTS, "separation_slopes.csv"))
