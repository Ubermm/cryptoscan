"""Monotone spectral filters, exact risks, and the Kim-Fu-Bartlett-Lee-Wu (2026) bound shapes.

Notation follows arXiv:2609.39440. With Sigma_hat = X'X/n = sum_i lh_i uh_i uh_i', a spectral
filter g gives  w_g = sum_i g(lh_i)/lh_i * uh_i uh_i' X'y/n.  Everything is computed in the
empirical eigenbasis, so each estimator below is *exact* (e.g. GD is the closed form of t
gradient steps from zero, not an approximation).
"""
from __future__ import annotations

import numpy as np

TOL = 1e-10
FAMILIES = ["PCR", "Ridge", "GD", "GradFlow", "IterRidge2", "RidgePCR"]


def eig_sample(X: np.ndarray):
    n = len(X)
    lh, Uh = np.linalg.eigh(X.T @ X / n)
    o = np.argsort(lh)[::-1]
    lh, Uh = np.clip(lh[o], 0, None), Uh[:, o]
    lh[lh < TOL * max(lh[0], 1e-300)] = 0.0
    return lh, Uh


def gd_stepsize(lam1: float, trace: float, n: int, c: float = 2.0) -> float:
    """Stepsize in the paper's stable regime: eta <= 1 / (c (lambda_1 + tr(Sigma)/n))."""
    return 1.0 / (c * (lam1 + trace / n))


def filter_grid(family: str, lh: np.ndarray, lam1: float, eta: float, kmax: int | None = None):
    """Return (hyperparameter values, G) where G[h, i] = g_h(lh_i), g(0) = 0.

    lam1 only scales the grids; kmax fixes the PCR grid length (needed for CV folds).
    """
    z = lh[None, :]
    pos = lh > 0
    if family == "PCR":
        k = np.arange(0, (int(pos.sum()) if kmax is None else kmax) + 1)   # keep the top-k empirical PCs
        G = (np.arange(len(lh))[None, :] < k[:, None]).astype(float)
        hp = k
    elif family == "Ridge":
        hp = lam1 * np.logspace(-9, 1.5, 211)
        G = z / (z + hp[:, None])
    elif family == "IterRidge2":
        hp = lam1 * np.logspace(-9, 1.5, 211)
        G = 1 - (hp[:, None] / (z + hp[:, None])) ** 2
    elif family == "GD":
        hp = np.unique(np.round(np.logspace(0, 10, 241))).astype(float)
        # Exact t-step GD from zero. If eta * lh > 1 (heavy-tailed samples can exceed the
        # population-based stable stepsize) the factor oscillates, and if > 2 it diverges,
        # exactly as real GD would; such entries are reported, not clipped.
        with np.errstate(over="ignore", invalid="ignore"):
            G = 1.0 - np.power(1.0 - eta * z, hp[:, None])
    elif family == "GradFlow":
        hp = np.logspace(-2, 10.5, 251) / lam1
        G = -np.expm1(-hp[:, None] * z)
    elif family == "RidgePCR":
        hp = lam1 * np.logspace(-9, 1.5, 211)
        G = np.minimum(1.0, z / hp[:, None])
    else:
        raise ValueError(family)
    G = np.where(pos[None, :], G, 0.0)
    G = np.where(np.isfinite(G), G, np.inf)
    return hp, G


def wellspec_risk(G, lh, a, A, sigma2, n):
    """Exact E[ ||w_g - w*||_Sigma^2 | X ] for y = x'w* + eps, Var(eps) = sigma2.

    a = Uh' w*, A = Uh' Sigma Uh.  Bias = ((g-1) a)' A ((g-1) a);
    Variance = sigma2/n * sum_i g_i^2 A_ii / lh_i.
    """
    B = (G - 1.0) * a[None, :]
    bias = np.einsum("hd,de,he->h", B, A, B, optimize=True)
    inv = np.where(lh > 0, 1.0 / np.where(lh > 0, lh, 1.0), 0.0)
    var = sigma2 / n * (G ** 2 * (np.diag(A) * inv)[None, :]).sum(1)
    return bias, var


def realized_risk(G, lh, a, A, b):
    """||w_g - w*||_Sigma^2 for the realized sample; b = Uh' X'y / n."""
    inv = np.where(lh > 0, 1.0 / np.where(lh > 0, lh, 1.0), 0.0)
    D = G * (inv * b)[None, :] - a[None, :]
    return np.einsum("hd,de,he->h", D, A, D, optimize=True)


# ----------------------------------------------------------------------------- bound shapes
# All absolute constants (c1..c4) are set to 1 and the failure probability delta = 0.01.
# A bound is "instance-wise tight up to constants" iff risk / shape stays inside a bounded
# band across instances; that band is what the experiment measures.

def _norms(lam, wc):
    """Prefix/suffix helpers in the population eigenbasis: wc = U' w*."""
    with np.errstate(divide="ignore", invalid="ignore"):
        head_inv = np.concatenate([[0.0], np.cumsum(np.where(lam > 0, wc ** 2 / np.where(lam > 0, lam, 1), 0.0))])
    tail_sig = np.concatenate([np.cumsum((lam * wc ** 2)[::-1])[::-1], [0.0]])
    S1 = np.concatenate([np.cumsum(lam[::-1])[::-1], [0.0]])          # S1[k] = sum_{i>k} lam_i
    S2 = np.concatenate([np.cumsum((lam ** 2)[::-1])[::-1], [0.0]])
    return head_inv, tail_sig, S1, S2


def pcr_bound_shapes(lam, wc, sigma2, n, rho, khat, c2=1.0, delta=0.01):
    """Theorem 4.1 upper and lower bound shapes for PCR at threshold rho (constants = 1)."""
    head_inv, tail_sig, S1, S2 = _norms(lam, wc)
    d = len(lam)
    alpha = S2 / n + (S1 / n) ** 2
    lam_next = np.concatenate([lam, [0.0]])                            # lam_next[k] = lam_{k+1}
    ks = np.arange(d + 1)
    kstar = int(ks[(1.1 * rho + S1 / (c2 * n)) >= lam_next][0])
    D = kstar + S2[kstar] / (rho + S1[kstar] / n) ** 2 if (rho + S1[kstar] / n) > 0 else kstar
    upper = ((alpha[kstar] + lam_next[kstar] ** 2 * np.log(1 / delta) / n) * head_inv[kstar]
             + tail_sig[kstar] + sigma2 * min(D, khat) / n)
    rstar = int(ks[(lam_next + S1 / n) <= 0.9 * rho][0]) if np.any((lam_next + S1 / n) <= 0.9 * rho) else d
    rho_t = max(1.1 * rho, S1[kstar] / n)
    lower = alpha[rstar] * head_inv[kstar] + tail_sig[rstar] + sigma2 * np.sum(lam > rho_t) / n
    return {"kstar": kstar, "rstar": rstar, "upper": float(upper), "lower": float(lower),
            "valid_upper": bool(kstar <= n)}


def gd_bound_shape(lam, wc, sigma2, n, eta, t, c2=1.0):
    """Corollary 3.1 shape for GD (upper and lower coincide up to constants)."""
    head_inv, tail_sig, S1, S2 = _norms(lam, wc)
    d = len(lam)
    lam_next = np.concatenate([lam, [0.0]])
    ks = np.arange(d + 1)
    kstar = int(ks[(1 / (eta * t) + S1 / n) >= c2 * lam_next][0])
    lt = 1 / (eta * t) + S1[kstar] / n
    D = kstar + S2[kstar] / lt ** 2
    opt = np.sum((lam[:kstar] * (1 - eta * lam[:kstar]) ** (2 * t)) * wc[:kstar] ** 2)
    shape = opt + (S1[kstar] / n) ** 2 * head_inv[kstar] + tail_sig[kstar] + sigma2 * D / n
    return {"kstar": kstar, "shape": float(shape), "valid": bool(kstar <= n)}
