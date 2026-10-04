"""Real-world design matrices used as finite populations.

Each loader returns a `Population`: the full dataset is treated as the population
distribution (uniform over rows), so the population covariance Sigma, the
population least-squares solution w*, and the excess risk ||w - w*||_Sigma^2 are
all known exactly. Training samples are drawn i.i.d. (with replacement) from it.
"""
from __future__ import annotations

import io
import os
import sys
import urllib.request
import zipfile
from dataclasses import dataclass, field

import numpy as np
import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DATA = os.path.join(ROOT, "data")
sys.path.insert(0, os.path.join(os.path.dirname(ROOT), "src"))  # the churn study's common.py

SOURCES = {
    "superconductivity": "https://archive.ics.uci.edu/static/public/464/superconductivty+data.zip",
    "communities": "https://archive.ics.uci.edu/static/public/183/communities+and+crime.zip",
    "yearmsd": "https://archive.ics.uci.edu/static/public/203/yearpredictionmsd.zip",
    "mnist": "https://storage.googleapis.com/tensorflow/tf-keras-datasets/mnist.npz",
}


@dataclass
class Population:
    name: str
    X: np.ndarray            # N x d, centred with the population mean
    y: np.ndarray | None     # N, centred (None: no natural regression target)
    target: str
    feature_names: list = field(default_factory=list)
    # derived
    Sigma: np.ndarray = None
    lam: np.ndarray = None   # population eigenvalues, descending
    U: np.ndarray = None     # population eigenvectors (columns)
    w_star: np.ndarray = None
    sigma2: float = None     # population residual variance of y about x'w*

    def finalize(self):
        N = len(self.X)
        self.Sigma = self.X.T @ self.X / N
        lam, U = np.linalg.eigh(self.Sigma)
        order = np.argsort(lam)[::-1]
        lam = np.clip(lam[order], 0, None)
        lam[lam < 1e-12 * lam[0]] = 0.0
        self.lam, self.U = lam, U[:, order]
        if self.y is not None:
            xy = self.X.T @ self.y / N
            inv = np.where(self.lam > 0, 1 / np.where(self.lam > 0, self.lam, 1), 0)
            self.w_star = self.U @ (inv * (self.U.T @ xy))      # min-norm population OLS
            self.sigma2 = float(np.mean((self.y - self.X @ self.w_star) ** 2))
        return self


def _download(key: str) -> str:
    os.makedirs(DATA, exist_ok=True)
    path = os.path.join(DATA, os.path.basename(SOURCES[key]).replace("+", "_"))
    if not os.path.exists(path):
        urllib.request.urlretrieve(SOURCES[key], path)
    return path


def _standardize(X: np.ndarray) -> np.ndarray:
    X = X - X.mean(0)
    sd = X.std(0)
    keep = sd > 0
    return X[:, keep] / sd[keep], keep


def superconductivity() -> Population:
    with zipfile.ZipFile(_download("superconductivity")) as z:
        df = pd.read_csv(z.open("train.csv"))
    y = df.pop("critical_temp").to_numpy(float)
    X, keep = _standardize(df.to_numpy(float))
    return Population("superconductivity", X, y - y.mean(), "critical temperature (K)",
                      list(df.columns[keep])).finalize()


def communities() -> Population:
    with zipfile.ZipFile(_download("communities")) as z:
        raw = z.read("communities.data").decode()
    df = pd.read_csv(io.StringIO(raw), header=None, na_values="?")
    df = df.drop(columns=[0, 1, 2, 3, 4])        # state, county, community, name, fold: not predictive
    y = df.pop(df.columns[-1]).to_numpy(float)    # ViolentCrimesPerPop
    df = df.dropna(axis=1)                        # drop the ~22 mostly-missing police columns
    X, keep = _standardize(df.to_numpy(float))
    return Population("communities", X, y - y.mean(), "violent crimes per capita (normalised)",
                      [str(c) for c in df.columns[keep]]).finalize()


def yearmsd() -> Population:
    with zipfile.ZipFile(_download("yearmsd")) as z:
        name = [n for n in z.namelist() if n.endswith(".txt")][0]
        arr = pd.read_csv(z.open(name), header=None, dtype=np.float64).to_numpy()
    y, X = arr[:, 0], arr[:, 1:]
    X, keep = _standardize(X)
    return Population("yearmsd", X, y - y.mean(), "release year",
                      [f"timbre_{i}" for i in range(X.shape[1])]).finalize()


def mnist() -> Population:
    with np.load(_download("mnist")) as f:
        X = np.concatenate([f["x_train"], f["x_test"]]).reshape(-1, 784).astype(float) / 255.0
    keep = X.std(0) > 0
    X = X[:, keep]
    X = X - X.mean(0)                              # pixels share a scale: centre, do not standardise
    return Population("mnist", X, None, "none (semi-synthetic targets only)",
                      [f"px{i}" for i in np.where(keep)[0]]).finalize()


def telco() -> Population:
    """The churn data from the parent SHAP study, encoded exactly as its LR pipeline."""
    from common import load_data, preprocessor   # noqa: E402
    X, y, _ = load_data()
    pre = preprocessor().fit(X)
    Z = pre.transform(X)
    Z = Z - Z.mean(0)
    yv = y.to_numpy(float)
    names = list(pre.get_feature_names_out())
    return Population("telco_churn", Z, yv - yv.mean(), "churn (0/1), linear probability model",
                      names).finalize()


LOADERS = {"superconductivity": superconductivity, "communities": communities,
           "yearmsd": yearmsd, "mnist": mnist, "telco_churn": telco}


def design_diagnostics(p: Population) -> dict:
    """Spectrum summary and how far the design is from the theorems' assumptions."""
    lam = p.lam
    pos = lam[lam > 0]
    # Whitened principal-component scores: under Assumption 1A these are independent
    # with bounded sub-Gaussian norm; under Gaussian design their excess kurtosis is 0.
    k = min(20, len(pos))
    S = p.X @ p.U[:, :k] / np.sqrt(pos[:k])
    kurt = (S ** 4).mean(0) / (S ** 2).mean(0) ** 2 - 3
    # Fit lambda_i ~ i^{-a} on the top half of the positive spectrum.
    m = max(3, len(pos) // 2)
    a = -np.polyfit(np.log(np.arange(1, m + 1)), np.log(pos[:m]), 1)[0]
    out = {"N": int(len(p.X)), "d": int(p.X.shape[1]), "rank": int((lam > 0).sum()),
           "trace": float(lam.sum()), "lambda1": float(lam[0]),
           "effective_rank_r0": float(lam.sum() / lam[0]),
           "top5_variance_share": float(lam[:5].sum() / lam.sum()),
           "powerlaw_exponent_top_half": float(a),
           "condition_number_positive": float(pos[0] / pos[-1]),
           "pc_score_excess_kurtosis_median_top20": float(np.median(kurt)),
           "pc_score_excess_kurtosis_max_top20": float(np.max(kurt))}
    if p.y is not None:
        out.update({"target": p.target, "pop_R2_linear": float(1 - p.sigma2 / np.mean(p.y ** 2)),
                    "snr": float(p.w_star @ p.Sigma @ p.w_star / p.sigma2)})
    return out
