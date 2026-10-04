"""Post-hoc checks added after inspecting the main run (reported as such in README)."""
import json
import os
import sys

import itertools

import numpy as np
import pandas as pd
from scipy.stats import spearmanr
from sklearn.linear_model import LinearRegression

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import FEATURES, RESULTS, load_data  # noqa: E402

X, y, _ = load_data()
svc = ["PhoneService", "MultipleLines", "InternetService", "OnlineSecurity", "OnlineBackup",
       "DeviceProtection", "TechSupport", "StreamingTV", "StreamingMovies"]
D = pd.get_dummies(X[svc]).astype(float)
out = {
    "r2_MonthlyCharges_on_service_dummies": LinearRegression().fit(D, X["MonthlyCharges"]).score(D, X["MonthlyCharges"]),
    "churn_rate_by_MonthlyCharges_quartile": {str(k): v for k, v in y.groupby(pd.qcut(X["MonthlyCharges"], 4), observed=True).mean().items()},
    "churn_rate_by_Contract": y.groupby(X["Contract"]).mean().to_dict(),
    "churn_rate_by_InternetService": y.groupby(X["InternetService"]).mean().to_dict(),
    "churn_rate_by_PaymentMethod": y.groupby(X["PaymentMethod"]).mean().to_dict(),
    "churn_rate_by_tenure_band": {str(k): v for k, v in y.groupby(pd.cut(X["tenure"], [-1, 6, 12, 24, 48, 72]), observed=True).mean().items()},
}
# Why is LR's bootstrap stability bimodal? Track MonthlyCharges' importance across refits.
G = np.load(os.path.join(RESULTS, "stab_global_LR_bootstrap.npy"))
j = FEATURES.index("MonthlyCharges")
hi = G[:, j] > np.median(G[:, j])
pairs = list(itertools.combinations(range(len(G)), 2))
out["lr_bootstrap_MonthlyCharges_importance"] = G[:, j].round(4).tolist()
out["lr_bootstrap_rho_same_MC_regime_median"] = float(np.median([spearmanr(G[a], G[b])[0] for a, b in pairs if hi[a] == hi[b]]))
out["lr_bootstrap_rho_diff_MC_regime_median"] = float(np.median([spearmanr(G[a], G[b])[0] for a, b in pairs if hi[a] != hi[b]]))
out["lr_bootstrap_corr_MC_vs_service_importance"] = {
    f: float(np.corrcoef(G[:, j], G[:, FEATURES.index(f)])[0, 1]) for f in ["StreamingMovies", "StreamingTV", "InternetService", "tenure"]}

with open(os.path.join(RESULTS, "rq4_extra.json"), "w") as f:
    json.dump(out, f, indent=2)
print(json.dumps(out, indent=2))
