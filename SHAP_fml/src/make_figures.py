"""Build all figures from ../results into ../figures."""
from __future__ import annotations

import json
import os
import sys

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
import shap  # noqa: E402
from sklearn.metrics import precision_recall_curve, roc_curve  # noqa: E402

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import FEATURES, FIGURES, MODELS, NUMERIC, RESULTS  # noqa: E402

# Reference palette (light mode), fixed slot order: model identity never changes colour.
SURFACE, INK, INK2, GRID = "#fcfcfb", "#0b0b0b", "#52514e", "#e4e3df"
C = {"LR": "#2a78d6", "RF": "#eb6834", "XGB": "#1baf7a"}
NAMES = {"LR": "Logistic regression", "RF": "Random forest", "XGB": "XGBoost"}
SEQ = ["#cde2fb", "#9ec5f4", "#6da7ec", "#3987e5", "#256abf", "#184f95", "#0d366b"]

plt.rcParams.update({
    "figure.facecolor": SURFACE, "axes.facecolor": SURFACE, "savefig.facecolor": SURFACE,
    "axes.edgecolor": GRID, "axes.labelcolor": INK2, "xtick.color": INK2, "ytick.color": INK2,
    "text.color": INK, "axes.titlecolor": INK, "axes.grid": True, "grid.color": GRID,
    "grid.linewidth": 0.6, "axes.spines.top": False, "axes.spines.right": False,
    "font.size": 9.5, "axes.titlesize": 10.5, "axes.titleweight": "semibold", "legend.frameon": False,
    "lines.linewidth": 2,
})
os.makedirs(FIGURES, exist_ok=True)


def save(fig, name):
    fig.savefig(os.path.join(FIGURES, name), dpi=160, bbox_inches="tight")
    plt.close(fig)


def load(name):
    return pd.read_csv(os.path.join(RESULTS, name))


# ---------------------------------------------------------------- 1. ROC / PR
tp = np.load(os.path.join(RESULTS, "test_probs.npz"))
y = tp["y"]
fig, axs = plt.subplots(1, 2, figsize=(9.5, 4))
mc = load("model_comparison.csv").set_index("model")
for m in MODELS:
    fpr, tpr, _ = roc_curve(y, tp[m])
    axs[0].plot(fpr, tpr, color=C[m], label=f"{NAMES[m]} (AUC {mc.loc[m, 'roc_auc']:.3f})")
    pr, rc, _ = precision_recall_curve(y, tp[m])
    axs[1].plot(rc, pr, color=C[m], label=f"{NAMES[m]} (AP {mc.loc[m, 'pr_auc']:.3f})")
axs[0].plot([0, 1], [0, 1], color=INK2, lw=1, ls="--")
axs[1].axhline(y.mean(), color=INK2, lw=1, ls="--")
axs[1].text(0.02, y.mean() + 0.02, f"prevalence {y.mean():.3f}", color=INK2, fontsize=8)
axs[0].set(xlabel="False positive rate", ylabel="True positive rate", title="ROC curve (test set)")
axs[1].set(xlabel="Recall", ylabel="Precision", title="Precision-recall curve (test set)", ylim=(0, 1.02))
for a in axs:
    a.legend(loc="lower right" if a is axs[0] else "upper right", fontsize=8.5)
save(fig, "01_roc_pr.png")

# ---------------------------------------------------------------- 2. global importance
imp = load("global_importance.csv").set_index("feature")
order = imp["shap_XGB"].sort_values().index
fig, axs = plt.subplots(1, 3, figsize=(11, 5), sharey=True)
for a, m in zip(axs, MODELS):
    v = imp.loc[order, f"shap_{m}"]
    a.barh(range(len(v)), v / v.max(), color=C[m], height=0.7)
    a.set_title(f"{NAMES[m]}")
    a.set_xlabel("mean |SHAP|, scaled to max = 1")
    for i, r in enumerate(imp.loc[order, f"rank_shap_{m}"]):
        if r <= 5:
            a.text(v.iloc[i] / v.max() + 0.02, i, f"#{int(r)}", va="center", fontsize=8, color=INK2)
    a.set_xlim(0, 1.18)
    a.grid(axis="y", visible=False)
axs[0].set_yticks(range(len(order)), order)
fig.suptitle("Global SHAP importance by model (interventional SHAP, test set, one-hot columns summed per feature)",
             fontsize=10.5, x=0.02, ha="left")
fig.tight_layout()
save(fig, "02_global_importance.png")

# ---------------------------------------------------------------- 3. beeswarm (XGB, column level)
sm = np.load(os.path.join(RESULTS, "shap_main.npz"))
cols = json.load(open(os.path.join(RESULTS, "shap_columns.json")))
plt.figure()
shap.summary_plot(sm["XGB_phi_cols"], sm["XGB_Z"], feature_names=cols["XGB"], max_display=15, show=False,
                  plot_size=(8, 6))
plt.title("XGBoost: SHAP values per one-hot column (log-odds), top 15", loc="left")
save(plt.gcf(), "03_beeswarm_xgb.png")

# ---------------------------------------------------------------- 4. dependence + PD
pdp = load("sanity_pdp_vs_shap.csv")
fig, axs = plt.subplots(2, 3, figsize=(11, 6.5))
for k, f in enumerate(NUMERIC):
    a = axs[0, k]
    for m in MODELS:
        g = pdp[(pdp.model == m) & (pdp.feature == f)]
        a.plot(g["x"], g["binned_mean_shap"] / np.nanmax(np.abs(g["binned_mean_shap"])), color=C[m], label=NAMES[m])
    a.axhline(0, color=INK2, lw=0.8)
    a.set(title=f"{f}: binned mean SHAP", xlabel=f, ylabel="scaled mean SHAP" if k == 0 else None)
    b = axs[1, k]
    for m in MODELS:
        g = pdp[(pdp.model == m) & (pdp.feature == f)]
        b.plot(g["x"], g["pd_prob"], color=C[m], label=NAMES[m])
    b.set(title=f"{f}: partial dependence", xlabel=f, ylabel="P(churn)" if k == 0 else None)
axs[0, 0].legend(fontsize=8)
fig.tight_layout()
save(fig, "04_dependence_vs_pdp.png")

# ---------------------------------------------------------------- 5. local cases
cases = load("local_cases.csv")
for cname in cases["case"].unique():
    fig, axs = plt.subplots(1, 3, figsize=(12, 4.2), sharey=False)
    for a, m in zip(axs, MODELS):
        g = cases[(cases.case == cname) & (cases.model == m)].copy()
        g = g.reindex(g["shap"].abs().sort_values(ascending=False).index).head(8)[::-1]
        colors = ["#e34948" if s > 0 else "#2a78d6" for s in g["shap"]]
        a.barh([f"{f} = {v}" for f, v in zip(g["feature"], g["value"])], g["shap"], color=colors, height=0.65)
        a.axvline(0, color=INK2, lw=0.8)
        unit = "P(churn)" if m == "RF" else "log-odds"
        a.set_title(f"{NAMES[m]}: p = {g['prob'].iloc[0]:.2f}")
        a.set_xlabel(f"SHAP ({unit}); red pushes toward churn")
        a.grid(axis="y", visible=False)
    yv = int(cases[cases.case == cname]["y"].iloc[0])
    fig.suptitle(f"Local explanation, case '{cname}' (actual: {'churned' if yv else 'stayed'}), top 8 features per model",
                 x=0.02, ha="left", fontsize=10.5)
    fig.tight_layout()
    save(fig, f"05_local_{cname}.png")

# ---------------------------------------------------------------- 6. rank spread across bootstraps
fig, axs = plt.subplots(1, 3, figsize=(12, 5.2), sharey=False)
for a, m in zip(axs, MODELS):
    G = np.load(os.path.join(RESULTS, f"stab_global_{m}_bootstrap.npy"))
    R = np.vstack([pd.Series(g).rank(ascending=False).to_numpy() for g in G])
    o = np.argsort(R.mean(0))[::-1]
    a.boxplot([R[:, j] for j in o], vert=False, widths=0.6, patch_artist=True,
              boxprops=dict(facecolor=C[m], edgecolor=C[m], alpha=0.35), medianprops=dict(color=INK),
              whiskerprops=dict(color=INK2), capprops=dict(color=INK2), flierprops=dict(markersize=3))
    a.set_yticks(range(1, len(o) + 1), [FEATURES[j] for j in o], fontsize=8.5)
    a.set_xlabel("rank across 20 bootstrap refits (1 = most important)")
    a.set_title(NAMES[m])
    a.set_xlim(0.5, 19.5)
    a.grid(axis="y", visible=False)
fig.suptitle("RQ2: how much does each feature's SHAP rank move under bootstrap resampling of the training set?",
             x=0.02, ha="left", fontsize=10.5)
fig.tight_layout()
save(fig, "06_rank_stability.png")

# ---------------------------------------------------------------- 7. pairwise Spearman distributions
stab = json.load(open(os.path.join(RESULTS, "rq2_stability.json")))
fig, ax = plt.subplots(figsize=(8, 4))
labels, pos = [], 0
import itertools  # noqa: E402
from scipy.stats import spearmanr  # noqa: E402

for m in MODELS:
    for regime in ("seed", "bootstrap"):
        p = os.path.join(RESULTS, f"stab_global_{m}_{regime}.npy")
        if not os.path.exists(p):
            continue
        G = np.load(p)
        rho = [spearmanr(G[i], G[j])[0] for i, j in itertools.combinations(range(len(G)), 2)]
        jitter = np.random.RandomState(0).uniform(-0.18, 0.18, len(rho))
        ax.scatter(pos + jitter, rho, s=9, color=C[m], alpha=0.55 if regime == "bootstrap" else 0.9,
                   marker="o" if regime == "bootstrap" else "^", linewidths=0)
        ax.plot([pos - 0.25, pos + 0.25], [np.median(rho)] * 2, color=INK, lw=2)
        labels.append(f"{m}\n{regime}")
        pos += 1
for a, b in itertools.combinations(MODELS, 2):
    v = stab[f"cross_{a}_vs_{b}"]["spearman_median"]
    ax.axhline(v, color=INK2, lw=0.9, ls=":")
    ax.text(pos - 0.45, v, f"cross-model\n{a} vs {b}\nmedian", fontsize=7.5, color=INK2, va="center", ha="left",
            bbox=dict(facecolor=SURFACE, edgecolor="none", pad=1))
ax.set_xlim(-0.6, pos + 0.5)
ax.set_xticks(range(pos), labels)
ax.set_ylabel("Spearman rho between global rankings")
ax.set_title("RQ2: pairwise rank correlation of global SHAP importance between refits", loc="left")
fig.tight_layout()
save(fig, "07_pairwise_spearman.png")

# ---------------------------------------------------------------- 8. method agreement heatmap
sp = pd.read_csv(os.path.join(RESULTS, "method_agreement_spearman.csv"), index_col=0)
fig, ax = plt.subplots(figsize=(7.2, 6))
from matplotlib.colors import LinearSegmentedColormap  # noqa: E402

cmap = LinearSegmentedColormap.from_list("seq", ["#f0efec"] + SEQ)
im = ax.imshow(sp.values, cmap=cmap, vmin=0, vmax=1)
ax.set_xticks(range(len(sp)), sp.columns, rotation=45, ha="right")
ax.set_yticks(range(len(sp)), sp.index)
for i in range(len(sp)):
    for j in range(len(sp)):
        v = sp.values[i, j]
        ax.text(j, i, f"{v:.2f}", ha="center", va="center", fontsize=7.5, color="white" if v > 0.7 else INK)
ax.grid(False)
fig.colorbar(im, ax=ax, shrink=0.8, label="Spearman rho (19 features)")
ax.set_title("RQ1/RQ3: rank agreement between models and attribution methods", loc="left")
fig.tight_layout()
save(fig, "08_method_agreement.png")

# ---------------------------------------------------------------- 9. ROAR sanity check
roar = load("sanity_roar.csv")
mcp = load("model_comparison.csv").set_index("model")
SC = {"top_shap": "#2a78d6", "top_perm": "#eb6834", "bottom_shap": "#1baf7a"}
SL = {"top_shap": "remove top-k by SHAP", "top_perm": "remove top-k by permutation", "bottom_shap": "remove bottom-k by SHAP"}
fig, axs = plt.subplots(1, 3, figsize=(12, 3.8), sharey=True)
for a, m in zip(axs, MODELS):
    g = roar[roar.model == m]
    rnd = g[g.strategy == "random"].groupby("k")["test_auc"]
    a.fill_between(rnd.min().index, rnd.min(), rnd.max(), color=GRID, alpha=0.9, label="random k (min-max of 10)")
    a.plot(rnd.mean().index, rnd.mean(), color=INK2, lw=1.2, ls="--", label="random k (mean)")
    for s in ("top_shap", "top_perm", "bottom_shap"):
        h = g[g.strategy == s].sort_values("k")
        a.plot([0] + h["k"].tolist(), [mcp.loc[m, "roc_auc"]] + h["test_auc"].tolist(), color=SC[s], marker="o",
               ms=4, label=SL[s])
    a.set(title=NAMES[m], xlabel="features removed and model retrained (k)")
axs[0].set_ylabel("test ROC-AUC")
axs[0].legend(fontsize=7.5, loc="lower left")
fig.suptitle("Sanity check: does removing the features SHAP ranks highest hurt the retrained model most?",
             x=0.02, ha="left", fontsize=10.5)
fig.tight_layout()
save(fig, "09_roar.png")

# ---------------------------------------------------------------- 10. correlated features
red = load("rq4_drop_totalcharges.csv")
dup = load("rq4_duplicate_feature.csv")
fig, axs = plt.subplots(1, 2, figsize=(11, 4))
a = axs[0]
feats = ["tenure", "MonthlyCharges", "TotalCharges"]
w = 0.13
for i, m in enumerate(MODELS):
    g = red[(red.model == m)].set_index("feature")
    scale = g.loc[feats + ["Contract"], "with_TotalCharges"].max()
    xs = np.arange(len(feats)) + (i - 1) * 2.3 * w
    a.bar(xs - w / 2, g.loc[feats, "with_TotalCharges"] / scale, w, color=C[m], label=f"{m}: with TotalCharges")
    a.bar(xs + w / 2, g.loc[feats, "without_TotalCharges"] / scale, w, color=C[m], alpha=0.4,
          hatch="///", edgecolor=C[m], label=f"{m}: TotalCharges removed")
a.set_xticks(range(len(feats)), feats)
a.set_ylabel("mean |SHAP| (scaled per model)")
a.set_title("RQ4a: SHAP credit when TotalCharges is removed", loc="left")
a.legend(fontsize=7, ncol=3, loc="upper center", bbox_to_anchor=(0.5, -0.12))
a.grid(axis="x", visible=False)
b = axs[1]
x = np.arange(len(MODELS))
b.bar(x - 0.18, dup["tenure_original_model"], 0.34, color=[C[m] for m in MODELS], label="tenure (original model)")
b.bar(x + 0.18, dup["tenure_with_copy"], 0.34, color=[C[m] for m in MODELS], alpha=0.45, label="tenure (with copy)")
b.bar(x + 0.18, dup["tenure_copy"], 0.34, bottom=dup["tenure_with_copy"], color="none", edgecolor=INK2,
      hatch="///", label="tenure_copy (stacked)")
b.set_xticks(x, [NAMES[m] for m in MODELS])
b.set_ylabel("mean |SHAP| (model units)")
b.set_title("RQ4b: adding a near-duplicate of tenure splits its credit", loc="left")
b.legend(fontsize=7.5)
b.grid(axis="x", visible=False)
fig.tight_layout()
save(fig, "10_correlated_features.png")

# ---------------------------------------------------------------- 11. local stability
fig, ax = plt.subplots(figsize=(7.5, 3.6))
loc = np.load(os.path.join(RESULTS, "stability_local.npz"))
for m in MODELS:
    L = np.abs(loc[f"{m}_bootstrap"])
    B, n, _ = L.shape
    vals = []
    for i in range(n):
        R = np.vstack([pd.Series(L[b, i]).rank().to_numpy() for b in range(B)])
        Cm = np.corrcoef(R)
        vals.append(Cm[np.triu_indices(B, 1)].mean())
    ax.hist(vals, bins=np.linspace(0, 1, 41), histtype="step", lw=2, color=C[m], label=NAMES[m])
ax.set(xlabel="per-customer mean pairwise Spearman of |SHAP| across 20 bootstrap refits",
       ylabel="customers", title="RQ2: local (per-customer) explanation stability")
ax.legend(fontsize=8, loc="upper left")
fig.tight_layout()
save(fig, "11_local_stability.png")
print("figures written")
