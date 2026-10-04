"""Summaries and figures for the PCR-bounds extension."""
from __future__ import annotations

import json
import os
import sys

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
import warnings  # noqa: E402

warnings.filterwarnings("ignore")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RES, FIG = os.path.join(ROOT, "results"), os.path.join(ROOT, "figures")
os.makedirs(FIG, exist_ok=True)

SURFACE, INK, INK2, GRID = "#fcfcfb", "#0b0b0b", "#52514e", "#e4e3df"
# Fixed categorical slot order from the reference palette; PCR always gets slot 1.
C = {"PCR": "#2a78d6", "Ridge": "#eb6834", "GD": "#1baf7a", "GradFlow": "#eda100",
     "IterRidge2": "#e87ba4", "RidgePCR": "#4a3aa7", "OLS": "#52514e"}
OTHERS = ["Ridge", "GD", "GradFlow", "IterRidge2", "RidgePCR"]
DS = ["superconductivity", "communities", "yearmsd", "mnist", "telco_churn"]
SIG = ["real", "head", "powerlaw", "isotropic", "tail"]
plt.rcParams.update({
    "figure.facecolor": SURFACE, "axes.facecolor": SURFACE, "savefig.facecolor": SURFACE,
    "axes.edgecolor": GRID, "axes.labelcolor": INK2, "xtick.color": INK2, "ytick.color": INK2,
    "text.color": INK, "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.6,
    "axes.spines.top": False, "axes.spines.right": False, "font.size": 9,
    "axes.titlesize": 10, "axes.titleweight": "bold", "legend.frameon": False, "lines.linewidth": 2})


def save(fig, name):
    fig.savefig(os.path.join(FIG, name), dpi=150, bbox_inches="tight")
    plt.close(fig)


orc = pd.read_csv(os.path.join(RES, "oracle_risks.csv.gz"))
cv = pd.read_csv(os.path.join(RES, "cv_risks.csv.gz"))
bt = pd.read_csv(os.path.join(RES, "bound_tracking.csv.gz"))
summary = {}

# ------------------------------------------------------------------ E1: dominance ratios
wide = orc.pivot_table(index=["dataset", "signal", "n", "draw"], columns="family", values="risk").reset_index()
for g in OTHERS + ["OLS"]:
    wide[f"ratio_{g}"] = wide["PCR"] / wide[g]                     # Thm 2.1: bounded above by c0
wide["pcr_is_best"] = wide["PCR"] <= wide[OTHERS].min(1) * (1 + 1e-9)
wide["ratio_best_other"] = wide["PCR"] / wide[OTHERS].min(1)
wide.to_csv(os.path.join(RES, "dominance_per_draw.csv.gz"), index=False)

syn = wide[wide.signal != "real_labels"]
real = wide[wide.signal == "real_labels"]
# Expected-risk version (mean over draws), closest to the theorem's E[.] on the right-hand side.
mean_risk = orc.groupby(["dataset", "signal", "n", "family"])["risk"].mean().unstack("family").reset_index()
for g in OTHERS:
    mean_risk[f"ratio_{g}"] = mean_risk["PCR"] / mean_risk[g]
mean_risk.to_csv(os.path.join(RES, "dominance_mean_risk.csv"), index=False)

tab = []
for (ds, sig), grp in mean_risk.groupby(["dataset", "signal"]):
    row = {"dataset": ds, "signal": sig}
    for g in OTHERS:
        row[f"max_ratio_{g}"] = grp[f"ratio_{g}"].max()
    row["max_ratio_any"] = max(row[f"max_ratio_{g}"] for g in OTHERS)
    row["min_ratio_best_other"] = (grp["PCR"] / grp[OTHERS].min(1)).min()
    tab.append(row)
tab = pd.DataFrame(tab)
tab.to_csv(os.path.join(RES, "dominance_table.csv"), index=False)
summary["empirical_c0_mean_risk_wellspec"] = float(tab[tab.signal != "real_labels"]["max_ratio_any"].max())
summary["empirical_c0_mean_risk_real_labels"] = float(tab[tab.signal == "real_labels"]["max_ratio_any"].max())
summary["empirical_c0_per_draw_wellspec_max"] = float(syn[[f"ratio_{g}" for g in OTHERS]].max().max())
summary["empirical_c0_per_draw_wellspec_q99"] = float(np.nanpercentile(syn[[f"ratio_{g}" for g in OTHERS]].to_numpy(), 99))
summary["frac_draws_pcr_best_wellspec"] = float(syn["pcr_is_best"].mean())
summary["frac_draws_pcr_best_real_labels"] = float(real["pcr_is_best"].mean())
summary["median_ratio_best_other_wellspec"] = float(syn["ratio_best_other"].median())
summary["median_ratio_best_other_real_labels"] = float(real["ratio_best_other"].median())
summary["median_ratio_vs_ridge_by_signal"] = syn.groupby("signal")["ratio_Ridge"].median().round(4).to_dict()
summary["median_ratio_vs_GD_by_signal"] = syn.groupby("signal")["ratio_GD"].median().round(4).to_dict()
summary["pcr_beats_ridge_frac_by_signal"] = (syn.assign(b=syn.ratio_Ridge < 1).groupby("signal")["b"].mean().round(3).to_dict())
summary["gd_diverged_draw_frac_by_dataset"] = (orc[orc.family == "GD"].assign(b=orc.eta_lhmax > 1)
                                               .groupby("dataset")["b"].mean().round(4).to_dict())

# Growth of the PCR advantage with n: slope of log(mean risk) vs log n.
slopes = []
for (ds, sig), grp in mean_risk.groupby(["dataset", "signal"]):
    if grp["n"].nunique() < 3:
        continue
    ln = np.log(grp["n"].to_numpy())
    row = {"dataset": ds, "signal": sig}
    for f in ["PCR"] + OTHERS:
        row[f"slope_{f}"] = float(np.polyfit(ln, np.log(grp[f].to_numpy()), 1)[0])
    row["slope_gap_best_other_minus_pcr"] = min(row[f"slope_{g}"] for g in OTHERS) - row["slope_PCR"]
    slopes.append(row)
pd.DataFrame(slopes).to_csv(os.path.join(RES, "risk_slopes.csv"), index=False)

# ------------------------------------------------------------------ real labels: oracle vs CV
cvw = cv.pivot_table(index=["dataset", "n", "draw"], columns="family", values="cv_risk").reset_index()
orw = real.set_index(["dataset", "n", "draw"])
cvt = []
for (ds, n), grp in cvw.groupby(["dataset", "n"]):
    o = orw.loc[(ds, n)]
    row = {"dataset": ds, "n": n}
    for f in ["PCR"] + OTHERS:
        row[f"cv_{f}"] = grp[f].mean()
        row[f"oracle_{f}"] = o[f].mean()
    row["cv_best_family"] = min(["PCR"] + OTHERS, key=lambda f: row[f"cv_{f}"])
    row["cv_ratio_PCR_over_Ridge"] = row["cv_PCR"] / row["cv_Ridge"]
    row["cv_ratio_PCR_over_best"] = row["cv_PCR"] / min(row[f"cv_{f}"] for f in OTHERS)
    cvt.append(row)
cvt = pd.DataFrame(cvt)
cvt.to_csv(os.path.join(RES, "real_labels_oracle_vs_cv.csv"), index=False)
summary["cv_ratio_PCR_over_best_other_median"] = float(cvt["cv_ratio_PCR_over_best"].median())
summary["cv_ratio_PCR_over_best_other_max"] = float(cvt["cv_ratio_PCR_over_best"].max())
summary["cv_best_family_counts"] = cvt["cv_best_family"].value_counts().to_dict()

# ------------------------------------------------------------------ E2: bound tracking
bt = bt[np.isfinite(bt["risk"]) & (bt["risk"] > 0)]
agg = bt.groupby(["dataset", "signal", "n", "method", "hp"]).agg(
    risk=("risk", "median"), upper=("upper", "first"), lower=("lower", "first"),
    valid=("valid_upper", "first"), kstar=("kstar", "first")).reset_index()
agg = agg[agg["valid"]]
agg["log10_risk_over_upper"] = np.log10(agg["risk"] / agg["upper"])
agg["log10_risk_over_lower"] = np.log10(agg["risk"] / agg["lower"].where(agg["lower"] > 0))
agg.to_csv(os.path.join(RES, "bound_tracking_summary.csv.gz"), index=False)
bsum = {}
for m in ["PCR", "GD"]:
    a = agg[agg.method == m]
    u = a["log10_risk_over_upper"].dropna()
    lo = a["log10_risk_over_lower"].replace([np.inf, -np.inf], np.nan).dropna()
    bsum[m] = {"n_configs": int(len(a)),
               "risk_over_upper_log10_q05_q50_q95_max": [float(u.quantile(q)) for q in (0.05, 0.5, 0.95)] + [float(u.max())],
               "risk_over_upper_band_width_decades_q05_q95": float(u.quantile(0.95) - u.quantile(0.05)),
               "risk_over_lower_log10_q05_q50_q95_min": [float(lo.quantile(q)) for q in (0.05, 0.5, 0.95)] + [float(lo.min())],
               "by_dataset_upper_q05_q95": {ds: [float(g["log10_risk_over_upper"].quantile(0.05)),
                                                 float(g["log10_risk_over_upper"].quantile(0.95))]
                                            for ds, g in a.groupby("dataset")}}
# The theorems require k* <= n / c3 for a large constant c3; c3 = 1 above admits the
# interpolation peak (k* ~ n). Re-run the tracking summary under c3 = 4.
for m in ["PCR", "GD"]:
    a = agg[(agg.method == m) & (agg.kstar <= agg.n / 4)]
    u = a["log10_risk_over_upper"].dropna()
    bsum[m]["c3_4"] = {"n_configs": int(len(a)),
                       "risk_over_upper_log10_q05_q50_q95_max": [float(u.quantile(q)) for q in (0.05, 0.5, 0.95)] + [float(u.max())],
                       "band_width_decades_q05_q95": float(u.quantile(0.95) - u.quantile(0.05)),
                       "frac_risk_more_than_3x_shape": float((u > np.log10(3)).mean())}
    full = agg[agg.method == m]
    bsum[m]["frac_risk_more_than_3x_shape_c3_1"] = float((full["log10_risk_over_upper"] > np.log10(3)).mean())
summary["bound_tracking"] = bsum
# Largest PCR advantage over each specific filter (mean risk), where the theorem's separation would show.
summary["min_mean_ratio_PCR_over_filter"] = {g: float(mean_risk[f"ratio_{g}"].min()) for g in OTHERS}
summary["min_mean_ratio_PCR_over_filter_where"] = {
    g: mean_risk.loc[mean_risk[f"ratio_{g}"].idxmin(), ["dataset", "signal", "n"]].astype(str).to_dict() for g in OTHERS}
json.dump(summary, open(os.path.join(RES, "summary.json"), "w"), indent=2, default=float)
print(json.dumps(summary, indent=2, default=float))

# ------------------------------------------------------------------ figures
# F1: separation instance (positive control)
sep = pd.read_csv(os.path.join(RES, "separation_instance.csv"))
med = sep.groupby(["family", "n"])["risk"].median().unstack("n")
fig, ax = plt.subplots(figsize=(6.4, 4.2))
for f in ["PCR"] + OTHERS:
    ax.plot(med.columns, med.loc[f], color=C[f], marker="o", ms=4, label=f)
ns = np.array(med.columns, float)
ax.plot(ns, med.loc["PCR"].iloc[0] * (ns / ns[0]) ** -1, color=INK2, ls=":", lw=1, label="slope −1")
ax.plot(ns, med.loc["Ridge"].iloc[0] * (ns / ns[0]) ** -0.5, color=INK2, ls="--", lw=1, label="slope −1/2")
ax.set(xscale="log", yscale="log", xlabel="sample size n", ylabel="oracle-tuned conditional excess risk",
       title="Theorem 2.2 instance: PCR ~ 1/n, every non-step filter ~ 1/√n")
ax.legend(fontsize=7.5, ncol=2)
save(fig, "p1_separation_instance.png")

# F2: PCR/other ratio vs n, per dataset (well-specified, real-signal and powerlaw)
fig, axs = plt.subplots(2, 5, figsize=(15, 6), sharey=True)
DSC = dict(zip(DS, ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4"]))
DSM = dict(zip(DS, ["o", "s", "^", "D", "v"]))
for row, sig in enumerate(["real", "isotropic"]):
    for col, ds in enumerate(DS):
        a = axs[row, col]
        g = mean_risk[(mean_risk.dataset == ds) & (mean_risk.signal == sig)]
        if g.empty:
            a.set_visible(False)
            continue
        for f in OTHERS:
            a.plot(g["n"], g[f"ratio_{f}"], color=C[f], marker="o", ms=3, label=f"PCR / {f}")
        a.axhline(1, color=INK2, lw=1)
        a.set(xscale="log", title=f"{ds} · {sig} signal")
        if col == 0:
            a.set_ylabel("mean risk ratio PCR / filter\n(<1: PCR better)")
        if row == 1:
            a.set_xlabel("n")
axs[0, 0].legend(fontsize=7)
fig.suptitle("Dominance on real designs: Theorem 2.1 says PCR / filter ≤ c₀ for every instance", x=0.01, ha="left")
fig.tight_layout()
save(fig, "p2_dominance_ratios.png")

# F3: per-draw ratio distribution by signal (well-specified)
fig, ax = plt.subplots(figsize=(9, 4))
pos = 0
ticks = []
for sig in SIG:
    for f in ["Ridge", "GD"]:
        v = np.log10(syn[syn.signal == sig][f"ratio_{f}"].dropna())
        ax.boxplot([v], positions=[pos], widths=0.6, patch_artist=True, showfliers=True,
                   boxprops=dict(facecolor=C[f], alpha=0.45, edgecolor=C[f]), medianprops=dict(color=INK),
                   flierprops=dict(markersize=2, alpha=0.4))
        ticks.append((pos, f"{sig}\nvs {f}"))
        pos += 1
    pos += 0.6
ax.axhline(0, color=INK2, lw=1)
ax.set_xticks([p for p, _ in ticks], [t for _, t in ticks], fontsize=7.5)
ax.set_ylabel("log10( PCR risk / filter risk ), per draw")
ax.set_title("All datasets and n pooled: PCR is never far worse, sometimes much better", loc="left")
save(fig, "p3_ratio_by_signal.png")

# F4: bound tracking
fig, axs = plt.subplots(1, 2, figsize=(12, 4.4))
for a, m in zip(axs, ["PCR", "GD"]):
    g = agg[agg.method == m]
    out_ = g[g.kstar > g.n / 4]
    a.scatter(out_["upper"], out_["risk"], s=5, color="#b8b7b0", alpha=0.5, label="k* > n/4 (outside theorem regime)")
    for ds in DS:
        h = g[(g.dataset == ds) & (g.kstar <= g.n / 4)]
        a.scatter(h["upper"], h["risk"], s=7, alpha=0.55, color=DSC[ds], marker=DSM[ds], linewidths=0, label=ds)
    lim = [max(1e-6, g[["upper", "risk"]].min().min()), g[["upper", "risk"]].max().max()]
    a.plot(lim, lim, color=INK2, lw=1)
    a.plot(lim, np.array(lim) / 10, color=INK2, lw=1, ls=":")
    a.set(xscale="log", yscale="log", xlabel="bound shape (all constants = 1)", ylabel="actual risk (median over draws)",
          title=f"{m}: {'Theorem 4.1 upper bound' if m == 'PCR' else 'Corollary 3.1 (two-sided)'}")
axs[0].legend(fontsize=7, markerscale=2)
fig.suptitle("Do the bounds track the true risk on real designs? Points on a line parallel to y = x mean tight up to a constant",
             x=0.01, ha="left")
fig.tight_layout()
save(fig, "p4_bound_tracking.png")

# F5: churn explanation stability
cs = json.load(open(os.path.join(RES, "churn_stability.json")))
order = ["parent_logistic_regression", "OLS", "Ridge", "GD", "PCR", "PCR_k20", "PCR_k22"]
labels = ["Logistic\n(parent)", "OLS", "Ridge\n(CV)", "GD\n(CV)", "PCR\n(CV k)", "PCR\nk=20", "PCR\nk=22"]
fig, ax = plt.subplots(figsize=(8, 3.8))
med_ = [cs[k]["global_spearman_median"] for k in order]
min_ = [cs[k]["global_spearman_min"] for k in order]
x = np.arange(len(order))
ax.bar(x - 0.18, med_, 0.34, color="#2a78d6", label="median pairwise ρ")
ax.bar(x + 0.18, min_, 0.34, color="#eb6834", label="worst pair ρ")
for i, (m1, m0) in enumerate(zip(med_, min_)):
    ax.text(i - 0.18, m1 + 0.01, f"{m1:.2f}", ha="center", fontsize=7.5, color=INK2)
    ax.text(i + 0.18, m0 + 0.01, f"{m0:.2f}", ha="center", fontsize=7.5, color=INK2)
ax.set_xticks(x, labels)
ax.set_ylim(0, 1.05)
ax.set_ylabel("Spearman ρ of global attribution\nacross 20 bootstrap refits")
ax.set_title("Churn: weak-direction removal stabilises explanations only when k is fixed", loc="left")
ax.legend(fontsize=8, loc="lower left")
ax.grid(axis="x", visible=False)
save(fig, "p5_churn_stability.png")
print("figures written")
