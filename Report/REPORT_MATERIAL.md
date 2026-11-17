# Material for the written report (facts you can cite)

All numbers come from `Implementation/results/experiment_results.md` (seed 42, 6000 synthetic findings; train 3746 / val 958 / test 1296).
Figures are in `Report/figures/`. **Say clearly in the report that the data is synthetic.**

## Research questions - what was found
**RQ1 (does the stronger method beat the strongest simple baseline?)** Only partly. GBDT (PR-AUC 0.400, ROC-AUC 0.843) is far better than CVSS (PR-AUC 0.142; paired-bootstrap difference +0.257, CI [+0.161, +0.351]).
Against Logistic Regression (0.390) and the rule-based score (0.372) the difference is **not statistically significant** (CIs include 0). Interpretable models are therefore a defensible choice on this data.
**Probability vs impact:** ranking by P x impact beats ranking by probability alone on NDCG@50 (+0.079, CI [+0.006, +0.164]); precision of picking exploited findings is not hurt much.

**RQ2 (robustness under shift)** Per-year test results: GBDT ROC-AUC 0.820 (2024) and 0.878 (2025); the ordering of methods is the same in both years. Re-sampling test prevalence to 2/5/10/20% lowers PR-AUC at low prevalence for every model (PR-AUC depends on prevalence), but the ranking of methods stays CVSS << rule < LR ~ GBDT.
Calibration: LR and GBDT are reasonably calibrated (ECE 0.021 / 0.017; Brier 0.057); the rule-based score is clearly miscalibrated (see `chart_calibration.png`) - it is a score, not a probability.

**RQ3 (what matters)** Removing EPSS costs the most (PR-AUC -0.136), then KEV (-0.080). Removing CVSS changes nothing (+0.001) and removing exploit-code is slightly positive (+0.019) - they are redundant given EPSS/KEV in this data. Mean |SHAP| ranks epss > vuln_age > internet_facing.

**Explanation stability** (inputs perturbed by 5% of feature std, 5 repeats x 150 findings): top-3 feature overlap 0.959 (LR) vs 0.937 (GBDT); Spearman of attribution vectors 0.995 vs 0.953. Tree attributions are slightly less stable because of hard split thresholds.

## Honest limitations to write
* Synthetic data; label generation is close to logistic, favouring LR. Real-data validation is future work (loader exists, see datasheet).
* Test set has about 97 exploited findings, so differences of a few points are noise (hence the bootstrap).
* `vuln_age_years` partly proxies the injected temporal drift.
* GBDT is a from-scratch implementation (not the XGBoost library); the SHAP is exact path-dependent TreeSHAP (verified by additivity test).
* Analyst usefulness study was not run with humans; the GUI + database provide the rating mechanism for it.
* The JDBC class was validated at SQL level against SQLite but run end-to-end only with the CSV repository in the build environment; run it on your machine with the jar and screenshot the DB mode.

## Future enhancements
Real NVD/KEV/EPSS data at scale; real asset inventory; calibration (Platt/isotonic); monotonic constraints; counterfactual explanations; a human study with SOC analysts; REST API.

## Testing section (section 11)
`SelfTest`: 25 checks - metric values vs hand calculation, ROC ties, NDCG perfect ranking, deterministic generator, no CVE overlap and no time overlap between train and test, SHAP additivity (max error 3.6e-15), zero attribution for removed features, repository insert/update/delete round trip, invalid rating rejected, loader label/leakage rules.
