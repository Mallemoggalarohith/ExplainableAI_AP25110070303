# Experiment results

Seed: 42 | runtime: 4.8s

Split: train=3746 (4.7% exploited), validation=958 (6.9%), test=1296 (7.5%)

## Main comparison (held-out test set)

| Model | ROC-AUC | PR-AUC | Brier | ECE | P@50 | P@100 | NDCG@50 | NDCG@100 |
|---|---|---|---|---|---|---|---|---|
| CVSS baseline | 0.686 | 0.142 | n/a | n/a | 0.16 | 0.15 | 0.124 | 0.141 |
| Rule-based weighted | 0.831 | 0.372 | n/a | n/a | 0.44 | 0.31 | 0.517 | 0.471 |
| Logistic Regression | 0.834 | 0.390 | 0.0570 | 0.0207 | 0.48 | 0.40 | 0.528 | 0.519 |
| XGBoost-style GBDT + SHAP | 0.843 | 0.400 | 0.0567 | 0.0167 | 0.50 | 0.38 | 0.541 | 0.506 |
| XGBoost-style GBDT + SHAP (probability only) | 0.843 | 0.400 | 0.0567 | 0.0167 | 0.52 | 0.41 | 0.465 | 0.478 |

## Temporal shift: performance by publication year of test CVEs

| Model | Year | n | Prevalence | ROC-AUC | PR-AUC |
|---|---|---|---|---|---|
| CVSS baseline | 2024 | 865 | 0.065 | 0.694 | 0.128 |
| CVSS baseline | 2025 | 431 | 0.095 | 0.682 | 0.185 |
| Rule-based weighted | 2024 | 865 | 0.065 | 0.806 | 0.318 |
| Rule-based weighted | 2025 | 431 | 0.095 | 0.866 | 0.477 |
| Logistic Regression | 2024 | 865 | 0.065 | 0.809 | 0.331 |
| Logistic Regression | 2025 | 431 | 0.095 | 0.870 | 0.493 |
| XGBoost-style GBDT + SHAP | 2024 | 865 | 0.065 | 0.820 | 0.330 |
| XGBoost-style GBDT + SHAP | 2025 | 431 | 0.095 | 0.878 | 0.551 |

## Class-distribution shift: PR-AUC when test prevalence is re-sampled

| Model | Target prevalence | PR-AUC |
|---|---|---|
| CVSS baseline | 0.02 | 0.053 |
| Rule-based weighted | 0.02 | 0.213 |
| Logistic Regression | 0.02 | 0.300 |
| XGBoost-style GBDT + SHAP | 0.02 | 0.283 |
| CVSS baseline | 0.05 | 0.092 |
| Rule-based weighted | 0.05 | 0.341 |
| Logistic Regression | 0.05 | 0.354 |
| XGBoost-style GBDT + SHAP | 0.05 | 0.354 |
| CVSS baseline | 0.10 | 0.186 |
| Rule-based weighted | 0.10 | 0.449 |
| Logistic Regression | 0.10 | 0.472 |
| XGBoost-style GBDT + SHAP | 0.10 | 0.469 |
| CVSS baseline | 0.20 | 0.313 |
| Rule-based weighted | 0.20 | 0.603 |
| Logistic Regression | 0.20 | 0.621 |
| XGBoost-style GBDT + SHAP | 0.20 | 0.615 |

## Feature-group ablation (GBDT retrained without a group)

| Removed group | ROC-AUC | PR-AUC | Delta PR-AUC vs full |
|---|---|---|---|
| CVSS | 0.834 | 0.401 | +0.001 |
| EPSS | 0.787 | 0.263 | -0.136 |
| KEV | 0.825 | 0.320 | -0.080 |
| Exploit code | 0.842 | 0.419 | +0.019 |
| Intel confidence | 0.847 | 0.387 | -0.012 |
| Exposure/patch/age | 0.826 | 0.384 | -0.016 |

## Global feature importance

| Feature | GBDT mean abs SHAP (log-odds) | LR abs std. coefficient |
|---|---|---|
| epss | 1.037 | 0.574 |
| vuln_age_years | 0.485 | 0.169 |
| internet_facing | 0.297 | 0.407 |
| attack_vector | 0.148 | 0.285 |
| in_kev | 0.138 | 0.378 |
| cvss_base | 0.115 | 0.178 |
| exploit_code_public | 0.067 | 0.406 |
| intel_confidence | 0.056 | 0.029 |
| patch_available | 0.032 | 0.061 |

## Explanation stability (inputs perturbed by sigma x feature std)

| Model | sigma | Top-3 Jaccard | Spearman of attributions |
|---|---|---|---|
| Logistic Regression | 0.05 | 0.959 | 0.995 |
| XGBoost-style GBDT + SHAP | 0.05 | 0.937 | 0.953 |

## RQ1: paired bootstrap (1000 resamples of the test set), 95% interval of the difference

| Comparison | Metric | Mean diff | 95% CI | Significant |
|---|---|---|---|---|
| GBDT - Logistic Regression | PR-AUC | +0.009 | [-0.027, +0.048] | no |
| GBDT - Rule-based | PR-AUC | +0.028 | [-0.019, +0.076] | no |
| GBDT - CVSS baseline | PR-AUC | +0.257 | [+0.161, +0.351] | yes |
| GBDT risk (p x impact) - GBDT probability-only | NDCG@50 | +0.079 | [+0.006, +0.164] | yes |
