package com.threatprio.eval;

import com.threatprio.model.Finding;
import java.util.List;
import java.util.Map;

/** Immutable bundle of everything the experiment produces (used by GUI, CLI and report writer). */
public record ExperimentResult(
        String splitDescription,
        List<ModelMetrics> metrics,
        Map<String, double[][]> rocCurves,
        Map<String, double[][]> prCurves,
        Map<String, List<Metrics.CalibrationBin>> calibration,
        List<YearMetrics> byYear,
        List<PrevalenceRow> prevalenceShift,
        List<AblationRow> ablation,
        List<ImportanceRow> importance,
        List<StabilityRow> stability,
        List<BootstrapRow> bootstrap,
        long seed, double elapsedSeconds) {

    public record ModelMetrics(String model, boolean probabilistic, double rocAuc, double prAuc, double brier, double ece,
                               double p50, double p100, double ndcg50, double ndcg100) {}
    public record YearMetrics(String model, int year, int n, double prevalence, double rocAuc, double prAuc) {}
    public record PrevalenceRow(String model, double prevalence, double prAuc) {}
    public record AblationRow(String removed, double rocAuc, double prAuc, double deltaPrAuc) {}
    public record ImportanceRow(String feature, double gbmMeanAbsShap, double lrAbsCoef) {}
    public record BootstrapRow(String comparison, String metric, double meanDiff, double lo, double hi) {
        public boolean significant() { return lo > 0 || hi < 0; }
    }
    public record StabilityRow(String model, double sigma, double top3Jaccard, double spearman) {}

    public String toMarkdown() {
        StringBuilder sb = new StringBuilder("# Experiment results\n\n");
        sb.append("Seed: ").append(seed).append(" | runtime: ").append(String.format("%.1fs", elapsedSeconds)).append("\n\n");
        sb.append("Split: ").append(splitDescription).append("\n\n## Main comparison (held-out test set)\n\n");
        sb.append("| Model | ROC-AUC | PR-AUC | Brier | ECE | P@50 | P@100 | NDCG@50 | NDCG@100 |\n|---|---|---|---|---|---|---|---|---|\n");
        for (ModelMetrics m : metrics)
            sb.append(String.format("| %s | %.3f | %.3f | %s | %s | %.2f | %.2f | %.3f | %.3f |%n", m.model(), m.rocAuc(), m.prAuc(),
                m.probabilistic() ? String.format("%.4f", m.brier()) : "n/a", m.probabilistic() ? String.format("%.4f", m.ece()) : "n/a",
                m.p50(), m.p100(), m.ndcg50(), m.ndcg100()));
        sb.append("\n## Temporal shift: performance by publication year of test CVEs\n\n| Model | Year | n | Prevalence | ROC-AUC | PR-AUC |\n|---|---|---|---|---|---|\n");
        for (YearMetrics y : byYear)
            sb.append(String.format("| %s | %d | %d | %.3f | %.3f | %.3f |%n", y.model(), y.year(), y.n(), y.prevalence(), y.rocAuc(), y.prAuc()));
        sb.append("\n## Class-distribution shift: PR-AUC when test prevalence is re-sampled\n\n| Model | Target prevalence | PR-AUC |\n|---|---|---|\n");
        for (PrevalenceRow r : prevalenceShift) sb.append(String.format("| %s | %.2f | %.3f |%n", r.model(), r.prevalence(), r.prAuc()));
        sb.append("\n## Feature-group ablation (GBDT retrained without a group)\n\n| Removed group | ROC-AUC | PR-AUC | Delta PR-AUC vs full |\n|---|---|---|---|\n");
        for (AblationRow a : ablation) sb.append(String.format("| %s | %.3f | %.3f | %+.3f |%n", a.removed(), a.rocAuc(), a.prAuc(), a.deltaPrAuc()));
        sb.append("\n## Global feature importance\n\n| Feature | GBDT mean abs SHAP (log-odds) | LR abs std. coefficient |\n|---|---|---|\n");
        for (ImportanceRow r : importance) sb.append(String.format("| %s | %.3f | %.3f |%n", r.feature(), r.gbmMeanAbsShap(), r.lrAbsCoef()));
        sb.append("\n## Explanation stability (inputs perturbed by sigma x feature std)\n\n| Model | sigma | Top-3 Jaccard | Spearman of attributions |\n|---|---|---|---|\n");
        for (StabilityRow s : stability) sb.append(String.format("| %s | %.2f | %.3f | %.3f |%n", s.model(), s.sigma(), s.top3Jaccard(), s.spearman()));
        sb.append("\n## RQ1: paired bootstrap (1000 resamples of the test set), 95% interval of the difference\n\n| Comparison | Metric | Mean diff | 95% CI | Significant |\n|---|---|---|---|---|\n");
        for (BootstrapRow b : bootstrap) sb.append(String.format("| %s | %s | %+.3f | [%+.3f, %+.3f] | %s |%n", b.comparison(), b.metric(), b.meanDiff(), b.lo(), b.hi(), b.significant() ? "yes" : "no"));
        return sb.toString();
    }

    public static String featureName(int i) { return Finding.FEATURE_NAMES[i]; }
}
