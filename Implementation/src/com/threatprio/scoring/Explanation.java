package com.threatprio.scoring;

import com.threatprio.model.Finding;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * Additive feature attribution in log-odds space:
 * margin = baseValue + sum(contributions).  probability = sigmoid(margin).
 */
public record Explanation(double[] x, double baseValue, double[] contributions, double margin, double probability) {

    public record FeatureContribution(String feature, double value, double contribution) {}

    public List<FeatureContribution> ranked() {
        List<FeatureContribution> out = new ArrayList<>();
        for (int i = 0; i < contributions.length; i++)
            out.add(new FeatureContribution(Finding.FEATURE_NAMES[i], x[i], contributions[i]));
        out.sort(Comparator.comparingDouble((FeatureContribution c) -> Math.abs(c.contribution())).reversed());
        return out;
    }

    public List<FeatureContribution> top(int k) { return ranked().subList(0, Math.min(k, contributions.length)); }

    /** Plain-language summary for the analyst. */
    public String toText(int k) {
        StringBuilder sb = new StringBuilder(String.format("Predicted exploitation probability: %.1f%%%n", probability * 100));
        sb.append(String.format("Baseline score (average log-odds of training data): %.1f%%%n", 100.0 / (1.0 + Math.exp(-baseValue))));
        sb.append("Main drivers:\n");
        for (FeatureContribution c : top(k))
            sb.append(String.format("  %s %-20s = %-7.3f  %+.3f log-odds%n",
                c.contribution() >= 0 ? "^" : "v", c.feature(), c.value(), c.contribution()));
        return sb.toString();
    }
}
