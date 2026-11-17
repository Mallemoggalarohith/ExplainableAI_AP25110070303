package com.threatprio.scoring;

/** Baseline 2: analyst-defined weighted score over threat signals; risk = score x asset impact. */
public class RuleBasedScorer implements Scorer {
    // weights sum to 1.0
    private static final double W_CVSS = 0.25, W_KEV = 0.30, W_EPSS = 0.20,
                                W_EXPLOIT = 0.10, W_EXPOSURE = 0.10, W_VECTOR = 0.05;

    @Override public String name() { return "Rule-based weighted"; }

    @Override public double probability(double[] x) {
        double epssScaled = Math.min(1.0, x[2] / 0.5);   // EPSS above 0.5 is treated as "maximal"
        return W_CVSS * x[0] / 10.0 + W_KEV * x[3] + W_EPSS * epssScaled
             + W_EXPLOIT * x[4] + W_EXPOSURE * x[8] + W_VECTOR * x[1];
    }
}
