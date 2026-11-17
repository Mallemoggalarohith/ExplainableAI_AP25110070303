package com.threatprio.scoring;

import com.threatprio.model.Finding;

/** Decorator that ranks by probability alone (ignores asset impact) - used for the probability-vs-risk ablation. */
public class ProbabilityOnlyScorer implements Scorer {
    private final Scorer inner;
    public ProbabilityOnlyScorer(Scorer inner) { this.inner = inner; }
    @Override public String name() { return inner.name() + " (probability only)"; }
    @Override public double probability(double[] x) { return inner.probability(x); }
    @Override public boolean isProbabilistic() { return inner.isProbabilistic(); }
    @Override public double priority(Finding f) { return inner.probability(f); }
}
