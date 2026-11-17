package com.threatprio.scoring;

import com.threatprio.model.Finding;

/** Baseline 1: classic CVSS-only prioritisation (asset-blind, as commonly practised). */
public class CvssScorer implements Scorer {
    @Override public String name() { return "CVSS baseline"; }
    @Override public double probability(double[] x) { return x[0] / 10.0; }
    @Override public double priority(Finding f) { return f.getVulnerability().getCvssBase(); }
}
