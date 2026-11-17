package com.threatprio.scoring;

import com.threatprio.model.Finding;
import java.util.List;

/** Common contract for every prioritisation method (baselines and learned models) - polymorphism. */
public interface Scorer {
    String name();

    /** Exploitation score in [0,1] for a raw feature vector. */
    double probability(double[] features);

    default double probability(Finding f) { return probability(f.features()); }

    /** True when the output is meant to be a calibrated probability (so Brier/calibration make sense). */
    default boolean isProbabilistic() { return false; }

    /** Ranking key = organisational risk = probability x asset impact. */
    default double priority(Finding f) { return probability(f) * ImpactModel.impact(f.getAsset()); }

    /** Learn from data; baselines ignore this. */
    default void fit(List<Finding> train, List<Finding> validation) {}
}
