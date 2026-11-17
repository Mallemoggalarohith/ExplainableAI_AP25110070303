package com.threatprio.scoring;

import com.threatprio.model.Finding;

/** Implemented by models that can attribute a prediction to individual input features. */
public interface Explainable {
    Explanation explain(double[] features);
    default Explanation explain(Finding f) { return explain(f.features()); }
}
