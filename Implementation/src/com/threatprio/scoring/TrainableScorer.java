package com.threatprio.scoring;

import com.threatprio.model.Finding;
import java.util.List;

/** Template for learned models: converts findings to arrays then delegates to {@link #doFit}. */
public abstract class TrainableScorer implements Scorer {
    @Override public final boolean isProbabilistic() { return true; }

    @Override public final void fit(List<Finding> train, List<Finding> validation) {
        if (train.isEmpty()) throw new IllegalArgumentException("empty training set");
        double[][] x = train.stream().map(Finding::features).toArray(double[][]::new);
        int[] y = train.stream().mapToInt(Finding::label).toArray();
        double[][] xv = validation.stream().map(Finding::features).toArray(double[][]::new);
        int[] yv = validation.stream().mapToInt(Finding::label).toArray();
        doFit(x, y, xv, yv);
    }

    protected abstract void doFit(double[][] x, int[] y, double[][] xv, int[] yv);

    protected static double sigmoid(double z) { return 1.0 / (1.0 + Math.exp(-z)); }

    protected static double logLoss(int[] y, double[] p) {
        double s = 0;
        for (int i = 0; i < y.length; i++) {
            double q = Math.min(1 - 1e-12, Math.max(1e-12, p[i]));
            s -= y[i] == 1 ? Math.log(q) : Math.log(1 - q);
        }
        return y.length == 0 ? 0 : s / y.length;
    }
}
