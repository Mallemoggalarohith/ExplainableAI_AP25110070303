package com.threatprio.scoring;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Stronger model: gradient-boosted decision trees with logistic loss, Newton (second-order) leaf weights,
 * L2 leaf regularisation, shrinkage and early stopping - the same family as XGBoost - together with
 * exact TreeSHAP explanations. Implemented from scratch in pure Java.
 */
public class GradientBoostingScorer extends TrainableScorer implements Explainable {
    private final RegressionTree.Params params;
    private final int maxRounds, patience;
    private final boolean[] enabled;
    private final String label;
    private final List<RegressionTree> trees = new ArrayList<>();
    private double base;

    public GradientBoostingScorer() { this("XGBoost-style GBDT + SHAP", null); }

    /** @param enabledFeatures null = all features; otherwise only features marked true may be used (ablation). */
    public GradientBoostingScorer(String label, boolean[] enabledFeatures) {
        this.label = label;
        this.params = new RegressionTree.Params(3, 1.0, 0.08, 25, 0.5);
        this.maxRounds = 400; this.patience = 25;
        this.enabled = enabledFeatures;
    }

    @Override public String name() { return label; }
    public int getNumTrees() { return trees.size(); }

    @Override protected void doFit(double[][] x, int[] y, double[][] xv, int[] yv) {
        int n = x.length, d = x[0].length;
        boolean[] en = enabled != null ? enabled : filled(d);
        int[][] order = new int[d][];
        for (int f = 0; f < d; f++) {
            final int ff = f;
            order[f] = java.util.stream.IntStream.range(0, n).boxed()
                .sorted((a, b) -> Double.compare(x[a][ff], x[b][ff])).mapToInt(Integer::intValue).toArray();
        }
        double prior = 0; for (int v : y) prior += v; prior = Math.min(1 - 1e-6, Math.max(1e-6, prior / n));
        base = Math.log(prior / (1 - prior));
        trees.clear();
        double[] m = new double[n]; Arrays.fill(m, base);
        double[] mv = new double[xv.length]; Arrays.fill(mv, base);
        double[] g = new double[n], h = new double[n];
        double bestLoss = Double.MAX_VALUE; int bestRound = 0;

        for (int r = 0; r < maxRounds; r++) {
            for (int i = 0; i < n; i++) { double p = sigmoid(m[i]); g[i] = p - y[i]; h[i] = Math.max(1e-6, p * (1 - p)); }
            RegressionTree t = RegressionTree.build(x, g, h, order, en, params);
            trees.add(t);
            for (int i = 0; i < n; i++) m[i] += t.predict(x[i]);
            if (xv.length == 0) { bestRound = r; continue; }
            double[] pv = new double[xv.length];
            for (int i = 0; i < xv.length; i++) { mv[i] += t.predict(xv[i]); pv[i] = sigmoid(mv[i]); }
            double loss = logLoss(yv, pv);
            if (loss < bestLoss - 1e-6) { bestLoss = loss; bestRound = r; }
            else if (r - bestRound >= patience) break;
        }
        while (trees.size() > bestRound + 1) trees.remove(trees.size() - 1);   // early stopping
    }

    private static boolean[] filled(int d) { boolean[] b = new boolean[d]; Arrays.fill(b, true); return b; }

    public double margin(double[] x) {
        double m = base;
        for (RegressionTree t : trees) m += t.predict(x);
        return m;
    }

    @Override public double probability(double[] x) { return sigmoid(margin(x)); }

    @Override public Explanation explain(double[] x) {
        double[] phi = new double[x.length];
        double baseValue = base;
        for (RegressionTree t : trees) { t.shap(x, phi); baseValue += t.expectedValue(); }
        double margin = margin(x);
        return new Explanation(x.clone(), baseValue, phi, margin, sigmoid(margin));
    }

    /** Global importance = mean |SHAP| over a sample of inputs. */
    public double[] meanAbsShap(List<double[]> sample) {
        double[] imp = new double[sample.get(0).length];
        for (double[] x : sample) {
            double[] c = explain(x).contributions();
            for (int j = 0; j < imp.length; j++) imp[j] += Math.abs(c[j]);
        }
        for (int j = 0; j < imp.length; j++) imp[j] /= sample.size();
        return imp;
    }
}
