package com.threatprio.scoring;

/** Interpretable model: L2-regularised logistic regression on standardised features (batch gradient descent). */
public class LogisticRegressionScorer extends TrainableScorer implements Explainable {
    private static final double[] LAMBDAS = {1e-4, 1e-3, 1e-2, 1e-1};
    private double[] mean, std, w;
    private double b;
    private double chosenLambda;

    @Override public String name() { return "Logistic Regression"; }
    public double getChosenLambda() { return chosenLambda; }
    public double[] standardisedCoefficients() { return w.clone(); }

    @Override protected void doFit(double[][] x, int[] y, double[][] xv, int[] yv) {
        int n = x.length, d = x[0].length;
        mean = new double[d]; std = new double[d];
        for (int j = 0; j < d; j++) {
            for (double[] r : x) mean[j] += r[j];
            mean[j] /= n;
            for (double[] r : x) std[j] += (r[j] - mean[j]) * (r[j] - mean[j]);
            std[j] = Math.max(1e-9, Math.sqrt(std[j] / n));
        }
        double[][] z = standardise(x);
        double bestLoss = Double.MAX_VALUE;
        for (double lambda : LAMBDAS) {
            double prior = Math.min(1 - 1e-6, Math.max(1e-6, mean(y)));
            double[] ww = new double[d]; double[] bb = {Math.log(prior / (1 - prior))};
            train(z, y, lambda, ww, bb);
            double[] pv = new double[xv.length];
            for (int i = 0; i < xv.length; i++) pv[i] = sigmoid(dot(ww, standardise(xv[i])) + bb[0]);
            double loss = xv.length > 0 ? logLoss(yv, pv) : lambda;   // without validation data pick the smallest loss proxy
            if (loss < bestLoss) { bestLoss = loss; w = ww; b = bb[0]; chosenLambda = lambda; }
        }
    }

    private static double mean(int[] y) { double s = 0; for (int v : y) s += v; return s / y.length; }

    private void train(double[][] z, int[] y, double lambda, double[] ww, double[] bb) {
        int n = z.length, d = ww.length;
        double lr = 0.3;
        for (int epoch = 0; epoch < 800; epoch++) {
            double[] g = new double[d]; double gb = 0;
            for (int i = 0; i < n; i++) {
                double err = sigmoid(dot(ww, z[i]) + bb[0]) - y[i];
                for (int j = 0; j < d; j++) g[j] += err * z[i][j];
                gb += err;
            }
            for (int j = 0; j < d; j++) ww[j] -= lr * (g[j] / n + lambda * ww[j]);
            bb[0] -= lr * gb / n;
        }
    }

    private double[][] standardise(double[][] x) {
        double[][] z = new double[x.length][];
        for (int i = 0; i < x.length; i++) z[i] = standardise(x[i]);
        return z;
    }
    private double[] standardise(double[] r) {
        double[] z = new double[r.length];
        for (int j = 0; j < r.length; j++) z[j] = (r[j] - mean[j]) / std[j];
        return z;
    }
    private static double dot(double[] a, double[] c) { double s = 0; for (int i = 0; i < a.length; i++) s += a[i] * c[i]; return s; }

    @Override public double probability(double[] x) { return sigmoid(dot(w, standardise(x)) + b); }

    /** Exact attribution for a linear model: w_j * (x_j - mean_j)/std_j relative to the average input. */
    @Override public Explanation explain(double[] x) {
        double[] z = standardise(x), c = new double[w.length];
        double margin = b;
        for (int j = 0; j < w.length; j++) { c[j] = w[j] * z[j]; margin += c[j]; }
        return new Explanation(x.clone(), b, c, margin, sigmoid(margin));
    }
}
