package com.threatprio.eval;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.IntStream;

/** Evaluation metrics: ROC-AUC, PR-AUC (average precision), Brier, calibration/ECE, Precision@K, NDCG@K. */
public final class Metrics {
    private Metrics() {}

    public record CalibrationBin(double meanPredicted, double observedRate, int count) {}

    private static int[] orderDesc(double[] s) {
        return IntStream.range(0, s.length).boxed()
            .sorted((a, b) -> { int c = Double.compare(s[b], s[a]); return c != 0 ? c : Integer.compare(a, b); })
            .mapToInt(Integer::intValue).toArray();
    }

    private static int positives(int[] y) { int p = 0; for (int v : y) p += v; return p; }

    /** ROC-AUC via the Mann-Whitney U statistic with average ranks for ties. */
    public static double rocAuc(int[] y, double[] s) {
        int n = y.length, pos = positives(y), neg = n - pos;
        if (pos == 0 || neg == 0) return Double.NaN;
        Integer[] idx = new Integer[n];
        for (int i = 0; i < n; i++) idx[i] = i;
        Arrays.sort(idx, (a, b) -> Double.compare(s[a], s[b]));
        double[] rank = new double[n];
        for (int i = 0; i < n; ) {
            int j = i;
            while (j + 1 < n && s[idx[j + 1]] == s[idx[i]]) j++;
            double avg = (i + j) / 2.0 + 1;
            for (int k = i; k <= j; k++) rank[idx[k]] = avg;
            i = j + 1;
        }
        double sumPos = 0;
        for (int i = 0; i < n; i++) if (y[i] == 1) sumPos += rank[i];
        return (sumPos - pos * (pos + 1) / 2.0) / ((double) pos * neg);
    }

    /** PR-AUC computed as average precision (step-wise, ties grouped) - same definition as scikit-learn. */
    public static double averagePrecision(int[] y, double[] s) {
        int pos = positives(y);
        if (pos == 0) return Double.NaN;
        int[] ord = orderDesc(s);
        double tp = 0, fp = 0, ap = 0, prevRecall = 0;
        for (int i = 0; i < ord.length; ) {
            int j = i;
            while (j + 1 < ord.length && s[ord[j + 1]] == s[ord[i]]) j++;
            for (int k = i; k <= j; k++) { if (y[ord[k]] == 1) tp++; else fp++; }
            double recall = tp / pos, precision = tp / (tp + fp);
            ap += (recall - prevRecall) * precision;
            prevRecall = recall;
            i = j + 1;
        }
        return ap;
    }

    /** Returns {fpr[], tpr[]}. */
    public static double[][] rocCurve(int[] y, double[] s) {
        int pos = positives(y), neg = y.length - pos;
        int[] ord = orderDesc(s);
        List<double[]> pts = new ArrayList<>();
        pts.add(new double[]{0, 0});
        double tp = 0, fp = 0;
        for (int i = 0; i < ord.length; ) {
            int j = i;
            while (j + 1 < ord.length && s[ord[j + 1]] == s[ord[i]]) j++;
            for (int k = i; k <= j; k++) { if (y[ord[k]] == 1) tp++; else fp++; }
            pts.add(new double[]{fp / Math.max(1, neg), tp / Math.max(1, pos)});
            i = j + 1;
        }
        return transpose(pts);
    }

    /** Returns {recall[], precision[]}. */
    public static double[][] prCurve(int[] y, double[] s) {
        int pos = positives(y);
        int[] ord = orderDesc(s);
        List<double[]> pts = new ArrayList<>();
        double tp = 0, fp = 0;
        for (int i = 0; i < ord.length; ) {
            int j = i;
            while (j + 1 < ord.length && s[ord[j + 1]] == s[ord[i]]) j++;
            for (int k = i; k <= j; k++) { if (y[ord[k]] == 1) tp++; else fp++; }
            pts.add(new double[]{tp / Math.max(1, pos), tp / (tp + fp)});
            i = j + 1;
        }
        return transpose(pts);
    }

    private static double[][] transpose(List<double[]> pts) {
        double[][] r = new double[2][pts.size()];
        for (int i = 0; i < pts.size(); i++) { r[0][i] = pts.get(i)[0]; r[1][i] = pts.get(i)[1]; }
        return r;
    }

    public static double brier(int[] y, double[] p) {
        double s = 0;
        for (int i = 0; i < y.length; i++) s += (p[i] - y[i]) * (p[i] - y[i]);
        return s / y.length;
    }

    /** Equal-width reliability bins on [0,1]; empty bins are omitted. */
    public static List<CalibrationBin> calibration(int[] y, double[] p, int bins) {
        double[] sp = new double[bins], sy = new double[bins]; int[] c = new int[bins];
        for (int i = 0; i < y.length; i++) {
            int b = Math.min(bins - 1, (int) (Math.max(0, Math.min(1, p[i])) * bins));
            sp[b] += p[i]; sy[b] += y[i]; c[b]++;
        }
        List<CalibrationBin> out = new ArrayList<>();
        for (int b = 0; b < bins; b++) if (c[b] > 0) out.add(new CalibrationBin(sp[b] / c[b], sy[b] / c[b], c[b]));
        return out;
    }

    /** Expected calibration error = count-weighted mean |observed - predicted| over bins. */
    public static double ece(List<CalibrationBin> bins, int n) {
        double e = 0;
        for (CalibrationBin b : bins) e += b.count() * Math.abs(b.observedRate() - b.meanPredicted());
        return e / n;
    }

    public static double precisionAtK(int[] y, double[] priority, int k) {
        int[] ord = orderDesc(priority);
        k = Math.min(k, y.length);
        double hit = 0;
        for (int i = 0; i < k; i++) hit += y[ord[i]];
        return hit / k;
    }

    /** NDCG@K with linear gains (here: realised loss = criticality of exploited assets). */
    public static double ndcgAtK(double[] gain, double[] priority, int k) {
        k = Math.min(k, gain.length);
        int[] ord = orderDesc(priority);
        double dcg = 0;
        for (int i = 0; i < k; i++) dcg += gain[ord[i]] / (Math.log(i + 2) / Math.log(2));
        double[] sorted = gain.clone();
        Arrays.sort(sorted);
        double idcg = 0;
        for (int i = 0; i < k; i++) idcg += sorted[sorted.length - 1 - i] / (Math.log(i + 2) / Math.log(2));
        return idcg == 0 ? 0 : dcg / idcg;
    }

    /** Spearman rank correlation (average ranks). */
    public static double spearman(double[] a, double[] b) {
        double[] ra = ranks(a), rb = ranks(b);
        double ma = Arrays.stream(ra).average().orElse(0), mb = Arrays.stream(rb).average().orElse(0);
        double num = 0, da = 0, db = 0;
        for (int i = 0; i < ra.length; i++) { num += (ra[i] - ma) * (rb[i] - mb); da += (ra[i] - ma) * (ra[i] - ma); db += (rb[i] - mb) * (rb[i] - mb); }
        return da == 0 || db == 0 ? 0 : num / Math.sqrt(da * db);
    }

    private static double[] ranks(double[] v) {
        Integer[] idx = new Integer[v.length];
        for (int i = 0; i < v.length; i++) idx[i] = i;
        Arrays.sort(idx, (x, z) -> Double.compare(v[x], v[z]));
        double[] r = new double[v.length];
        for (int i = 0; i < v.length; ) {
            int j = i;
            while (j + 1 < v.length && v[idx[j + 1]] == v[idx[i]]) j++;
            for (int k = i; k <= j; k++) r[idx[k]] = (i + j) / 2.0 + 1;
            i = j + 1;
        }
        return r;
    }
}
