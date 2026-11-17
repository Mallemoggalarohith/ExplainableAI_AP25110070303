package com.threatprio.scoring;

import java.util.ArrayList;
import java.util.List;

/**
 * Second-order (Newton) regression tree as used in XGBoost-style boosting, plus an exact
 * path-dependent TreeSHAP implementation (Lundberg et al., 2018) for feature attributions.
 */
public class RegressionTree {
    private static final class Node {
        int feature = -1, left = -1, right = -1;
        double threshold, value, cover;
        boolean isLeaf() { return left < 0; }
    }

    private final List<Node> nodes = new ArrayList<>();
    private int maxDepth;

    // ------------------------------------------------------------------ training
    /** Hyper-parameters bundled in an immutable record. */
    public record Params(int maxDepth, double lambda, double eta, int minSamples, double minHessian) {}

    public static RegressionTree build(double[][] x, double[] g, double[] h, int[][] order, boolean[] enabled, Params p) {
        RegressionTree t = new RegressionTree();
        t.maxDepth = p.maxDepth();
        boolean[] in = new boolean[x.length];
        java.util.Arrays.fill(in, true);
        t.grow(x, g, h, order, enabled, p, in, x.length, 0);
        return t;
    }

    private int grow(double[][] x, double[] g, double[] h, int[][] order, boolean[] enabled, Params p,
                     boolean[] in, int count, int depth) {
        Node node = new Node();
        int id = nodes.size();
        nodes.add(node);
        double G = 0, H = 0;
        for (int i = 0; i < x.length; i++) if (in[i]) { G += g[i]; H += h[i]; }
        node.cover = count;
        node.value = -p.eta() * G / (H + p.lambda());
        if (depth >= p.maxDepth() || count < 2 * p.minSamples()) return id;

        double bestGain = 1e-9, bestThr = 0; int bestF = -1;
        double parentScore = G * G / (H + p.lambda());
        int[] buf = new int[count];
        for (int f = 0; f < x[0].length; f++) {
            if (!enabled[f]) continue;
            int m = 0;
            for (int i : order[f]) if (in[i]) buf[m++] = i;
            double GL = 0, HL = 0;
            for (int k = 0; k < m - 1; k++) {
                GL += g[buf[k]]; HL += h[buf[k]];
                double v = x[buf[k]][f], vn = x[buf[k + 1]][f];
                if (v == vn) continue;
                int nl = k + 1, nr = m - nl;
                if (nl < p.minSamples() || nr < p.minSamples() || HL < p.minHessian() || H - HL < p.minHessian()) continue;
                double gain = GL * GL / (HL + p.lambda()) + (G - GL) * (G - GL) / (H - HL + p.lambda()) - parentScore;
                if (gain > bestGain) { bestGain = gain; bestF = f; bestThr = (v + vn) / 2.0; }
            }
        }
        if (bestF < 0) return id;

        boolean[] inL = new boolean[x.length], inR = new boolean[x.length];
        int nl = 0;
        for (int i = 0; i < x.length; i++) if (in[i]) { if (x[i][bestF] < bestThr) { inL[i] = true; nl++; } else inR[i] = true; }
        node.feature = bestF; node.threshold = bestThr;
        node.left = grow(x, g, h, order, enabled, p, inL, nl, depth + 1);
        node.right = grow(x, g, h, order, enabled, p, inR, count - nl, depth + 1);
        return id;
    }

    // ------------------------------------------------------------------ prediction
    public double predict(double[] x) {
        Node n = nodes.get(0);
        while (!n.isLeaf()) n = nodes.get(x[n.feature] < n.threshold ? n.left : n.right);
        return n.value;
    }

    /** Cover-weighted mean of the leaf values = the tree's expected output over the training data. */
    public double expectedValue() {
        double s = 0;
        for (Node n : nodes) if (n.isLeaf()) s += n.value * n.cover;
        return s / nodes.get(0).cover;
    }

    public int size() { return nodes.size(); }

    // ------------------------------------------------------------------ TreeSHAP
    private static final class Path {
        final int[] f; final double[] z, o, w;
        Path(int n) { f = new int[n]; z = new double[n]; o = new double[n]; w = new double[n]; }
        Path copy() {
            Path c = new Path(f.length);
            System.arraycopy(f, 0, c.f, 0, f.length); System.arraycopy(z, 0, c.z, 0, z.length);
            System.arraycopy(o, 0, c.o, 0, o.length); System.arraycopy(w, 0, c.w, 0, w.length);
            return c;
        }
        void extend(int d, double zf, double of, int feat) {
            f[d] = feat; z[d] = zf; o[d] = of; w[d] = d == 0 ? 1 : 0;
            for (int i = d - 1; i >= 0; i--) {
                w[i + 1] += of * w[i] * (i + 1) / (double) (d + 1);
                w[i] = zf * w[i] * (d - i) / (double) (d + 1);
            }
        }
        void unwind(int d, int idx) {
            double of = o[idx], zf = z[idx], next = w[d];
            for (int i = d - 1; i >= 0; i--) {
                if (of != 0) {
                    double tmp = w[i];
                    w[i] = next * (d + 1) / ((i + 1) * of);
                    next = tmp - w[i] * zf * (d - i) / (double) (d + 1);
                } else {
                    w[i] = w[i] * (d + 1) / (zf * (d - i));
                }
            }
            for (int i = idx; i < d; i++) { f[i] = f[i + 1]; z[i] = z[i + 1]; o[i] = o[i + 1]; }
        }
        double unwoundSum(int d, int idx) {
            double of = o[idx], zf = z[idx], next = w[d], total = 0;
            for (int i = d - 1; i >= 0; i--) {
                if (of != 0) {
                    double tmp = next * (d + 1) / ((i + 1) * of);
                    total += tmp;
                    next = w[i] - tmp * zf * ((d - i) / (double) (d + 1));
                } else {
                    total += (w[i] / zf) / ((d - i) / (double) (d + 1));
                }
            }
            return total;
        }
    }

    /** Adds this tree's exact Shapley attributions for input x into phi (log-odds units). */
    public void shap(double[] x, double[] phi) {
        if (nodes.get(0).isLeaf()) return;
        recurse(0, 0, new Path(maxDepth + 3), 1, 1, -1, x, phi);
    }

    private void recurse(int idx, int ud, Path parent, double pz, double po, int pf, double[] x, double[] phi) {
        Path p = parent.copy();
        p.extend(ud, pz, po, pf);
        Node n = nodes.get(idx);
        if (n.isLeaf()) {
            for (int i = 1; i <= ud; i++) phi[p.f[i]] += p.unwoundSum(ud, i) * (p.o[i] - p.z[i]) * n.value;
            return;
        }
        int hot = x[n.feature] < n.threshold ? n.left : n.right;
        int cold = hot == n.left ? n.right : n.left;
        double hz = nodes.get(hot).cover / n.cover, cz = nodes.get(cold).cover / n.cover;
        double iz = 1, io = 1;
        int k = 0;
        for (; k <= ud; k++) if (p.f[k] == n.feature) break;
        if (k != ud + 1) { iz = p.z[k]; io = p.o[k]; p.unwind(ud, k); ud--; }
        recurse(hot, ud + 1, p, hz * iz, io, n.feature, x, phi);
        recurse(cold, ud + 1, p, cz * iz, 0, n.feature, x, phi);
    }
}
