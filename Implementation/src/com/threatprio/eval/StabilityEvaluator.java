package com.threatprio.eval;

import com.threatprio.model.Finding;
import com.threatprio.scoring.Explainable;
import com.threatprio.scoring.Explanation;
import java.util.*;

/** Measures how much feature attributions change when continuous inputs are slightly perturbed. */
public final class StabilityEvaluator {
    private StabilityEvaluator() {}

    public static ExperimentResult.StabilityRow evaluate(String modelName, Explainable model, List<double[]> sample,
                                                         double[] featureStd, double sigma, int repeats, long seed) {
        Random rnd = new Random(seed);
        double jac = 0, rho = 0; int cnt = 0;
        for (double[] x : sample) {
            Explanation base = model.explain(x);
            Set<Integer> topBase = topIdx(base.contributions(), 3);
            for (int r = 0; r < repeats; r++) {
                double[] xp = x.clone();
                for (int j : Finding.CONTINUOUS) xp[j] += sigma * featureStd[j] * rnd.nextGaussian();
                xp[0] = Math.max(0, Math.min(10, xp[0]));
                xp[2] = Math.max(0, Math.min(1, xp[2]));
                xp[6] = Math.max(0, xp[6]);
                xp[7] = Math.max(0, Math.min(1, xp[7]));
                Explanation pert = model.explain(xp);
                Set<Integer> topPert = topIdx(pert.contributions(), 3);
                Set<Integer> inter = new HashSet<>(topBase); inter.retainAll(topPert);
                Set<Integer> union = new HashSet<>(topBase); union.addAll(topPert);
                jac += inter.size() / (double) union.size();
                rho += Metrics.spearman(base.contributions(), pert.contributions());
                cnt++;
            }
        }
        return new ExperimentResult.StabilityRow(modelName, sigma, jac / cnt, rho / cnt);
    }

    private static Set<Integer> topIdx(double[] c, int k) {
        Integer[] idx = new Integer[c.length];
        for (int i = 0; i < c.length; i++) idx[i] = i;
        Arrays.sort(idx, (a, b) -> Double.compare(Math.abs(c[b]), Math.abs(c[a])));
        Set<Integer> s = new HashSet<>();
        for (int i = 0; i < k; i++) s.add(idx[i]);
        return s;
    }
}
