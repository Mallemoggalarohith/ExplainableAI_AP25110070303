package com.threatprio.eval;

import com.threatprio.data.DatasetSplit;
import com.threatprio.eval.ExperimentResult.*;
import com.threatprio.model.Finding;
import com.threatprio.scoring.*;
import java.time.LocalDate;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.Consumer;
import java.util.stream.Collectors;

/** Orchestrates training and every evaluation in the study; heavy jobs run in parallel on a thread pool. */
public class ExperimentRunner {
    public static final double STABILITY_SIGMA = 0.05;

    /** Result plus the trained models (the GUI needs them to score and explain individual findings). */
    public record Outcome(ExperimentResult result, Map<String, Scorer> scorers, DatasetSplit split) {}

    private final long seed;
    private final Consumer<String> progress;

    public ExperimentRunner(long seed, Consumer<String> progress) { this.seed = seed; this.progress = progress; }

    private void log(String m) { progress.accept(m); }

    public Outcome run(List<Finding> all) throws Exception {
        long t0 = System.nanoTime();
        DatasetSplit split = DatasetSplit.temporal(all, LocalDate.of(2023, 1, 1), LocalDate.of(2024, 1, 1));
        if (split.train().isEmpty() || split.test().isEmpty()) throw new IllegalStateException("Split produced an empty train or test set");
        log("Split: " + split.describe());

        ExecutorService pool = Executors.newFixedThreadPool(Math.max(2, Math.min(6, Runtime.getRuntime().availableProcessors())));
        try {
            // ---- train main models in parallel
            log("Training Logistic Regression and gradient-boosted trees in parallel ...");
            LogisticRegressionScorer lr = new LogisticRegressionScorer();
            GradientBoostingScorer gb = new GradientBoostingScorer();
            Future<?> f1 = pool.submit(() -> lr.fit(split.train(), split.validation()));
            Future<?> f2 = pool.submit(() -> gb.fit(split.train(), split.validation()));
            // ---- ablation models (one per feature group) trained concurrently as well
            List<Future<GradientBoostingScorer>> abl = new ArrayList<>();
            for (int g = 0; g < Finding.GROUPS.length; g++) {
                boolean[] en = new boolean[Finding.FEATURE_NAMES.length];
                Arrays.fill(en, true);
                for (int j : Finding.GROUPS[g]) en[j] = false;
                GradientBoostingScorer m = new GradientBoostingScorer("GBDT without " + Finding.GROUP_NAMES[g], en);
                abl.add(pool.submit(() -> { m.fit(split.train(), split.validation()); return m; }));
            }
            f1.get(); f2.get();
            log(String.format("GBDT trained with %d trees (early stopping); LR lambda=%.0e", gb.getNumTrees(), lr.getChosenLambda()));

            Scorer cvss = new CvssScorer(), rule = new RuleBasedScorer();
            List<Scorer> evalOrder = List.of(cvss, rule, lr, gb, new ProbabilityOnlyScorer(gb));
            Map<String, Scorer> byName = new LinkedHashMap<>();
            for (Scorer s : List.of(cvss, rule, lr, gb)) byName.put(s.name(), s);

            // ---- main test-set evaluation
            List<Finding> test = split.test();
            int[] y = test.stream().mapToInt(Finding::label).toArray();
            double[] gain = test.stream().mapToDouble(Finding::realizedLoss).toArray();
            List<ModelMetrics> metrics = new ArrayList<>();
            Map<String, double[][]> roc = new LinkedHashMap<>(), pr = new LinkedHashMap<>();
            Map<String, List<Metrics.CalibrationBin>> cal = new LinkedHashMap<>();
            for (Scorer s : evalOrder) {
                double[] p = test.stream().mapToDouble(s::probability).toArray();
                double[] pri = test.stream().mapToDouble(s::priority).toArray();
                List<Metrics.CalibrationBin> bins = Metrics.calibration(y, p, 10);
                metrics.add(new ModelMetrics(s.name(), s.isProbabilistic(), Metrics.rocAuc(y, p), Metrics.averagePrecision(y, p),
                    s.isProbabilistic() ? Metrics.brier(y, p) : Double.NaN, Metrics.ece(bins, y.length),
                    Metrics.precisionAtK(y, pri, 50), Metrics.precisionAtK(y, pri, 100),
                    Metrics.ndcgAtK(gain, pri, 50), Metrics.ndcgAtK(gain, pri, 100)));
                if (!(s instanceof ProbabilityOnlyScorer)) {
                    roc.put(s.name(), Metrics.rocCurve(y, p));
                    pr.put(s.name(), Metrics.prCurve(y, p));
                    if (s.isProbabilistic() || s == rule) cal.put(s.name(), bins);
                }
            }
            log("Main evaluation done.");

            // ---- RQ2: temporal shift (per publication year) and class-distribution shift
            List<YearMetrics> byYear = new ArrayList<>();
            Map<Integer, List<Finding>> years = test.stream().collect(Collectors.groupingBy(Finding::publishedYear, TreeMap::new, Collectors.toList()));
            for (Scorer s : List.of(cvss, rule, lr, gb))
                for (var e : years.entrySet()) {
                    int[] yy = e.getValue().stream().mapToInt(Finding::label).toArray();
                    double[] pp = e.getValue().stream().mapToDouble(s::probability).toArray();
                    byYear.add(new YearMetrics(s.name(), e.getKey(), yy.length, DatasetSplit.prevalence(e.getValue()),
                        Metrics.rocAuc(yy, pp), Metrics.averagePrecision(yy, pp)));
                }
            List<PrevalenceRow> prev = new ArrayList<>();
            for (double target : new double[]{0.02, 0.05, 0.10, 0.20}) {
                List<Finding> rs = resample(test, target, seed);
                int[] yy = rs.stream().mapToInt(Finding::label).toArray();
                for (Scorer s : List.of(cvss, rule, lr, gb))
                    prev.add(new PrevalenceRow(s.name(), DatasetSplit.prevalence(rs),
                        Metrics.averagePrecision(yy, rs.stream().mapToDouble(s::probability).toArray())));
            }
            log("Shift analysis done.");

            // ---- RQ3: ablation + importance
            double fullPr = Metrics.averagePrecision(y, test.stream().mapToDouble(gb::probability).toArray());
            List<AblationRow> ablation = new ArrayList<>();
            for (int g = 0; g < abl.size(); g++) {
                GradientBoostingScorer m = abl.get(g).get();
                double[] p = test.stream().mapToDouble(m::probability).toArray();
                double ap = Metrics.averagePrecision(y, p);
                ablation.add(new AblationRow(Finding.GROUP_NAMES[g], Metrics.rocAuc(y, p), ap, ap - fullPr));
            }
            List<double[]> xs = test.stream().map(Finding::features).collect(Collectors.toList());
            double[] shapImp = gb.meanAbsShap(xs.subList(0, Math.min(500, xs.size())));
            double[] coef = lr.standardisedCoefficients();
            List<ImportanceRow> imp = new ArrayList<>();
            for (int j = 0; j < shapImp.length; j++) imp.add(new ImportanceRow(Finding.FEATURE_NAMES[j], shapImp[j], Math.abs(coef[j])));
            imp.sort(Comparator.comparingDouble(ImportanceRow::gbmMeanAbsShap).reversed());
            log("Ablation and importance done.");

            // ---- explanation stability
            double[] std = featureStd(split.train());
            List<double[]> sample = new ArrayList<>(xs);
            Collections.shuffle(sample, new Random(seed));
            sample = sample.subList(0, Math.min(150, sample.size()));
            List<StabilityRow> stab = List.of(
                StabilityEvaluator.evaluate(lr.name(), lr, sample, std, STABILITY_SIGMA, 5, seed),
                StabilityEvaluator.evaluate(gb.name(), gb, sample, std, STABILITY_SIGMA, 5, seed));
            log("Stability done.");

            // ---- RQ1: paired bootstrap of metric differences
            List<BootstrapRow> boot = new ArrayList<>();
            boot.add(bootstrap("GBDT - Logistic Regression", gb, lr, test, 1000));
            boot.add(bootstrap("GBDT - Rule-based", gb, rule, test, 1000));
            boot.add(bootstrap("GBDT - CVSS baseline", gb, cvss, test, 1000));
            boot.addAll(ndcgBootstrap(gb, new ProbabilityOnlyScorer(gb), test, 1000));
            log("Bootstrap done.");

            double secs = (System.nanoTime() - t0) / 1e9;
            ExperimentResult res = new ExperimentResult(split.describe(), metrics, roc, pr, cal, byYear, prev, ablation, imp, stab, boot, seed, secs);
            return new Outcome(res, byName, split);
        } finally {
            pool.shutdown();
        }
    }

    /** Paired bootstrap: same resampled indices for both models, reports PR-AUC and ROC-AUC differences. */
    private BootstrapRow bootstrap(String name, Scorer a, Scorer b, List<Finding> test, int B) {
        int n = test.size();
        int[] y = test.stream().mapToInt(Finding::label).toArray();
        double[] pa = test.stream().mapToDouble(a::probability).toArray(), pb = test.stream().mapToDouble(b::probability).toArray();
        Random rnd = new Random(seed + 11);
        double[] d = new double[B]; int k = 0;
        while (k < B) {
            int[] yy = new int[n]; double[] sa = new double[n], sb = new double[n];
            for (int i = 0; i < n; i++) { int j = rnd.nextInt(n); yy[i] = y[j]; sa[i] = pa[j]; sb[i] = pb[j]; }
            double v = Metrics.averagePrecision(yy, sa) - Metrics.averagePrecision(yy, sb);
            if (!Double.isNaN(v)) d[k++] = v;
        }
        return summarise(name, "PR-AUC", d);
    }

    /** Paired bootstrap of NDCG@50 difference between risk ranking (p x impact) and probability-only ranking. */
    private List<BootstrapRow> ndcgBootstrap(Scorer risk, Scorer probOnly, List<Finding> test, int B) {
        int n = test.size();
        double[] gain = test.stream().mapToDouble(Finding::realizedLoss).toArray();
        double[] pr = test.stream().mapToDouble(risk::priority).toArray(), pp = test.stream().mapToDouble(probOnly::priority).toArray();
        Random rnd = new Random(seed + 13);
        double[] d = new double[B];
        for (int b = 0; b < B; b++) {
            double[] g = new double[n], r1 = new double[n], r2 = new double[n];
            for (int i = 0; i < n; i++) { int j = rnd.nextInt(n); g[i] = gain[j]; r1[i] = pr[j]; r2[i] = pp[j]; }
            d[b] = Metrics.ndcgAtK(g, r1, 50) - Metrics.ndcgAtK(g, r2, 50);
        }
        return List.of(summarise("GBDT risk (p x impact) - GBDT probability-only", "NDCG@50", d));
    }

    private static BootstrapRow summarise(String name, String metric, double[] d) {
        double[] s = d.clone(); Arrays.sort(s);
        double mean = Arrays.stream(d).average().orElse(0);
        return new BootstrapRow(name, metric, mean, s[(int) (0.025 * s.length)], s[(int) (0.975 * s.length) - 1]);
    }

    /** Deterministically re-samples so that the positive rate equals target (drops positives or negatives). */
    static List<Finding> resample(List<Finding> fs, double target, long seed) {
        List<Finding> pos = fs.stream().filter(Finding::isExploited).collect(Collectors.toList());
        List<Finding> neg = fs.stream().filter(f -> !f.isExploited()).collect(Collectors.toList());
        Random rnd = new Random(seed);
        Collections.shuffle(pos, rnd); Collections.shuffle(neg, rnd);
        double cur = pos.size() / (double) fs.size();
        List<Finding> out = new ArrayList<>();
        if (cur > target) {   // keep all negatives, reduce positives
            int keepPos = (int) Math.round(target * neg.size() / (1 - target));
            out.addAll(neg); out.addAll(pos.subList(0, Math.min(pos.size(), keepPos)));
        } else {              // keep all positives, reduce negatives
            int keepNeg = (int) Math.round(pos.size() * (1 - target) / target);
            out.addAll(pos); out.addAll(neg.subList(0, Math.min(neg.size(), keepNeg)));
        }
        return out;
    }

    static double[] featureStd(List<Finding> fs) {
        int d = Finding.FEATURE_NAMES.length;
        double[] mean = new double[d], std = new double[d];
        for (Finding f : fs) { double[] x = f.features(); for (int j = 0; j < d; j++) mean[j] += x[j]; }
        for (int j = 0; j < d; j++) mean[j] /= fs.size();
        for (Finding f : fs) { double[] x = f.features(); for (int j = 0; j < d; j++) std[j] += (x[j] - mean[j]) * (x[j] - mean[j]); }
        for (int j = 0; j < d; j++) std[j] = Math.sqrt(std[j] / fs.size());
        return std;
    }
}
