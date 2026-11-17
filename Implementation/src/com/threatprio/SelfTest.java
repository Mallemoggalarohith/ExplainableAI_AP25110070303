package com.threatprio;

import com.threatprio.data.*;
import com.threatprio.eval.*;
import com.threatprio.model.*;
import com.threatprio.scoring.*;
import java.util.*;

/** Dependency-free tests (no JUnit needed). Run: scripts/test.sh  -> exits non-zero on failure. */
public class SelfTest {
    static int failures = 0, checks = 0;
    static void check(String name, boolean ok) { checks++; if (!ok) failures++; System.out.println((ok ? "PASS  " : "FAIL  ") + name); }
    static boolean near(double a, double b, double tol) { return Math.abs(a - b) <= tol; }

    public static void main(String[] args) throws Exception {
        // ---- metrics against hand-computed values
        int[] y = {1, 0, 1, 0, 0};
        double[] s = {0.9, 0.8, 0.7, 0.3, 0.1};
        check("ROC-AUC known value (5/6)", near(Metrics.rocAuc(y, s), 5.0 / 6, 1e-9));
        check("Average precision known value (0.8333)", near(Metrics.averagePrecision(y, s), (1.0 * 0.5 + 0.5 * (2.0 / 3)), 1e-9));
        check("ROC-AUC ties give 0.5", near(Metrics.rocAuc(new int[]{1, 0, 1, 0}, new double[]{.5, .5, .5, .5}), 0.5, 1e-9));
        check("Brier known value", near(Metrics.brier(new int[]{1, 0}, new double[]{0.8, 0.3}), (0.04 + 0.09) / 2, 1e-9));
        check("Precision@2", near(Metrics.precisionAtK(y, s, 2), 0.5, 1e-9));
        check("NDCG@K perfect ranking = 1", near(Metrics.ndcgAtK(new double[]{3, 0, 2}, new double[]{9, 1, 5}, 3), 1.0, 1e-9));
        check("Spearman identical = 1", near(Metrics.spearman(new double[]{1, 2, 3}, new double[]{10, 20, 30}), 1.0, 1e-9));

        // ---- data
        List<Finding> all = SyntheticDataGenerator.generate(3000, 7);
        check("generator is deterministic", SyntheticDataGenerator.generate(50, 1).get(10).getCveId()
            .equals(SyntheticDataGenerator.generate(50, 1).get(10).getCveId()));
        check("CVE ids unique", all.stream().map(Finding::getCveId).distinct().count() == all.size());
        DatasetSplit sp = DatasetSplit.temporal(all, java.time.LocalDate.of(2023, 1, 1), java.time.LocalDate.of(2024, 1, 1));
        boolean noLeak = sp.train().stream().allMatch(f -> f.publishedYear() < 2023)
            && sp.test().stream().allMatch(f -> f.publishedYear() >= 2024);
        check("temporal split has no overlap in time", noLeak);
        Set<String> trainIds = new HashSet<>(); sp.train().forEach(f -> trainIds.add(f.getCveId()));
        check("no CVE in both train and test", sp.test().stream().noneMatch(f -> trainIds.contains(f.getCveId())));

        // ---- models + SHAP additivity (local accuracy property)
        GradientBoostingScorer gb = new GradientBoostingScorer();
        gb.fit(sp.train(), sp.validation());
        LogisticRegressionScorer lr = new LogisticRegressionScorer();
        lr.fit(sp.train(), sp.validation());
        double maxErr = 0, maxErrLr = 0;
        for (Finding f : sp.test().subList(0, 100)) {
            Explanation e = gb.explain(f);
            double sum = e.baseValue(); for (double c : e.contributions()) sum += c;
            maxErr = Math.max(maxErr, Math.abs(sum - e.margin()));
            Explanation l = lr.explain(f);
            double s2 = l.baseValue(); for (double c : l.contributions()) s2 += c;
            maxErrLr = Math.max(maxErrLr, Math.abs(s2 - l.margin()));
        }
        System.out.printf("      max |base + sum(SHAP) - margin| = %.2e (GBDT), %.2e (LR)%n", maxErr, maxErrLr);
        check("TreeSHAP additivity (GBDT)", maxErr < 1e-8);
        check("Linear attribution additivity (LR)", maxErrLr < 1e-9);
        check("probabilities in [0,1]", sp.test().stream().allMatch(f -> gb.probability(f) >= 0 && gb.probability(f) <= 1));
        // a feature the model never uses must receive zero attribution
        boolean[] en = new boolean[9]; Arrays.fill(en, true); en[3] = false;
        GradientBoostingScorer noKev = new GradientBoostingScorer("noKev", en);
        noKev.fit(sp.train(), sp.validation());
        check("ablated feature gets zero SHAP", near(noKev.explain(sp.test().get(0)).contributions()[3], 0, 1e-12));

        // ---- CVSS baseline ignores asset, risk models do not
        Finding f0 = all.get(0);
        check("risk = probability x impact", near(gb.priority(f0), gb.probability(f0) * ImpactModel.impact(f0.getAsset()), 1e-12));

        // ---- persistence round trip (file repository; JDBC SQL is validated separately in scripts/validate_sql.py)
        java.nio.file.Path tmp = java.nio.file.Files.createTempDirectory("tp");
        var repo = new com.threatprio.db.FileThreatRepository(tmp);
        repo.init();
        repo.replaceFindings(all.subList(0, 200));
        List<Finding> back = repo.loadFindings();
        check("repository round trip keeps all findings", back.size() == 200
            && back.get(5).getCveId().equals(all.get(5).getCveId()) && back.get(5).label() == all.get(5).label());
        repo.saveFeedback(new com.threatprio.db.AnalystFeedback("CVE-X", 3, "ok, with comma", java.time.LocalDateTime.now()));
        repo.saveFeedback(new com.threatprio.db.AnalystFeedback("CVE-X", 5, "better", java.time.LocalDateTime.now()));
        check("feedback insert then update", repo.allFeedback().size() == 1 && repo.findFeedback("CVE-X").get().rating() == 5);
        check("feedback delete", repo.deleteFeedback("CVE-X") && repo.findFeedback("CVE-X").isEmpty() && !repo.deleteFeedback("CVE-X"));
        boolean bad = false; try { new com.threatprio.db.AnalystFeedback("C", 9, "", java.time.LocalDateTime.now()); } catch (IllegalArgumentException e) { bad = true; }
        check("invalid rating rejected", bad);

        // ---- real-format loader: join + leakage-safe labelling
        java.nio.file.Path d = java.nio.file.Path.of("..", "Dataset", "sample_real_format");
        if (java.nio.file.Files.exists(d)) {
            List<Finding> real = CsvDatasetLoader.load(d.resolve("nvd_sample.csv"), d.resolve("kev_sample.csv"), d.resolve("epss_sample.csv"),
                java.time.LocalDate.of(2025, 1, 1), 90, 1);
            Map<String, Finding> m = new HashMap<>(); real.forEach(f -> m.put(f.getCveId(), f));
            check("loader skips CVEs published after snapshot", !m.containsKey("CVE-2025-0006") && real.size() == 5);
            check("KEV before snapshot -> feature, not label", m.get("CVE-2024-0001").getVulnerability().isInKev() && !m.get("CVE-2024-0001").isExploited());
            check("KEV 40 days after snapshot -> label", m.get("CVE-2024-0003").isExploited() && !m.get("CVE-2024-0003").getVulnerability().isInKev());
            check("EPSS joined", near(m.get("CVE-2024-0001").getVulnerability().getEpss(), 0.91234, 1e-9));
            check("quoted CSV field with comma parsed", CsvUtil.split("a,\"b,c\",d").size() == 3);
        }

        System.out.printf("%n%d checks, %d failures%n", checks, failures);
        System.exit(failures == 0 ? 0 : 1);
    }
}
