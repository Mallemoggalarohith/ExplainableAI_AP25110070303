package com.threatprio.model;

import java.time.LocalDate;
import java.time.temporal.ChronoUnit;

/**
 * A finding = one vulnerability present on one asset, observed at a snapshot date.
 * The label {@code exploited} says whether exploitation was observed in the window after the snapshot.
 */
public class Finding {
    public static final String[] FEATURE_NAMES = {
        "cvss_base", "attack_vector", "epss", "in_kev", "exploit_code_public",
        "patch_available", "vuln_age_years", "intel_confidence", "internet_facing"
    };
    /** Indices of continuous features (used when perturbing inputs for explanation-stability tests). */
    public static final int[] CONTINUOUS = {0, 2, 6, 7};
    /** Feature groups used in the ablation study (RQ3). */
    public static final String[] GROUP_NAMES = {"CVSS", "EPSS", "KEV", "Exploit code", "Intel confidence", "Exposure/patch/age"};
    public static final int[][] GROUPS = {{0, 1}, {2}, {3}, {4}, {7}, {5, 6, 8}};

    private final Vulnerability vulnerability;
    private final Asset asset;
    private final LocalDate snapshot;
    private final boolean exploited;

    public Finding(Vulnerability v, Asset a, LocalDate snapshot, boolean exploited) {
        this.vulnerability = v; this.asset = a; this.snapshot = snapshot; this.exploited = exploited;
    }

    public Vulnerability getVulnerability() { return vulnerability; }
    public Asset getAsset() { return asset; }
    public LocalDate getSnapshot() { return snapshot; }
    public boolean isExploited() { return exploited; }
    public int label() { return exploited ? 1 : 0; }
    public String getCveId() { return vulnerability.getId(); }
    public int publishedYear() { return vulnerability.getPublished().getYear(); }

    /** Realised organisational loss used as the gain for NDCG: exploitation of an asset costs its criticality. */
    public double realizedLoss() { return exploited ? asset.getCriticality() : 0.0; }

    /** Feature vector for the exploitation-probability models (impact/criticality is deliberately excluded). */
    public double[] features() {
        Vulnerability v = vulnerability;
        double age = ChronoUnit.DAYS.between(v.getPublished(), snapshot) / 365.25;
        return new double[]{
            v.getCvssBase(), v.getAttackVector().getScore(), v.getEpss(), v.isInKev() ? 1 : 0,
            v.isExploitCodePublic() ? 1 : 0, v.isPatchAvailable() ? 1 : 0, age,
            v.getIntelConfidence(), asset.isInternetFacing() ? 1 : 0
        };
    }
}
