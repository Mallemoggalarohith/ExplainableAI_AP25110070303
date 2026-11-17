package com.threatprio.data;

import com.threatprio.model.*;
import java.time.LocalDate;
import java.util.*;

/**
 * Generates a documented SYNTHETIC dataset (NVD/KEV/EPSS-like vulnerability signals + asset context).
 *
 * A hidden "true exploitability" factor h drives CVSS, exploit-code availability, KEV listing, EPSS and the
 * future exploitation label, so the observable signals are informative but imperfect. The label additionally
 * depends on exposure (internet-facing), patch availability, attack vector, noise and a mild upward drift over time
 * (to create temporal/class-distribution shift). Asset criticality is independent of exploitation: it only
 * determines impact. See Documentation/DATASET_DATASHEET.md for all assumptions.
 */
public final class SyntheticDataGenerator {
    public static final LocalDate SNAPSHOT = LocalDate.of(2025, 9, 30);
    private static final LocalDate START = LocalDate.of(2019, 1, 1), END = LocalDate.of(2025, 6, 30);

    private SyntheticDataGenerator() {}

    public static List<Asset> createAssetPool(int size, Random rnd) {
        double[] typeProb = {0.20, 0.15, 0.05, 0.35, 0.10, 0.15};  // WEB, DB, DC, WS, IOT, CLOUD
        double[] facing   = {0.85, 0.10, 0.02, 0.05, 0.30, 0.80};
        int[][] critRange = {{3, 4}, {3, 5}, {4, 5}, {1, 3}, {1, 3}, {3, 4}};
        AssetType[] types = AssetType.values();
        List<Asset> pool = new ArrayList<>();
        for (int i = 0; i < size; i++) {
            int t = sample(typeProb, rnd);
            int crit = critRange[t][0] + rnd.nextInt(critRange[t][1] - critRange[t][0] + 1);
            pool.add(new Asset(String.format("A-%04d", i + 1),
                types[t].name().toLowerCase().replace('_', '-') + "-" + String.format("%03d", i + 1),
                types[t], crit, rnd.nextDouble() < facing[t]));
        }
        return pool;
    }

    private static int sample(double[] p, Random rnd) {
        double u = rnd.nextDouble(), c = 0;
        for (int i = 0; i < p.length; i++) { c += p[i]; if (u < c) return i; }
        return p.length - 1;
    }
    private static double sig(double z) { return 1.0 / (1.0 + Math.exp(-z)); }

    public static List<Finding> generate(int n, long seed) {
        Random rnd = new Random(seed);
        List<Asset> assets = createAssetPool(Math.max(20, n / 5), rnd);
        long days = java.time.temporal.ChronoUnit.DAYS.between(START, END);
        Set<String> used = new HashSet<>();
        List<Finding> out = new ArrayList<>(n);
        for (int i = 0; i < n; i++) {
            LocalDate pub = START.plusDays((long) (rnd.nextDouble() * days));
            String cve;
            do { cve = String.format("CVE-%d-%05d", pub.getYear(), 1000 + rnd.nextInt(60000)); } while (!used.add(cve));

            double h = rnd.nextGaussian();
            double cvss = clamp(Math.round((6.3 + 1.3 * rnd.nextGaussian() + 0.5 * h) * 10) / 10.0, 1.0, 10.0);
            double avU = rnd.nextDouble();
            AttackVector av = avU < 0.62 ? AttackVector.NETWORK : avU < 0.72 ? AttackVector.ADJACENT
                            : avU < 0.97 ? AttackVector.LOCAL : AttackVector.PHYSICAL;
            boolean exploit = rnd.nextDouble() < sig(-1.7 + 1.2 * h + 0.10 * (cvss - 6));
            boolean kev = rnd.nextDouble() < sig(-3.6 + 1.0 * h + 1.3 * (exploit ? 1 : 0));
            double epss = clamp(sig(-4.0 + 1.3 * h + 0.9 * (exploit ? 1 : 0) + 0.6 * rnd.nextGaussian()), 0.0005, 0.999);
            boolean patch = rnd.nextDouble() < 0.72;
            double conf = clamp(0.55 + 0.20 * rnd.nextGaussian() + 0.12 * (kev ? 1 : 0), 0.05, 1.0);
            Asset asset = assets.get(rnd.nextInt(assets.size()));

            double drift = 0.18 * (pub.getYear() - 2022);   // injected temporal drift in exploitation rate
            double logit = -5.0 + 1.5 * h + 1.5 * (kev ? 1 : 0) + 0.9 * (exploit ? 1 : 0) + 0.15 * (cvss - 6)
                         + 0.8 * (asset.isInternetFacing() ? 1 : 0) + 0.5 * (av == AttackVector.NETWORK ? 1 : 0)
                         - 0.4 * (patch ? 1 : 0) + drift + 0.5 * rnd.nextGaussian();
            boolean exploited = rnd.nextDouble() < sig(logit);

            Vulnerability v = new Vulnerability(cve, pub, cvss, av, round(epss, 4), kev, exploit, patch, round(conf, 3));
            out.add(new Finding(v, asset, SNAPSHOT, exploited));
        }
        return out;
    }

    private static double clamp(double v, double lo, double hi) { return Math.max(lo, Math.min(hi, v)); }
    private static double round(double v, int dp) { double s = Math.pow(10, dp); return Math.round(v * s) / s; }
}
