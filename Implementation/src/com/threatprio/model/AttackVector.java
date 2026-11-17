package com.threatprio.model;

/** CVSS attack vector with the numeric exploitability weight used as a model feature. */
public enum AttackVector {
    NETWORK(1.00), ADJACENT(0.62), LOCAL(0.55), PHYSICAL(0.20);

    private final double score;
    AttackVector(double score) { this.score = score; }
    public double getScore() { return score; }

    public static AttackVector parse(String s) {
        if (s == null) return NETWORK;
        String u = s.trim().toUpperCase().replace("ADJACENT_NETWORK", "ADJACENT");
        for (AttackVector v : values()) if (v.name().equals(u)) return v;
        return NETWORK;
    }
}
