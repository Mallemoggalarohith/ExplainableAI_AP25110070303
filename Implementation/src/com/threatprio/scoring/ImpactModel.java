package com.threatprio.scoring;

import com.threatprio.model.Asset;

/** Organisational impact, kept separate from exploitation probability: risk = P(exploit) x impact. */
public final class ImpactModel {
    private ImpactModel() {}
    public static double impact(Asset a) { return a.getCriticality() / 5.0; }
}
