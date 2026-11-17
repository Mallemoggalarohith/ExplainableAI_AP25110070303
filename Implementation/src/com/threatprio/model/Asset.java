package com.threatprio.model;

/** An organisational asset (impact side of the problem). Synthetic unless supplied by the organisation. */
public class Asset extends Identifiable {
    private final String name;
    private final AssetType type;
    private final int criticality;          // 1 (low) .. 5 (business critical)
    private final boolean internetFacing;

    public Asset(String assetId, String name, AssetType type, int criticality, boolean internetFacing) {
        super(assetId);
        if (criticality < 1 || criticality > 5) throw new IllegalArgumentException("criticality must be 1..5");
        this.name = name; this.type = type; this.criticality = criticality; this.internetFacing = internetFacing;
    }

    public String getName() { return name; }
    public AssetType getType() { return type; }
    public int getCriticality() { return criticality; }
    public boolean isInternetFacing() { return internetFacing; }

    @Override public String describe() { return name + " [" + type.getLabel() + ", crit " + criticality + "]"; }
}
