package com.threatprio.model;

/** Kinds of (synthetic) organisational assets. */
public enum AssetType {
    WEB_SERVER("Web Server"), DATABASE("Database"), DOMAIN_CONTROLLER("Domain Controller"),
    WORKSTATION("Workstation"), IOT_DEVICE("IoT Device"), CLOUD_API("Cloud API");

    private final String label;
    AssetType(String label) { this.label = label; }
    public String getLabel() { return label; }

    public static AssetType parse(String s) {
        for (AssetType t : values()) if (t.name().equalsIgnoreCase(s) || t.label.equalsIgnoreCase(s)) return t;
        return WORKSTATION;
    }
}
