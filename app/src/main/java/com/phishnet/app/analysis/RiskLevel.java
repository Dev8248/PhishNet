package com.phishnet.app.analysis;

/** The three result levels. The written label is always shown next to any colour. */
public enum RiskLevel {
    APPEARS_SAFE("Appears Safe"),
    SUSPICIOUS("Suspicious"),
    HIGH_RISK("High Risk"),
    NOT_SAFE("Not Safe");

    private final String label;

    RiskLevel(String label) {
        this.label = label;
    }

    public String label() {
        return label;
    }
}
