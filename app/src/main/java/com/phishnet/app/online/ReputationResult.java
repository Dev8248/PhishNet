package com.phishnet.app.online;

/** Answer from a {@link ReputationService}. */
public final class ReputationResult {
    public enum Verdict {
        /** The service has no record of the link. This is NOT a guarantee that it is safe. */
        NO_MATCH,
        /** The service lists the link as a known threat. */
        THREAT_MATCH,
        /** The service could not give a usable answer. */
        UNKNOWN
    }

    public final Verdict verdict;
    /** Short plain-language description, e.g. the threat type the service reported. May be empty. */
    public final String detail;

    private ReputationResult(Verdict verdict, String detail) {
        this.verdict = verdict;
        this.detail = detail == null ? "" : detail;
    }

    public static ReputationResult noMatch() { return new ReputationResult(Verdict.NO_MATCH, ""); }
    public static ReputationResult threat(String detail) { return new ReputationResult(Verdict.THREAT_MATCH, detail); }
    public static ReputationResult unknown(String detail) { return new ReputationResult(Verdict.UNKNOWN, detail); }
}
