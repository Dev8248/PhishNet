package com.phishnet.app.analysis;

/** One piece of evidence. Findings are indicators, never proof. */
public final class Finding {
    public enum Source { URL, MESSAGE, ONLINE }

    public final String id;
    public final String title;
    public final String detail;
    public final int points;
    public final Source source;

    public Finding(String id, String title, String detail, int points, Source source) {
        this.id = id;
        this.title = title;
        this.detail = detail;
        this.points = points;
        this.source = source;
    }
}
