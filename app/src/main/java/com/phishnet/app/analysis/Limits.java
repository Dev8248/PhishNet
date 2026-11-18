package com.phishnet.app.analysis;

/** Hard bounds that keep analysis fast and the UI responsive on any input. */
public final class Limits {
    /** Maximum characters of pasted/shared/decoded text that are examined. */
    public static final int MAX_INPUT_CHARS = 20_000;
    /** Maximum number of distinct links offered for selection. */
    public static final int MAX_URLS = 25;
    /** Maximum characters of a single link that are parsed. */
    public static final int MAX_URL_CHARS = 4_096;
    /** Maximum characters of a link shown on screen. */
    public static final int MAX_DISPLAY_CHARS = 1_000;

    private Limits() {}
}
