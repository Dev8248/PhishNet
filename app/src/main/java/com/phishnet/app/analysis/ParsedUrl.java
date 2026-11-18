package com.phishnet.app.analysis;

/** Result of {@link UrlParser#parse}. Fields are filled by the parser only. */
public final class ParsedUrl {
    public enum IpKind { NONE, IPV4, IPV4_OBFUSCATED, IPV6 }

    public boolean valid;
    /** Plain-language reason when {@link #valid} is false. */
    public String problem;

    /** Trimmed input, cut to {@link Limits#MAX_URL_CHARS}. */
    public String raw = "";
    public boolean truncated;

    /** Lower-case scheme; "https" when the text had none (see {@link #schemeAssumed}). */
    public String scheme = "";
    public boolean schemeAssumed;
    /** javascript:, vbscript: or data: style link without an authority. */
    public boolean opaque;
    /** Missing or wrong slashes, e.g. "http:/example.com" or "http:\\example.com". */
    public boolean oddSlashes;

    /** Text before the last '@' in the authority, or null. */
    public String userInfo;
    public int atCount;

    /** ASCII host, lower-case, punycode form, no trailing dot. IPv6 keeps its brackets. */
    public String host = "";
    /** Unicode form of the host for display and look-alike checks. */
    public String unicodeHost = "";
    public IpKind ipKind = IpKind.NONE;
    public boolean hostPercentEncoded;
    public boolean badHostChars;
    public boolean emptyLabel;
    /** -1 when absent. */
    public int port = -1;

    public String path = "";
    public String query = "";
    public String fragment = "";

    public boolean hasInvisible;
    public boolean hasControl;
    public boolean hasBackslash;

    /** The link used for copy/open/online checks: raw, with https:// added if no scheme was given. */
    public String normalized() {
        if (!schemeAssumed) {
            return raw;
        }
        String r = raw;
        while (r.startsWith("/")) {
            r = r.substring(1);
        }
        return "https://" + r;
    }

    public boolean isWebScheme() {
        return "http".equals(scheme) || "https".equals(scheme);
    }
}
