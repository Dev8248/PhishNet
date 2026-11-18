package com.phishnet.app.analysis;

import java.io.ByteArrayOutputStream;
import java.net.IDN;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Lenient, bounded URL parser written for security analysis. It never opens, resolves or fetches
 * anything, and it never throws on bad input: problems are reported through {@link ParsedUrl}.
 *
 * It deliberately does not use android.net.Uri so that the same code runs in plain JVM unit tests.
 */
public final class UrlParser {
    private static final Pattern SCHEME = Pattern.compile("^([A-Za-z][A-Za-z0-9+.\\-]{0,19}):");
    private static final Pattern PORT_START = Pattern.compile("^\\d{1,5}(?:[/?#\\\\]|$)");
    private static final Pattern PLAIN_OCTET = Pattern.compile("(?:0|[1-9]\\d{0,2})");
    private static final Pattern DECIMAL = Pattern.compile("\\d+");
    private static final Pattern HEX = Pattern.compile("0[xX][0-9a-fA-F]*");

    public static ParsedUrl parse(String input) {
        ParsedUrl u = new ParsedUrl();
        if (input == null) {
            return fail(u, "There is nothing to analyse.");
        }
        String s = input.trim();
        if (s.length() >= 2 && ((s.charAt(0) == '<' && s.charAt(s.length() - 1) == '>')
                || (s.charAt(0) == '"' && s.charAt(s.length() - 1) == '"'))) {
            s = s.substring(1, s.length() - 1).trim();
        }
        if (s.isEmpty()) {
            return fail(u, "There is nothing to analyse.");
        }
        if (s.length() > Limits.MAX_URL_CHARS) {
            s = s.substring(0, Limits.MAX_URL_CHARS);
            u.truncated = true;
        }
        u.raw = s;

        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (Character.isWhitespace(c) || Character.isSpaceChar(c)) {
                return fail(u, "A link can't contain spaces or line breaks.");
            }
            if (Character.isISOControl(c)) u.hasControl = true;
            if (isInvisible(c)) u.hasInvisible = true;
            if (c == '\\') u.hasBackslash = true;
        }

        String rest;
        Matcher m = SCHEME.matcher(s);
        boolean hasScheme = false;
        if (m.find()) {
            String after = s.substring(m.end());
            String first = m.group(1);
            boolean hostLike = first.indexOf('.') >= 0 || "localhost".equalsIgnoreCase(first);
            if (hostLike && PORT_START.matcher(after).find()) {
                hasScheme = false; // "example.com:8080/x" is host:port, not a scheme
            } else {
                hasScheme = true;
                String sch = m.group(1).toLowerCase(Locale.ROOT);
                u.scheme = sch;
                if (after.startsWith("//") || after.startsWith("\\\\")) {
                    rest = after.substring(2);
                    return parseAfterScheme(u, rest);
                }
                if (isOpaqueScheme(sch)) {
                    u.opaque = true;
                    u.path = after;
                    u.valid = true;
                    return u;
                }
                if (after.startsWith("/") || after.startsWith("\\")) {
                    u.oddSlashes = true;
                    int i = 0;
                    while (i < after.length() && (after.charAt(i) == '/' || after.charAt(i) == '\\')) i++;
                    return parseAfterScheme(u, after.substring(i));
                }
                if ("http".equals(sch) || "https".equals(sch) || "ftp".equals(sch)) {
                    u.oddSlashes = true;
                    return parseAfterScheme(u, after);
                }
                return fail(u, "This doesn't look like a web link. PhishNet checks web links (http or https).");
            }
        }
        if (!hasScheme) {
            u.scheme = "https";
            u.schemeAssumed = true;
            rest = s.startsWith("//") ? s.substring(2) : s;
            return parseAfterScheme(u, rest);
        }
        return fail(u, "This doesn't look like a web link.");
    }

    private static ParsedUrl parseAfterScheme(ParsedUrl u, String rest) {
        int end = rest.length();
        for (int i = 0; i < rest.length(); i++) {
            char c = rest.charAt(i);
            if (c == '/' || c == '?' || c == '#' || c == '\\') {
                end = i;
                break;
            }
        }
        String authority = rest.substring(0, end);
        String tail = rest.substring(end);

        // path / query / fragment
        String frag = "";
        int h = tail.indexOf('#');
        if (h >= 0) {
            frag = tail.substring(h + 1);
            tail = tail.substring(0, h);
        }
        String query = "";
        int q = tail.indexOf('?');
        if (q >= 0) {
            query = tail.substring(q + 1);
            tail = tail.substring(0, q);
        }
        u.path = tail.replace('\\', '/');
        u.query = query;
        u.fragment = frag;

        // userinfo: browsers use the LAST '@' to split
        String hostPort = authority;
        int at = authority.lastIndexOf('@');
        for (int i = 0; i < authority.length(); i++) {
            if (authority.charAt(i) == '@') u.atCount++;
        }
        if (at >= 0) {
            u.userInfo = authority.substring(0, at);
            hostPort = authority.substring(at + 1);
        }

        String hostPart = hostPort;
        if (hostPort.startsWith("[")) {
            int close = hostPort.indexOf(']');
            if (close < 0) {
                return fail(u, "The website address has an unclosed bracket.");
            }
            hostPart = hostPort.substring(0, close + 1);
            String after = hostPort.substring(close + 1);
            if (!after.isEmpty()) {
                if (!after.startsWith(":") || !setPort(u, after.substring(1))) {
                    return fail(u, "The website address has an invalid port.");
                }
            }
            u.host = hostPart.toLowerCase(Locale.ROOT);
            u.unicodeHost = u.host;
            u.ipKind = ParsedUrl.IpKind.IPV6;
            u.valid = true;
            return u;
        }
        int colon = hostPort.lastIndexOf(':');
        if (colon >= 0) {
            hostPart = hostPort.substring(0, colon);
            if (!setPort(u, hostPort.substring(colon + 1))) {
                return fail(u, "The website address has an invalid port.");
            }
        }
        if (hostPart.indexOf(':') >= 0) {
            return fail(u, "The website address contains characters that can't be used.");
        }

        if (hostPart.indexOf('%') >= 0) {
            u.hostPercentEncoded = true;
            hostPart = percentDecode(hostPart);
        }
        String host = hostPart.toLowerCase(Locale.ROOT);
        while (host.endsWith(".")) {
            host = host.substring(0, host.length() - 1);
        }
        if (host.isEmpty()) {
            return fail(u, "The link has no website address.");
        }

        String ascii = host;
        if (!isAscii(host)) {
            try {
                ascii = IDN.toASCII(host, IDN.ALLOW_UNASSIGNED).toLowerCase(Locale.ROOT);
            } catch (IllegalArgumentException e) {
                return fail(u, "The website name contains characters that can't be used in a domain name.");
            }
        }
        u.host = ascii;
        u.unicodeHost = IDN.toUnicode(ascii, IDN.ALLOW_UNASSIGNED);

        for (int i = 0; i < ascii.length(); i++) {
            char c = ascii.charAt(i);
            boolean ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '-';
            if (!ok) u.badHostChars = true;
        }
        if (ascii.startsWith(".") || ascii.contains("..")) {
            u.emptyLabel = true;
        }
        u.ipKind = detectIp(ascii);
        u.valid = true;
        return u;
    }

    private static boolean setPort(ParsedUrl u, String p) {
        if (p.isEmpty()) {
            return true;
        }
        if (p.length() > 5 || !DECIMAL.matcher(p).matches()) {
            return false;
        }
        int v = Integer.parseInt(p);
        if (v > 65535) {
            return false;
        }
        u.port = v;
        return true;
    }

    /** Detects plain and obfuscated (decimal, hex, octal, short-form) IPv4 host names. */
    static ParsedUrl.IpKind detectIp(String host) {
        String[] parts = host.split("\\.", -1);
        if (parts.length == 0 || parts.length > 4) {
            return ParsedUrl.IpKind.NONE;
        }
        String last = parts[parts.length - 1];
        boolean numericLast = DECIMAL.matcher(last).matches() || HEX.matcher(last).matches();
        if (!numericLast) {
            return ParsedUrl.IpKind.NONE;
        }
        boolean plain = parts.length == 4;
        for (String p : parts) {
            if (p.isEmpty()) {
                return ParsedUrl.IpKind.NONE;
            }
            boolean numeric = DECIMAL.matcher(p).matches() || HEX.matcher(p).matches();
            if (!numeric) {
                return ParsedUrl.IpKind.NONE;
            }
            if (!(PLAIN_OCTET.matcher(p).matches() && Integer.parseInt(p) <= 255)) {
                plain = false;
            }
        }
        return plain ? ParsedUrl.IpKind.IPV4 : ParsedUrl.IpKind.IPV4_OBFUSCATED;
    }

    private static boolean isOpaqueScheme(String s) {
        return "javascript".equals(s) || "vbscript".equals(s) || "data".equals(s);
    }

    private static boolean isAscii(String s) {
        for (int i = 0; i < s.length(); i++) {
            if (s.charAt(i) > 127) return false;
        }
        return true;
    }

    static boolean isInvisible(char c) {
        return c == '\u00AD' || (c >= '\u200B' && c <= '\u200F') || (c >= '\u2028' && c <= '\u202E')
                || (c >= '\u2060' && c <= '\u2064') || (c >= '\u2066' && c <= '\u2069') || c == '\uFEFF';
    }

    static String percentDecode(String s) {
        if (s.indexOf('%') < 0) return s;
        ByteArrayOutputStream out = new ByteArrayOutputStream(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '%' && i + 2 < s.length()) {
                int hi = Character.digit(s.charAt(i + 1), 16);
                int lo = Character.digit(s.charAt(i + 2), 16);
                if (hi >= 0 && lo >= 0) {
                    out.write(hi * 16 + lo);
                    i += 2;
                    continue;
                }
            }
            int cp = s.codePointAt(i);
            byte[] b = new String(Character.toChars(cp)).getBytes(StandardCharsets.UTF_8);
            out.write(b, 0, b.length);
            i += Character.charCount(cp) - 1;
        }
        return new String(out.toByteArray(), StandardCharsets.UTF_8);
    }

    private static ParsedUrl fail(ParsedUrl u, String problem) {
        u.valid = false;
        u.problem = problem;
        return u;
    }

    /**
     * Text safe to show on screen: invisible, bidirectional and control characters are replaced
     * by visible markers such as {@code <U+202E>}, and very long text is shortened.
     */
    public static String visible(String s, int max) {
        if (s == null) return "";
        StringBuilder b = new StringBuilder(Math.min(s.length(), max) + 16);
        int shown = 0;
        int i = 0;
        for (; i < s.length() && shown < max; i++) {
            char c = s.charAt(i);
            if (isInvisible(c) || Character.isISOControl(c)) {
                b.append(String.format(Locale.ROOT, "<U+%04X>", (int) c));
            } else {
                b.append(c);
            }
            shown++;
        }
        if (i < s.length()) {
            b.append("\u2026 (+").append(s.length() - i).append(" more characters)");
        }
        return b.toString();
    }

    private UrlParser() {}
}
