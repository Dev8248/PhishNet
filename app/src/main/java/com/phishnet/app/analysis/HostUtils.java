package com.phishnet.app.analysis;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Small host helpers. Without a full public-suffix list (which would need regular updates), a short
 * built-in set of common multi-part suffixes is used. Unknown suffixes are treated as one label.
 */
public final class HostUtils {
    private static final Set<String> MULTI_PART_SUFFIXES = new HashSet<>(Arrays.asList(
            "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk",
            "com.au", "net.au", "org.au", "edu.au", "gov.au",
            "co.in", "net.in", "org.in", "ac.in", "gov.in", "edu.in", "res.in", "nic.in",
            "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
            "com.br", "net.br", "org.br", "gov.br",
            "com.cn", "net.cn", "org.cn", "gov.cn",
            "com.mx", "com.tr", "org.tr", "com.sg", "com.hk", "com.tw", "com.my", "com.ph",
            "com.pk", "com.bd", "com.ng", "com.eg", "com.sa", "com.ar", "com.co", "com.pe",
            "co.za", "co.nz", "co.kr", "co.id", "co.il", "co.th", "co.ke"));

    /** Non-empty labels of a host. */
    static String[] labels(String host) {
        List<String> out = new ArrayList<>();
        for (String l : host.split("\\.")) {
            if (!l.isEmpty()) out.add(l);
        }
        return out.toArray(new String[0]);
    }

    /** Number of labels in the public suffix (1 for "com", 2 for "co.uk"). */
    static int suffixLabelCount(String[] labels) {
        int n = labels.length;
        if (n >= 3 && MULTI_PART_SUFFIXES.contains(labels[n - 2] + "." + labels[n - 1])) {
            return 2;
        }
        return 1;
    }

    /** Registrable domain, e.g. "mail.example.co.uk" gives "example.co.uk". */
    public static String registrableDomain(String host) {
        String[] labels = labels(host);
        int n = labels.length;
        if (n <= 2) {
            return String.join(".", labels);
        }
        int keep = suffixLabelCount(labels) + 1;
        StringBuilder b = new StringBuilder();
        for (int i = n - keep; i < n; i++) {
            if (b.length() > 0) b.append('.');
            b.append(labels[i]);
        }
        return b.toString();
    }

    /** The public suffix, e.g. "co.uk" or "com". */
    static String publicSuffix(String host) {
        String[] labels = labels(host);
        int n = labels.length;
        int k = Math.min(suffixLabelCount(labels), n);
        StringBuilder b = new StringBuilder();
        for (int i = n - k; i < n; i++) {
            if (b.length() > 0) b.append('.');
            b.append(labels[i]);
        }
        return b.toString();
    }

    private HostUtils() {}
}
