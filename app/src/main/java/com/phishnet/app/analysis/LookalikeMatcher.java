package com.phishnet.app.analysis;

import java.text.Normalizer;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Heuristics for spoofed names: confusable characters, digit-for-letter swaps, typos and brand
 * names embedded in unrelated domains. These are indicators only and will have false positives
 * and false negatives; the brand list is short and built in.
 */
final class LookalikeMatcher {

    /** Maps common non-Latin look-alike letters to the Latin letter they imitate. */
    private static char confusable(char c) {
        switch (c) {
            // Cyrillic
            case '\u0430': return 'a';
            case '\u0441': return 'c';
            case '\u0435': return 'e';
            case '\u043E': return 'o';
            case '\u0440': return 'p';
            case '\u0445': return 'x';
            case '\u0443': return 'y';
            case '\u0456': return 'i';
            case '\u0458': return 'j';
            case '\u0455': return 's';
            case '\u0501': return 'd';
            case '\u04BB': return 'h';
            case '\u051B': return 'q';
            case '\u051D': return 'w';
            // Greek
            case '\u03BF': return 'o';
            case '\u03B1': return 'a';
            case '\u03B5': return 'e';
            case '\u03BD': return 'v';
            case '\u03B9': return 'i';
            case '\u03BA': return 'k';
            case '\u03C1': return 'p';
            case '\u03C4': return 't';
            case '\u03C5': return 'u';
            case '\u03C7': return 'x';
            case '\u03F2': return 'c';
            // Latin extended
            case '\u0131': return 'i';
            case '\u0261': return 'g';
            case '\u0251': return 'a';
            case '\u2113': return 'l';
            case '\u217C': return 'l';
            default: return c;
        }
    }

    /** NFKC-normalises (full-width forms etc.) and maps confusable letters to Latin. */
    static String skeleton(String label) {
        String n = Normalizer.normalize(label, Normalizer.Form.NFKC).toLowerCase(Locale.ROOT);
        StringBuilder b = new StringBuilder(n.length());
        for (int i = 0; i < n.length(); i++) {
            b.append(confusable(n.charAt(i)));
        }
        return b.toString();
    }

    private static boolean isAscii(String s) {
        for (int i = 0; i < s.length(); i++) {
            if (s.charAt(i) > 127) return false;
        }
        return true;
    }

    /** True when the label mixes letters from different scripts (e.g. Latin with Cyrillic). */
    static boolean isMixedScript(String label) {
        Set<Character.UnicodeScript> scripts = new HashSet<>();
        for (int i = 0; i < label.length(); ) {
            int cp = label.codePointAt(i);
            i += Character.charCount(cp);
            if (!Character.isLetter(cp)) continue;
            Character.UnicodeScript sc = Character.UnicodeScript.of(cp);
            if (sc != Character.UnicodeScript.COMMON && sc != Character.UnicodeScript.INHERITED) {
                scripts.add(sc);
            }
        }
        return scripts.size() > 1;
    }

    /** True when the label has non-ASCII letters that all collapse to plain Latin look-alikes. */
    static boolean usesConfusableLetters(String label) {
        if (isAscii(label)) return false;
        String sk = skeleton(label);
        return isAscii(sk) && !sk.equals(label.toLowerCase(Locale.ROOT));
    }

    /** Lower-case alphanumeric/hyphen tokens: "secure-paypal" gives [secure, paypal]. */
    static String[] tokens(String label) {
        return label.split("-");
    }

    /** Candidate spellings after undoing digit-for-letter swaps and rn/vv tricks. */
    private static List<String> leetVariants(String s) {
        List<String> out = new ArrayList<>(2);
        for (char one : new char[]{'l', 'i'}) {
            StringBuilder b = new StringBuilder(s.length());
            for (int i = 0; i < s.length(); i++) {
                char c = s.charAt(i);
                switch (c) {
                    case '0': b.append('o'); break;
                    case '1': b.append(one); break;
                    case '3': b.append('e'); break;
                    case '4': b.append('a'); break;
                    case '5': b.append('s'); break;
                    case '$': b.append('s'); break;
                    default: b.append(c);
                }
            }
            String v = b.toString().replace("rn", "m").replace("vv", "w");
            if (!out.contains(v)) out.add(v);
        }
        return out;
    }

    /** Optimal-string-alignment distance (insert, delete, replace, swap of neighbours). */
    static int editDistance(String a, String b) {
        int n = a.length(), m = b.length();
        int[][] d = new int[n + 1][m + 1];
        for (int i = 0; i <= n; i++) d[i][0] = i;
        for (int j = 0; j <= m; j++) d[0][j] = j;
        for (int i = 1; i <= n; i++) {
            for (int j = 1; j <= m; j++) {
                int cost = a.charAt(i - 1) == b.charAt(j - 1) ? 0 : 1;
                int v = Math.min(Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1), d[i - 1][j - 1] + cost);
                if (i > 1 && j > 1 && a.charAt(i - 1) == b.charAt(j - 2) && a.charAt(i - 2) == b.charAt(j - 1)) {
                    v = Math.min(v, d[i - 2][j - 2] + 1);
                }
                d[i][j] = v;
            }
        }
        return d[n][m];
    }

    /** True when a label imitates one of the brand's names without being it. */
    static boolean isLookalike(String label, BrandData.Brand brand) {
        String sk = skeleton(label);
        for (String token : tokens(sk)) {
            if (token.isEmpty()) continue;
            for (String name : brand.tokens) {
                if (token.equals(name)) {
                    // exact after skeleton: a look-alike only if the raw label was not already plain
                    if (!isAscii(label)) return true;
                    continue;
                }
                for (String v : leetVariants(token)) {
                    if (v.equals(name) && !token.equals(name)) return true;
                }
                if (name.length() >= 6 && token.length() >= 5 && Math.abs(token.length() - name.length()) <= 1
                        && editDistance(token, name) == 1) {
                    return true;
                }
            }
        }
        return false;
    }

    /** True when the label contains the brand name (whole hyphen-token for short names). */
    static boolean containsBrand(String label, BrandData.Brand brand) {
        String sk = skeleton(label);
        for (String name : brand.tokens) {
            if (name.length() >= 6) {
                if (sk.contains(name)) return true;
            } else {
                for (String t : tokens(sk)) {
                    if (t.equals(name)) return true;
                }
            }
        }
        return false;
    }

    private LookalikeMatcher() {}
}
