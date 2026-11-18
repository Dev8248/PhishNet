package com.phishnet.app.analysis;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Offline indicators computed from the link alone. Every rule adds a {@link Finding} with points.
 * See README.md for the full rule table. These are indicators, not proof.
 */
final class UrlRules {
    private static final Set<String> DANGEROUS_SCHEMES = new HashSet<>(Arrays.asList(
            "file", "intent", "javascript", "vbscript", "data", "blob", "content", "android-app"));

    private static final String[] SENSITIVE_WORDS = {
            "login", "signin", "sign-in", "logon", "verify", "verification", "secure", "security", "account",
            "update", "confirm", "password", "passcode", "wallet", "bank", "banking", "payment", "billing",
            "invoice", "otp", "kyc", "suspend", "suspended", "unlock", "recover", "recovery", "authenticate",
            "validate", "support", "refund", "claim", "reward", "prize", "alert", "unusual"};

    static void apply(ParsedUrl p, List<Finding> out, List<String> incomplete) {
        if (p.truncated) {
            incomplete.add("This link is very long, so only its first " + Limits.MAX_URL_CHARS
                    + " characters were analysed.");
        }
        if (p.opaque) {
            add(out, "SCHEME-OPAQUE", "Not a web page: runs code or embeds content",
                    "Links that start with \"" + p.scheme + ":\" are not normal web pages. They can run script or carry "
                            + "embedded content, and no genuine message needs one.", 60);
            hidden(p, out);
            return;
        }
        scheme(p, out);
        syntax(p, out);
        hidden(p, out);
        credentials(p, out);
        network(p, out);
        if (p.ipKind == ParsedUrl.IpKind.NONE) {
            domain(p, out, incomplete);
        }
        encoding(p, out);
        nestedLink(p, out);
    }

    private static void add(List<Finding> out, String id, String title, String detail, int points) {
        out.add(new Finding(id, title, detail, points, Finding.Source.URL));
    }

    private static void scheme(ParsedUrl p, List<Finding> out) {
        String s = p.scheme;
        if (p.schemeAssumed) {
            add(out, "SCHEME-MISSING", "No http:// or https:// at the start",
                    "The text had no scheme, so it was analysed as https://. Check that the real link starts the way you expect.", 0);
        } else if ("http".equals(s)) {
            add(out, "SCHEME-HTTP", "Connection is not encrypted",
                    "The link uses plain http, so anyone on the network path can read or alter what is sent, including anything typed into a page.", 20);
        } else if (!"https".equals(s)) {
            if (DANGEROUS_SCHEMES.contains(s)) {
                add(out, "SCHEME-DANGEROUS", "Not a normal web link",
                        "\"" + s + ":\" links can open apps or files, or run code, instead of loading a web page.", 60);
            } else {
                add(out, "SCHEME-ODD", "Unusual link type",
                        "The link type \"" + s + ":\" is not an ordinary web (https) link.", 25);
            }
        }
    }

    private static void syntax(ParsedUrl p, List<Finding> out) {
        List<String> issues = new ArrayList<>();
        if (p.oddSlashes) issues.add("missing or wrong slashes after the scheme");
        if (p.hasBackslash) issues.add("backslashes");
        if (p.atCount > 1) issues.add("more than one @");
        if (p.emptyLabel) issues.add("empty parts in the website name");
        if (p.badHostChars) issues.add("unusual characters in the website name");
        if (!issues.isEmpty()) {
            add(out, "SYNTAX-ODD", "Unusual link syntax",
                    "The link has " + String.join(", ", issues)
                            + ". Browsers can interpret such tricks differently from how they look.",
                    p.badHostChars ? 15 : 10);
        }
    }

    private static void hidden(ParsedUrl p, List<Finding> out) {
        if (p.hasInvisible || p.hasControl) {
            add(out, "SYNTAX-HIDDEN", "Hidden characters in the link",
                    "The link contains invisible or text-direction characters that can make it look different from where it "
                            + "really goes. They are shown as <U+XXXX> in the address below.", 30);
        }
    }

    private static void credentials(ParsedUrl p, List<Finding> out) {
        if (p.userInfo == null || p.userInfo.isEmpty()) return;
        String ui = p.userInfo.toLowerCase(Locale.ROOT);
        String real = UrlParser.visible(p.host, 120);
        if (ui.contains(".") || ui.contains("http") || ui.contains("www")) {
            add(out, "AUTH-AT-DECEPTIVE", "Misleading \"@\" in the link",
                    "Everything before the @ is ignored when choosing where the link goes. Here it looks like a website name "
                            + "placed to mislead. The real destination is " + real + ".", 55);
        } else {
            add(out, "AUTH-CREDENTIALS", "Login details inside the link",
                    "The link contains a user name or password before the @. Real sites almost never do this and it is a "
                            + "known disguise. The real destination is " + real + ".", 35);
        }
    }

    private static void network(ParsedUrl p, List<Finding> out) {
        switch (p.ipKind) {
            case IPV4:
                add(out, "HOST-IP", "Address is a raw IP number",
                        "Genuine services almost always use a domain name. Links to bare IP addresses are common in scams.", 35);
                break;
            case IPV4_OBFUSCATED:
                add(out, "HOST-IP-OBFUSCATED", "Address is a disguised IP number",
                        "The address is an IP number written in an unusual form (decimal, hex or octal) that hides what it is.", 45);
                break;
            case IPV6:
                add(out, "HOST-IPV6", "Address is a raw IPv6 number",
                        "Genuine services almost always use a domain name.", 35);
                break;
            default:
                break;
        }
        if (p.port != -1) {
            boolean normal = (p.port == 443 && "https".equals(p.scheme)) || (p.port == 80 && "http".equals(p.scheme));
            if (!normal) {
                boolean common = p.port == 8080 || p.port == 8443;
                add(out, "HOST-PORT", "Unusual port number",
                        "The link uses port " + p.port + ". Ordinary sites use the default port.", common ? 8 : 15);
            }
        }
    }

    private static void domain(ParsedUrl p, List<Finding> out, List<String> incomplete) {
        String host = p.host;
        String[] labels = HostUtils.labels(host);
        if (labels.length == 0) return;
        String[] uLabels = HostUtils.labels(p.unicodeHost);
        String registrable = HostUtils.registrableDomain(host);
        int suffixCount = HostUtils.suffixLabelCount(labels);
        int sldIndex = Math.max(0, labels.length - suffixCount - 1);
        boolean official = BrandData.isOfficialAny(registrable);
        String tld = labels[labels.length - 1];

        // Internationalised names
        boolean puny = false;
        for (String l : labels) {
            if (l.startsWith("xn--")) puny = true;
        }
        if (puny) {
            add(out, "HOST-PUNYCODE", "Internationalised (punycode) domain name",
                    "The name is stored as punycode and displays as \"" + UrlParser.visible(p.unicodeHost, 120)
                            + "\". Such names are sometimes used to imitate familiar sites.", 25);
        }
        for (String l : uLabels) {
            if (LookalikeMatcher.isMixedScript(l)) {
                add(out, "HOST-MIXED-SCRIPT", "Mixed alphabets in one name",
                        "A part of the name mixes letters from different alphabets (for example Latin and Cyrillic), "
                                + "a classic way to fake a familiar name.", 35);
                break;
            }
        }
        for (String l : uLabels) {
            if (LookalikeMatcher.usesConfusableLetters(l)) {
                add(out, "HOST-CONFUSABLE", "Look-alike letters",
                        "Some characters in the name are non-Latin letters that look like Latin ones.", 30);
                break;
            }
        }

        // Shape of the name
        if (sldIndex >= 4) {
            add(out, "HOST-SUBDOMAINS", "Many subdomains",
                    "The name has " + sldIndex + " parts before the main domain, which can hide the real owner "
                            + "(" + registrable + ").", 15);
        }
        if (host.length() > 50) {
            add(out, "HOST-LONG", "Very long website name",
                    "Long names are used to push the real domain out of sight on small screens.", 10);
        }
        int hyphens = 0;
        for (int i = 0; i < host.length(); i++) {
            if (host.charAt(i) == '-') hyphens++;
        }
        if (hyphens >= 3) {
            add(out, "HOST-HYPHENS", "Many hyphens in the name",
                    "Names stuffed with hyphens are a common pattern for throwaway scam domains.", 10);
        }
        if (!official && BrandData.SUSPICIOUS_TLDS.contains(tld)) {
            add(out, "HOST-TLD", "Frequently abused domain ending",
                    "\"." + tld + "\" is cheap and frequently used for scams. Many legitimate sites use it too.", 10);
        }
        for (String d : BrandData.FREE_HOSTS) {
            if (host.equals(d) || host.endsWith("." + d)) {
                add(out, "HOST-FREEHOST", "Free hosting or tunnelling service",
                        "Anyone can publish a page on " + d + ", so the name tells you nothing about who made it.", 10);
                break;
            }
        }
        for (int i = 1; i < sldIndex; i++) {
            if (BrandData.TLD_WORDS.contains(labels[i])) {
                add(out, "HOST-FAKE-TLD", "Domain-like text inside a subdomain",
                        "The name contains \".\"" + labels[i] + "\" before the real domain (" + registrable
                                + "), which is meant to look like a different site.", 20);
                break;
            }
        }

        // Shorteners
        if (BrandData.SHORTENERS.contains(registrable) || BrandData.SHORTENERS.contains(host)) {
            add(out, "HOST-SHORTENER", "Link shortener hides the destination",
                    registrable + " forwards to another address that cannot be seen from the link itself.", 20);
            incomplete.add("This is a shortened link. PhishNet cannot see where it leads without contacting it, "
                    + "which it deliberately never does.");
        }

        // Brands
        boolean brandFound = false;
        outer:
        for (BrandData.Brand b : BrandData.BRANDS) {
            if (b.isOfficial(registrable)) continue;
            for (String o : b.exactOfficial()) {
                if (o.length() >= 7 && (host.startsWith(o + ".") || host.contains("." + o + "."))) {
                    add(out, "BRAND-REAL-DOMAIN-INSIDE", "A real site's address appears inside this name",
                            "The name contains \"" + o + "\" but belongs to " + registrable
                                    + ". Only the end of a name decides who owns it.", 55);
                    brandFound = true;
                    break outer;
                }
            }
        }
        if (!brandFound) {
            int last = Math.min(sldIndex, uLabels.length - 1);
            outer2:
            for (BrandData.Brand b : BrandData.BRANDS) {
                if (b.isOfficial(registrable)) continue;
                for (int i = 0; i <= last; i++) {
                    if (LookalikeMatcher.isLookalike(uLabels[i], b)) {
                        add(out, "BRAND-LOOKALIKE", "Looks like a copy of the " + b.display + " name",
                                "\"" + UrlParser.visible(uLabels[i], 80) + "\" imitates " + b.display
                                        + " using look-alike characters or a small misspelling, but the site belongs to "
                                        + registrable + ".", 50);
                        brandFound = true;
                        break outer2;
                    }
                }
                for (int i = 0; i <= last; i++) {
                    if (LookalikeMatcher.containsBrand(uLabels[i], b)) {
                        if (i < sldIndex) {
                            add(out, "BRAND-SUBDOMAIN", b.display + " name used as a subdomain",
                                    "\"" + b.display + "\" appears at the start of the name, but the site belongs to "
                                            + registrable + ", not " + b.display + ".", 50);
                        } else {
                            add(out, "BRAND-IN-DOMAIN", b.display + " name inside an unrelated domain",
                                    "The domain " + registrable + " contains the name " + b.display
                                            + " but is not a known " + b.display + " domain.", 45);
                        }
                        brandFound = true;
                        break outer2;
                    }
                }
            }
        }

        if (official) return; // keyword and path heuristics add noise on well-known first-party domains

        // Sensitive words
        StringBuilder hostBody = new StringBuilder();
        for (int i = 0; i <= sldIndex && i < labels.length; i++) {
            if (hostBody.length() > 0) hostBody.append('.');
            hostBody.append(labels[i]);
        }
        Set<String> hostWords = new LinkedHashSet<>();
        for (String w : SENSITIVE_WORDS) {
            if (containsWord(hostBody.toString(), w, w.length() > 4)) hostWords.add(w);
        }
        if (!hostWords.isEmpty()) {
            add(out, "KEYWORD-HOST", "Sensitive words in the website name",
                    "The name contains " + quote(hostWords) + ". Scam sites often put words like these in the name to look official.",
                    Math.min(24, 8 * hostWords.size()));
        }
        String pq = (UrlParser.percentDecode(p.path) + " " + UrlParser.percentDecode(p.query)).toLowerCase(Locale.ROOT);
        String[] pathTokens = pq.split("[^a-z0-9]+");
        Set<String> pathWords = new LinkedHashSet<>();
        for (String w : SENSITIVE_WORDS) {
            for (String t : pathTokens) {
                if (t.equals(w)) pathWords.add(w);
            }
        }
        if (!pathWords.isEmpty()) {
            add(out, "KEYWORD-PATH", "Sensitive words in the page address",
                    "The page address contains " + quote(pathWords) + ". This is common on genuine sites too, so it counts for little on its own.",
                    Math.min(9, 3 * pathWords.size()));
        }
        if (!brandFound) {
            pathBrand:
            for (BrandData.Brand b : BrandData.BRANDS) {
                for (String t : pathTokens) {
                    if (t.isEmpty()) continue;
                    for (String name : b.tokens) {
                        if (t.equals(name) || (name.length() >= 6 && t.contains(name))) {
                            add(out, "BRAND-IN-PATH", b.display + " name in the page address of another site",
                                    "The page address mentions " + b.display + " but the site belongs to " + registrable + ".", 10);
                            break pathBrand;
                        }
                    }
                }
            }
        }
    }

    private static void encoding(ParsedUrl p, List<Finding> out) {
        if (p.hostPercentEncoded) {
            add(out, "ENC-HOST", "Website name is percent-encoded",
                    "Website names are never encoded in genuine links. This hides the real name from a quick look.", 30);
        }
        String pq = p.path + "?" + p.query;
        int plain = 0;
        int doubles = 0;
        for (int i = 0; i + 2 < pq.length(); i++) {
            if (pq.charAt(i) != '%') continue;
            int hi = Character.digit(pq.charAt(i + 1), 16);
            int lo = Character.digit(pq.charAt(i + 2), 16);
            if (hi < 0 || lo < 0) continue;
            int v = hi * 16 + lo;
            if ((v >= 'a' && v <= 'z') || (v >= 'A' && v <= 'Z') || (v >= '0' && v <= '9')) plain++;
            if (v == '%' && i + 4 < pq.length()
                    && Character.digit(pq.charAt(i + 3), 16) >= 0 && Character.digit(pq.charAt(i + 4), 16) >= 0) {
                doubles++;
            }
        }
        if (plain >= 3) {
            add(out, "ENC-LETTERS", "Ordinary letters are percent-encoded",
                    "Encoding plain letters and digits (such as %61 for \"a\") has no normal purpose except hiding text.", 15);
        }
        if (doubles > 0) {
            add(out, "ENC-DOUBLE", "Double-encoded text",
                    "The link is encoded twice, a trick used to slip past filters.", 10);
        }
        int len = p.raw.length();
        if (len > 2000) {
            add(out, "SHAPE-LONG", "Very long link",
                    "The link is " + len + " characters long, which can hide its destination or carry tracking and payload data.", 15);
        } else if (len > 1000) {
            add(out, "SHAPE-LONG", "Long link",
                    "The link is " + len + " characters long.", 8);
        }
    }

    private static void nestedLink(ParsedUrl p, List<Finding> out) {
        if (p.query.isEmpty()) return;
        for (String pair : p.query.split("&", 50)) {
            int eq = pair.indexOf('=');
            if (eq < 0) continue;
            String v = UrlParser.percentDecode(pair.substring(eq + 1)).toLowerCase(Locale.ROOT);
            if (v.startsWith("http://") || v.startsWith("https://") || v.startsWith("//")) {
                add(out, "URL-NESTED", "Link contains another link",
                        "A parameter holds a second web address. Redirect-style links can send you to a different site than the one shown.", 15);
                return;
            }
        }
    }

    private static boolean containsWord(String text, String word, boolean substring) {
        if (substring) return text.contains(word);
        for (String t : text.split("[^a-z0-9]+")) {
            if (t.equals(word)) return true;
        }
        return false;
    }

    private static String quote(Set<String> words) {
        List<String> q = new ArrayList<>();
        int n = 0;
        for (String w : words) {
            if (n++ >= 4) break;
            q.add("\"" + w + "\"");
        }
        return String.join(", ", q);
    }

    private UrlRules() {}
}
