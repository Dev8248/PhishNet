package com.phishnet.app.online;

import com.phishnet.app.analysis.Finding;
import com.phishnet.app.analysis.HostUtils;
import com.phishnet.app.analysis.ParsedUrl;
import com.phishnet.app.analysis.UrlParser;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Executes a controlled HTTP request to analyze redirects and initial page content.
 * Used for Checks 32-39.
 */
public final class RedirectAnalyzer {
    private static final int MAX_REDIRECTS = 5;
    private static final int MAX_BODY_SIZE = 100 * 1024; // 100 KB
    private static final int TIMEOUT_MS = 5000;

    public static List<Finding> analyze(String startUrl) {
        List<Finding> findings = new ArrayList<>();
        String currentUrl = startUrl;
        int redirectCount = 0;
        boolean crossDomain = false;

        ParsedUrl originalParsed = UrlParser.parse(startUrl);
        String originalDomain = originalParsed != null ? originalParsed.host : "";

        try {
            while (redirectCount <= MAX_REDIRECTS) {
                ParsedUrl parsed = UrlParser.parse(currentUrl);
                if (parsed == null || parsed.host.isEmpty()) {
                    break;
                }

                if (isLocalOrPrivateIp(parsed.host)) {
                    findings.add(new Finding("NET-PRIVATE-IP", "Internal network target",
                            "The link points to a private or local network address, which is unsafe to follow.", 80, Finding.Source.ONLINE));
                    break;
                }

                URL url = new URL(currentUrl);
                HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                conn.setInstanceFollowRedirects(false); // We handle redirects manually
                conn.setConnectTimeout(TIMEOUT_MS);
                conn.setReadTimeout(TIMEOUT_MS);
                conn.setRequestProperty("User-Agent", "PhishNet Security Scanner/1.0");
                conn.connect();

                int status = conn.getResponseCode();
                if (status >= 300 && status <= 399) {
                    String location = conn.getHeaderField("Location");
                    if (location == null) {
                        conn.disconnect();
                        break;
                    }

                    redirectCount++;
                    String nextUrl;
                    try {
                        nextUrl = new URL(url, location).toString();
                    } catch (java.net.MalformedURLException e) {
                        conn.disconnect();
                        break;
                    }

                    ParsedUrl nextParsed = UrlParser.parse(nextUrl);
                    if (nextParsed != null && !originalDomain.isEmpty() && !nextParsed.host.isEmpty()) {
                        String origReg = HostUtils.registrableDomain(originalDomain);
                        String nextReg = HostUtils.registrableDomain(nextParsed.host);
                        if (origReg != null && nextReg != null && !origReg.equals(nextReg)) {
                            crossDomain = true;
                        }
                    }
                    currentUrl = nextUrl;
                    conn.disconnect();
                    continue;
                }

                if (status == 200) {
                    String contentType = conn.getContentType();
                    if (contentType != null) {
                        String ct = contentType.toLowerCase(Locale.ROOT);
                        if (ct.contains("application/vnd.android.package-archive") || ct.contains("application/x-msdownload") || ct.contains("application/octet-stream")) {
                            findings.add(new Finding("DOWNLOAD-SUSPICIOUS", "Direct executable download",
                                    "The link directly downloads a file (app or executable), which can be highly dangerous.", 90, Finding.Source.ONLINE));
                            conn.disconnect();
                            break;
                        }

                        if (ct.contains("text/html")) {
                            parseHtml(conn, findings);
                        }
                    }
                }
                conn.disconnect();
                break;
            }

            if (redirectCount > 0) {
                findings.add(new Finding("HTTP-REDIRECT", "Website redirects",
                        "The URL redirected " + redirectCount + " time(s) before loading.", redirectCount > 2 ? 15 : 0, Finding.Source.ONLINE));
            }
            if (redirectCount > 3) {
                findings.add(new Finding("HTTP-MANY-REDIRECTS", "Multiple redirects",
                        "Too many redirects often indicate tracking or evasion techniques.", 40, Finding.Source.ONLINE));
            }
            if (crossDomain) {
                findings.add(new Finding("HTTP-CROSS-DOMAIN", "Cross-domain redirect",
                        "The link redirected to a completely different domain name than the original one.", 35, Finding.Source.ONLINE));
            }

        } catch (IOException | RuntimeException e) {
            // Exceptions are expected for broken or heavily shielded sites; do not crash.
        }
        return findings;
    }

    private static void parseHtml(HttpURLConnection conn, List<Finding> findings) throws IOException {
        StringBuilder body = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()))) {
            int read;
            char[] buffer = new char[4096];
            while ((read = reader.read(buffer)) != -1) {
                body.append(buffer, 0, read);
                if (body.length() > MAX_BODY_SIZE) break;
            }
        }
        String html = body.toString().toLowerCase(Locale.ROOT);

        if (html.contains("type=\"password\"") || html.contains("type='password'")) {
            findings.add(new Finding("HTML-PASSWORD-FORM", "Password input detected",
                    "The destination page contains a login form requesting a password.", 30, Finding.Source.ONLINE));
        }
        if (html.contains("<iframe") && (html.contains("visibility:hidden") || html.contains("visibility: hidden") || html.contains("display:none") || html.contains("display: none"))) {
            findings.add(new Finding("HTML-HIDDEN-IFRAME", "Hidden iframe detected",
                    "The page contains hidden external content, a technique sometimes used in stealthy attacks.", 40, Finding.Source.ONLINE));
        }
        if (html.contains("<script src=\"http") || html.contains("<script src='http")) {
            findings.add(new Finding("HTML-EXTERNAL-SCRIPT", "External scripts loaded",
                    "The page loads scripts from external sources.", 0, Finding.Source.ONLINE));
        }
    }

    private static boolean isLocalOrPrivateIp(String host) {
        if (host.startsWith("10.") || host.startsWith("192.168.") || host.matches("172\\.(1[6-9]|2[0-9]|3[0-1])\\..*") || host.startsWith("127.") || host.equals("localhost")) {
            return true;
        }
        try {
            java.net.InetAddress[] addresses = java.net.InetAddress.getAllByName(host);
            for (java.net.InetAddress addr : addresses) {
                if (addr.isLoopbackAddress() || addr.isSiteLocalAddress() || addr.isAnyLocalAddress() || addr.isLinkLocalAddress()) {
                    return true;
                }
            }
        } catch (java.net.UnknownHostException e) {
            // If it can't resolve, it's not a valid public host anyway, but we'll let normal connection logic fail.
        }
        return false;
    }

    private RedirectAnalyzer() {}
}
