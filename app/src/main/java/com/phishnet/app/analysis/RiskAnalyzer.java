package com.phishnet.app.analysis;

import java.util.ArrayList;
import java.util.List;

/**
 * Offline-first analyser. Everything here runs on the device, in bounded time, with no network access.
 * It never opens, fetches or resolves the link.
 */
public final class RiskAnalyzer {

    /**
     * @param rawUrl       the link to analyse
     * @param messageText  the surrounding message, or null when only a link was supplied
     * @param inputTruncated true if the text the link came from was longer than the analysis limit
     * @throws IllegalArgumentException with a plain-language message if the text cannot be read as a link
     */
    public static AnalysisResult analyze(String rawUrl, String messageText, boolean inputTruncated) {
        ParsedUrl p = UrlParser.parse(rawUrl);
        if (!p.valid) {
            throw new IllegalArgumentException(p.problem);
        }
        List<Finding> findings = new ArrayList<>();
        List<String> incomplete = new ArrayList<>();
        UrlRules.apply(p, findings, incomplete);

        boolean message = messageText != null && !messageText.trim().isEmpty();
        if (message) {
            TextRules.apply(messageText, findings);
        }
        if (inputTruncated) {
            incomplete.add("The text was longer than " + Limits.MAX_INPUT_CHARS
                    + " characters, so only the start of it was read.");
        }
        return AnalysisResult.create(p.normalized(), p.isWebScheme(), findings, incomplete, message,
                OnlineStatus.NOT_REQUESTED, null);
    }

    public static AnalysisResult analyze(String rawUrl) {
        return analyze(rawUrl, null, false);
    }

    private RiskAnalyzer() {}
}
