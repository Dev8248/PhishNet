package com.phishnet.app.analysis;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** Immutable outcome of a scan. Classification depends only on the evidence, never on UI wording. */
public final class AnalysisResult {
    private final String url;
    private final boolean webLink;
    private final RiskLevel level;
    private final int score;
    private final List<Finding> findings;
    private final List<String> incompleteReasons;
    private final boolean messageAnalysed;
    private final OnlineStatus onlineStatus;
    private final String onlineServiceName;

    private AnalysisResult(String url, boolean webLink, RiskLevel level, int score, List<Finding> findings,
                           List<String> incompleteReasons, boolean messageAnalysed,
                           OnlineStatus onlineStatus, String onlineServiceName) {
        this.url = url;
        this.webLink = webLink;
        this.level = level;
        this.score = score;
        this.findings = findings;
        this.incompleteReasons = incompleteReasons;
        this.messageAnalysed = messageAnalysed;
        this.onlineStatus = onlineStatus;
        this.onlineServiceName = onlineServiceName;
    }

    public static AnalysisResult create(String url, boolean webLink, List<Finding> findings,
                                        List<String> incompleteReasons, boolean messageAnalysed,
                                        OnlineStatus onlineStatus, String onlineServiceName) {
        List<Finding> sorted = new ArrayList<>(findings);
        sorted.sort((a, b) -> Integer.compare(b.points, a.points)); // stable: ties keep rule order
        int score = RiskScorer.total(sorted);
        RiskLevel level = RiskScorer.level(score, !incompleteReasons.isEmpty());
        return new AnalysisResult(url, webLink, level, score,
                Collections.unmodifiableList(sorted),
                Collections.unmodifiableList(new ArrayList<>(incompleteReasons)),
                messageAnalysed, onlineStatus, onlineServiceName);
    }

    /** Returns a new result that adds the outcome of an online check. Local findings are kept. */
    public AnalysisResult withOnline(OnlineStatus status, String serviceName, List<Finding> extra,
                                     String incompleteReason) {
        List<Finding> all = new ArrayList<>(findings);
        all.addAll(extra);
        List<String> reasons = new ArrayList<>(incompleteReasons);
        if (incompleteReason != null) {
            reasons.add(incompleteReason);
        }
        return create(url, webLink, all, reasons, messageAnalysed, status, serviceName);
    }

    /** The link that was analysed (scheme added if the text had none). */
    public String url() { return url; }
    /** True for http/https links, the only kind the app will ever offer to open. */
    public boolean isWebLink() { return webLink; }
    public RiskLevel level() { return level; }
    public int score() { return score; }
    public List<Finding> findings() { return findings; }
    /** Reasons an important check could not be completed. Non-empty means "incomplete". */
    public List<String> incompleteReasons() { return incompleteReasons; }
    public boolean messageAnalysed() { return messageAnalysed; }
    public OnlineStatus onlineStatus() { return onlineStatus; }
    public String onlineServiceName() { return onlineServiceName; }
}
