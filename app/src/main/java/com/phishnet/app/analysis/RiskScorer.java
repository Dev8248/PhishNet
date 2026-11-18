package com.phishnet.app.analysis;

import java.util.List;

/**
 * Turns evidence points into one of three levels.
 *
 * Score = sum of finding points, capped at 100. It is NOT a probability of being attacked.
 * 0-19 Appears Safe, 20-39 Suspicious, 40-69 High Risk, 70-100 Not Safe.
 * If an important check could not be completed (see {@link AnalysisResult#incompleteReasons()}),
 * a Safe result is raised to Suspicious. A Risky result is never lowered by this rule.
 */
public final class RiskScorer {
    public static final int SUSPICIOUS_AT = 20;
    public static final int HIGH_RISK_AT = 40;
    public static final int NOT_SAFE_AT = 70;
    public static final int MAX_SCORE = 100;

    public static int total(List<Finding> findings) {
        long sum = 0;
        for (Finding f : findings) {
            sum += f.points;
        }
        return (int) Math.max(0, Math.min(MAX_SCORE, sum));
    }

    public static RiskLevel level(int score, boolean importantCheckIncomplete) {
        RiskLevel level;
        if (score >= NOT_SAFE_AT) {
            level = RiskLevel.NOT_SAFE;
        } else if (score >= HIGH_RISK_AT) {
            level = RiskLevel.HIGH_RISK;
        } else if (score >= SUSPICIOUS_AT) {
            level = RiskLevel.SUSPICIOUS;
        } else {
            level = RiskLevel.APPEARS_SAFE;
        }
        if (level == RiskLevel.APPEARS_SAFE && importantCheckIncomplete) {
            level = RiskLevel.SUSPICIOUS;
        }
        return level;
    }

    private RiskScorer() {}
}
