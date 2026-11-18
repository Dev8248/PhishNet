package com.phishnet.app.models;

import com.phishnet.app.analysis.AnalysisResult;
import com.phishnet.app.analysis.Finding;
import com.phishnet.app.analysis.RiskLevel;
import com.phishnet.app.analysis.RiskScorer;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class QRResult {
    public final QRPayload payload;

    // For URL payloads, we reuse the existing AnalysisResult
    public final AnalysisResult urlAnalysisResult;

    // For non-URL payloads (UPI, WiFi, etc.), we can have custom findings
    public final List<Finding> qrFindings;

    public final int score;
    public final RiskLevel level;

    public QRResult(QRPayload payload, AnalysisResult urlAnalysisResult, List<Finding> qrFindings) {
        this.payload = payload;
        this.urlAnalysisResult = urlAnalysisResult;

        List<Finding> allFindings = new ArrayList<>(qrFindings);
        if (urlAnalysisResult != null) {
            allFindings.addAll(urlAnalysisResult.findings());
        }

        // Sort findings by severity
        Collections.sort(allFindings, (a, b) -> Integer.compare(b.points, a.points));
        this.qrFindings = Collections.unmodifiableList(allFindings);

        // Use existing RiskScorer
        if (urlAnalysisResult != null) {
            this.score = urlAnalysisResult.score();
            this.level = urlAnalysisResult.level();
        } else {
            this.score = RiskScorer.total(this.qrFindings);
            this.level = RiskScorer.level(this.score, false);
        }
    }
}
