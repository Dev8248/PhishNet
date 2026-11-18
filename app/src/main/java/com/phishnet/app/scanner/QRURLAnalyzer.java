package com.phishnet.app.scanner;

import com.phishnet.app.analysis.AnalysisResult;
import com.phishnet.app.analysis.Finding;
import com.phishnet.app.analysis.RiskAnalyzer;
import com.phishnet.app.models.QRPayload;
import com.phishnet.app.models.QRResult;

import java.util.List;

public final class QRURLAnalyzer {

    public static QRResult analyze(QRPayload payload) {
        // Run base security first
        List<Finding> qrFindings = QRSecurityAnalyzer.analyzeBaseSecurity(payload.rawContent);

        AnalysisResult urlResult = null;
        if (payload.type == QRPayload.Type.HTTP_URL || payload.type == QRPayload.Type.HTTPS_URL) {
            try {
                urlResult = RiskAnalyzer.analyze(payload.rawContent, null, false);
            } catch (IllegalArgumentException e) {
                // If it fails URL parsing even though it started with http/https
                qrFindings.add(new Finding("QR-URL-MALFORMED", "Malformed URL in QR", "The QR code payload starts with http(s) but is an invalid URL.", 40, Finding.Source.URL));
            }
        }

        return new QRResult(payload, urlResult, qrFindings);
    }

    private QRURLAnalyzer() {}
}
