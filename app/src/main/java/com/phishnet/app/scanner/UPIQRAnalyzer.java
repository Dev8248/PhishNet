package com.phishnet.app.scanner;

import com.phishnet.app.analysis.Finding;
import com.phishnet.app.models.QRPayload;
import com.phishnet.app.models.QRResult;

import java.util.List;
import java.util.Locale;

public final class UPIQRAnalyzer {

    public static QRResult analyze(QRPayload payload) {
        List<Finding> findings = QRSecurityAnalyzer.analyzeBaseSecurity(payload.rawContent);

        if (payload.type != QRPayload.Type.UPI_URI) {
            return new QRResult(payload, null, findings);
        }

        String lower = payload.rawContent.toLowerCase(Locale.ROOT);

        if (!lower.contains("pa=")) {
            findings.add(new Finding("UPI-NO-PAYEE", "Missing Payee Address", "The UPI payment request does not specify who will receive the funds.", 30, Finding.Source.URL));
        } else if (lower.contains("pa=merchant@upi")) {
            // Note: usually we check for realistic VPA, but here we flag very generic or suspicious examples
            // Or just extract for display.
        }

        if (lower.contains("url=") || lower.contains("http://") || lower.contains("https://")) {
            findings.add(new Finding("UPI-EMBEDDED-URL", "Embedded URL in Payment", "The payment request contains a web link, which could be an attempt to redirect you to a phishing site.", 50, Finding.Source.URL));
        }

        if (!lower.contains("am=")) {
            findings.add(new Finding("UPI-NO-AMOUNT", "No amount specified", "No amount is set. The payee could trick you into typing a large amount yourself.", 20, Finding.Source.URL));
        }

        return new QRResult(payload, null, findings);
    }

    private UPIQRAnalyzer() {}
}
