package com.phishnet.app.scanner;

import com.phishnet.app.analysis.Finding;

import java.util.ArrayList;
import java.util.List;

public final class QRSecurityAnalyzer {

    public static List<Finding> analyzeBaseSecurity(String payload) {
        List<Finding> findings = new ArrayList<>();

        if (payload == null || payload.isEmpty()) {
            findings.add(new Finding("QR-EMPTY", "Empty payload", "The QR code contains no data.", 0, Finding.Source.URL));
            return findings;
        }

        if (payload.length() > 2000) {
            findings.add(new Finding("QR-LARGE-PAYLOAD", "Suspiciously large payload", "The QR code contains an unusually large amount of data (" + payload.length() + " chars), which might be hiding a malicious script or executable.", 20, Finding.Source.URL));
        }

        if (payload.indexOf('\0') >= 0) {
            findings.add(new Finding("QR-NULL-BYTE", "Null-byte detected", "The payload contains a null-byte character, often used to truncate strings and bypass security filters.", 60, Finding.Source.URL));
        }

        boolean hasControlChars = false;
        for (int i = 0; i < payload.length(); i++) {
            char c = payload.charAt(i);
            if (c < 32 && c != '\n' && c != '\r' && c != '\t') {
                hasControlChars = true;
                break;
            }
        }

        if (hasControlChars) {
            findings.add(new Finding("QR-CONTROL-CHARS", "Hidden control characters", "The QR code contains non-printable control characters that might exploit parser vulnerabilities.", 40, Finding.Source.URL));
        }

        if (payload.contains("%25")) {
            findings.add(new Finding("QR-DOUBLE-ENCODED", "Double-encoded data", "The data appears to be double-encoded, a common technique to evade detection.", 30, Finding.Source.URL));
        }

        return findings;
    }

    private QRSecurityAnalyzer() {}
}
