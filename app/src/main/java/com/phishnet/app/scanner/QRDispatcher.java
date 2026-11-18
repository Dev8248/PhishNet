package com.phishnet.app.scanner;

import com.phishnet.app.analysis.Finding;
import com.phishnet.app.models.QRPayload;
import com.phishnet.app.models.QRResult;

import java.util.List;
import java.util.Locale;

public final class QRDispatcher {

    public static QRResult dispatch(String rawContent) {
        QRPayload payload = QRPayloadAnalyzer.analyze(rawContent);

        switch (payload.type) {
            case HTTP_URL:
            case HTTPS_URL:
                return QRURLAnalyzer.analyze(payload);

            case UPI_URI:
                return UPIQRAnalyzer.analyze(payload);

            case WIFI_CONFIG:
                return WiFiQRAnalyzer.analyze(payload);

            default:
                return analyzeGeneric(payload);
        }
    }

    private static QRResult analyzeGeneric(QRPayload payload) {
        List<Finding> findings = QRSecurityAnalyzer.analyzeBaseSecurity(payload.rawContent);
        String lower = payload.rawContent.toLowerCase(Locale.ROOT);

        if (payload.type == QRPayload.Type.APP_DEEP_LINK || payload.type == QRPayload.Type.INTENT_URI) {
            findings.add(new Finding("QR-DEEP-LINK", "Application Deep Link", "This QR code attempts to open a specific application on your device.", 20, Finding.Source.URL));
            if (lower.contains("http://") || lower.contains("https://")) {
                findings.add(new Finding("QR-DEEP-LINK-URL", "Embedded URL in App Link", "The deep link contains a web link, potentially attempting to bypass browser protections.", 40, Finding.Source.URL));
            }
        }

        if (payload.type == QRPayload.Type.EMAIL || payload.type == QRPayload.Type.SMS) {
            if (lower.contains("password") || lower.contains("login") || lower.contains("verify") || lower.contains("bank")) {
                findings.add(new Finding("QR-MSG-SENSITIVE", "Sensitive words in message", "The prepared message contains words like password, login, or verify, which is highly unusual for a QR code.", 30, Finding.Source.URL));
            }
            if (lower.contains("http://") || lower.contains("https://")) {
                findings.add(new Finding("QR-MSG-URL", "Web link in message", "The prepared message contains a web link. This is a common tactic to trick you into sending a phishing link to others.", 50, Finding.Source.URL));
            }
        }

        if (payload.type == QRPayload.Type.GEOLOCATION) {
            if (lower.contains("http://") || lower.contains("https://")) {
                findings.add(new Finding("QR-GEO-URL", "Web link in location data", "Location data shouldn't normally contain web links.", 30, Finding.Source.URL));
            }
        }

        if (payload.type == QRPayload.Type.UNSUPPORTED_SCHEME) {
            findings.add(new Finding("QR-UNSUPPORTED", "Unsupported URI Scheme", "The QR code uses an uncommon or unsupported link type. It may attempt to exploit a specific app.", 35, Finding.Source.URL));
        }

        return new QRResult(payload, null, findings);
    }

    private QRDispatcher() {}
}
