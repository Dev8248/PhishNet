package com.phishnet.app.scanner;

import com.phishnet.app.analysis.Finding;
import com.phishnet.app.models.QRPayload;
import com.phishnet.app.models.QRResult;

import java.util.List;
import java.util.Locale;

public final class WiFiQRAnalyzer {

    public static QRResult analyze(QRPayload payload) {
        List<Finding> findings = QRSecurityAnalyzer.analyzeBaseSecurity(payload.rawContent);

        if (payload.type != QRPayload.Type.WIFI_CONFIG) {
            return new QRResult(payload, null, findings);
        }

        String content = payload.rawContent;
        String upper = content.toUpperCase(Locale.ROOT);

        if (!upper.contains("S:") || upper.matches(".*S: *;.*")) {
            findings.add(new Finding("WIFI-NO-SSID", "Missing Network Name", "The Wi-Fi QR code does not specify a network name (SSID).", 40, Finding.Source.URL));
        }

        if (upper.contains("T:WEP")) {
            findings.add(new Finding("WIFI-WEP", "Insecure WEP Encryption", "The network uses WEP security, which is obsolete and easily hacked.", 60, Finding.Source.URL));
        } else if (upper.contains("T:NOPASS") || (!upper.contains("T:") && !upper.contains("P:"))) {
            findings.add(new Finding("WIFI-OPEN", "Open Network", "This is an open network with no password. Anyone can intercept your traffic.", 30, Finding.Source.URL));
        }

        if (upper.contains("H:TRUE")) {
            findings.add(new Finding("WIFI-HIDDEN", "Hidden Network", "This network is configured to hide its name. This does not provide real security.", 10, Finding.Source.URL));
        }

        if (content.contains("http://") || content.contains("https://")) {
            findings.add(new Finding("WIFI-EMBEDDED-URL", "Embedded Web Link", "The Wi-Fi configuration contains a web link, which is abnormal and potentially dangerous.", 50, Finding.Source.URL));
        }

        return new QRResult(payload, null, findings);
    }

    private WiFiQRAnalyzer() {}
}
