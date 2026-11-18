package com.phishnet.app.scanner;

import com.phishnet.app.models.QRPayload;

import java.util.Locale;

public final class QRPayloadAnalyzer {

    public static QRPayload analyze(String content) {
        if (content == null || content.trim().isEmpty()) {
            return new QRPayload(content, QRPayload.Type.UNKNOWN);
        }

        String lower = content.trim().toLowerCase(Locale.ROOT);

        if (lower.startsWith("https://")) {
            return new QRPayload(content, QRPayload.Type.HTTPS_URL);
        } else if (lower.startsWith("http://")) {
            return new QRPayload(content, QRPayload.Type.HTTP_URL);
        } else if (lower.startsWith("upi://pay")) {
            return new QRPayload(content, QRPayload.Type.UPI_URI);
        } else if (lower.startsWith("wifi:")) {
            return new QRPayload(content, QRPayload.Type.WIFI_CONFIG);
        } else if (lower.startsWith("mailto:")) {
            return new QRPayload(content, QRPayload.Type.EMAIL);
        } else if (lower.startsWith("sms:") || lower.startsWith("smsto:")) {
            return new QRPayload(content, QRPayload.Type.SMS);
        } else if (lower.startsWith("tel:")) {
            return new QRPayload(content, QRPayload.Type.TELEPHONE);
        } else if (lower.startsWith("intent://")) {
            return new QRPayload(content, QRPayload.Type.INTENT_URI);
        } else if (lower.startsWith("android-app://")) {
            return new QRPayload(content, QRPayload.Type.APP_DEEP_LINK);
        } else if (lower.startsWith("geo:")) {
            return new QRPayload(content, QRPayload.Type.GEOLOCATION);
        } else if (lower.startsWith("begin:vcard")) {
            return new QRPayload(content, QRPayload.Type.VCARD);
        } else if (lower.matches("^[a-z0-9+.-]+://.*")) {
            return new QRPayload(content, QRPayload.Type.UNSUPPORTED_SCHEME);
        } else {
            return new QRPayload(content, QRPayload.Type.PLAIN_TEXT);
        }
    }

    private QRPayloadAnalyzer() {}
}
