package com.phishnet.app.models;

public class QRPayload {
    public enum Type {
        HTTP_URL,
        HTTPS_URL,
        PLAIN_TEXT,
        UPI_URI,
        WIFI_CONFIG,
        EMAIL,
        SMS,
        TELEPHONE,
        INTENT_URI,
        APP_DEEP_LINK,
        GEOLOCATION,
        VCARD,
        FILE_REFERENCE,
        UNSUPPORTED_SCHEME,
        UNKNOWN
    }

    public final String rawContent;
    public final Type type;

    public QRPayload(String rawContent, Type type) {
        this.rawContent = rawContent;
        this.type = type;
    }
}
