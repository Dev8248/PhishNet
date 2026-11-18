package com.phishnet.app.analysis;

/** What happened with the optional online reputation check. */
public enum OnlineStatus {
    /** The user has not asked for an online check. Nothing was sent anywhere. */
    NOT_REQUESTED,
    /** No reputation service is configured in this build. Nothing was sent anywhere. */
    UNAVAILABLE,
    /** The service answered. */
    COMPLETED,
    /** The service answered but could not give a usable verdict. */
    INCONCLUSIVE,
    /** The request failed (network error, timeout, bad response). */
    FAILED
}
