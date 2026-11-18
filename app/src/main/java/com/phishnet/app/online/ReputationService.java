package com.phishnet.app.online;

import java.io.IOException;

/**
 * Replaceable adapter for an optional online reputation lookup.
 *
 * Contract for implementers:
 * - {@link #check} receives ONLY the link. Never send message text or anything about the user.
 * - Never open, download, execute or follow redirects of the submitted link; ask the service about it.
 * - Never embed a private API key in the app. Use a service that needs none, or your own proxy.
 * - {@link #check} blocks, and is always called off the main thread.
 */
public interface ReputationService {
    /** Human-readable service name shown in the consent dialog and on the result screen. */
    String name();

    /** One or two plain sentences telling the user exactly what the service receives. */
    String dataSentDescription();

    /** False when no service/endpoint is configured; the app then reports online checking as unavailable. */
    boolean isConfigured();

    ReputationResult check(String url) throws IOException;
}
