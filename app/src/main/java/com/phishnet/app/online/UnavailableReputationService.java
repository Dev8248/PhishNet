package com.phishnet.app.online;

/**
 * Default service: reports that online checking is not available. It never touches the network and
 * never produces a result, so no online outcome can be simulated or fabricated.
 */
public final class UnavailableReputationService implements ReputationService {
    @Override public String name() { return "No service configured"; }
    @Override public String dataSentDescription() { return "Nothing is sent: no online service is configured in this build."; }
    @Override public boolean isConfigured() { return false; }

    @Override
    public ReputationResult check(String url) {
        throw new UnsupportedOperationException("No reputation service is configured.");
    }
}
