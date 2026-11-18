package com.phishnet.app;

import com.phishnet.app.online.ReputationService;
import com.phishnet.app.online.SafeBrowsingService;

/** Build-time configuration. Contains no secrets and no invented destinations. */
final class AppConfig {
    /**
     * Where "Donate to developers" should go. Left empty on purpose: PhishNet does not invent a person,
     * payment account or donation page. Set a real https URL here to enable the donate action.
     */
    static final String DONATION_URL = "";

    /**
     * The optional online reputation service. The default reports "not available". To add one,
     * implement {@link ReputationService}, return it here, and then (and only then) add the INTERNET
     * permission to the manifest. Never embed a private API key in the app.
     */
    static ReputationService reputationService() {
        return new SafeBrowsingService(""); // Provide your secure backend proxy URL here.
    }

    private AppConfig() {}
}
