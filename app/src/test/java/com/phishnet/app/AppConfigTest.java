package com.phishnet.app;

import static org.junit.Assert.*;

import org.junit.Test;

public class AppConfigTest {
    @Test public void noDonationDestinationIsInvented() {
        assertEquals("", AppConfig.DONATION_URL);
    }

    @Test public void onlineCheckingIsUnavailableUntilAServiceIsConfigured() {
        assertFalse(AppConfig.reputationService().isConfigured());
    }
}
