package com.phishnet.app.online;

import static org.junit.Assert.*;

import com.phishnet.app.analysis.AnalysisResult;
import com.phishnet.app.analysis.OnlineStatus;
import com.phishnet.app.analysis.RiskAnalyzer;
import com.phishnet.app.analysis.RiskLevel;
import java.io.IOException;
import org.junit.Test;

public class OnlineCheckTest {

    /** Test double. No test touches the network or a live malicious site. */
    private static final class Fake implements ReputationService {
        private final ReputationResult result;
        private final IOException failure;
        String lastUrl;
        Fake(ReputationResult result, IOException failure) { this.result = result; this.failure = failure; }
        @Override public String name() { return "FakeService"; }
        @Override public String dataSentDescription() { return "the link"; }
        @Override public boolean isConfigured() { return true; }
        @Override public ReputationResult check(String url) throws IOException {
            lastUrl = url;
            if (failure != null) throw failure;
            return result;
        }
    }

    @Test public void unavailableServiceLeavesTheLocalResultUntouched() {
        AnalysisResult local = RiskAnalyzer.analyze("https://example.com");
        AnalysisResult r = OnlineCheck.run(local, new UnavailableReputationService(), null);
        assertEquals(OnlineStatus.UNAVAILABLE, r.onlineStatus());
        assertEquals(local.level(), r.level());
        assertEquals(local.score(), r.score());
        assertTrue(r.findings().size() >= local.findings().size()); // Can add DNS/TLS findings
        assertNull(r.onlineServiceName());
    }

    @Test public void defaultBuildHasNoServiceConfigured() {
        assertFalse(new UnavailableReputationService().isConfigured());
        assertNull(null); // nothing is ever fabricated: check() is unsupported
        try {
            new UnavailableReputationService().check("https://example.com");
            fail("must not simulate a result");
        } catch (UnsupportedOperationException expected) {
            // correct
        }
    }

    @Test public void nullServiceIsTreatedAsUnavailable() {
        AnalysisResult r = OnlineCheck.run(RiskAnalyzer.analyze("https://example.com"), null, null);
        assertEquals(OnlineStatus.UNAVAILABLE, r.onlineStatus());
    }

    @Test public void threatMatchRaisesToRiskyAndKeepsLocalFindings() {
        AnalysisResult local = RiskAnalyzer.analyze("https://example.com");
        Fake svc = new Fake(ReputationResult.threat("phishing"), null);
        AnalysisResult r = OnlineCheck.run(local, svc, null);
        assertEquals("https://example.com", svc.lastUrl);
        assertEquals(OnlineStatus.COMPLETED, r.onlineStatus());
        assertEquals("FakeService", r.onlineServiceName());
        assertEquals(RiskLevel.NOT_SAFE, r.level());
        assertEquals("ONLINE-LISTED", r.findings().get(0).id);
    }

    @Test public void noMatchDoesNotLowerTheLocalLevel() {
        AnalysisResult local = RiskAnalyzer.analyze("http://example.com");
        AnalysisResult r = OnlineCheck.run(local, new Fake(ReputationResult.noMatch(), null), null);
        assertEquals(OnlineStatus.COMPLETED, r.onlineStatus());
        assertEquals(local.level(), r.level());
        assertEquals(local.score(), r.score());
    }

    @Test public void failedOrInconclusiveChecksNeverLeaveASafeResult() {
        AnalysisResult local = RiskAnalyzer.analyze("https://example.com");
        assertEquals(RiskLevel.APPEARS_SAFE, local.level());
        AnalysisResult failed = OnlineCheck.run(local, new Fake(null, new IOException("offline")), null);
        assertEquals(OnlineStatus.FAILED, failed.onlineStatus());
        assertEquals(RiskLevel.SUSPICIOUS, failed.level());
        assertFalse(failed.incompleteReasons().isEmpty());
        AnalysisResult unknown = OnlineCheck.run(local, new Fake(ReputationResult.unknown(""), null), null);
        assertEquals(OnlineStatus.INCONCLUSIVE, unknown.onlineStatus());
        assertEquals(RiskLevel.SUSPICIOUS, unknown.level());
    }
}
