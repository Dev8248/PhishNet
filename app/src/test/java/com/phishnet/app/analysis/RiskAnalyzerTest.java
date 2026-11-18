package com.phishnet.app.analysis;

import static org.junit.Assert.*;

import java.net.IDN;
import org.junit.Test;

public class RiskAnalyzerTest {

    private static void assertLevel(RiskLevel expected, String url) {
        AnalysisResult r = RiskAnalyzer.analyze(url);
        assertEquals(url + " score=" + r.score() + " findings=" + ids(r), expected, r.level());
    }

    private static String ids(AnalysisResult r) {
        StringBuilder b = new StringBuilder();
        for (Finding f : r.findings()) b.append(f.id).append('(').append(f.points).append(") ");
        return b.toString();
    }

    private static boolean has(AnalysisResult r, String id) {
        for (Finding f : r.findings()) if (f.id.equals(id)) return true;
        return false;
    }

    // ---- Safe: no obvious warning signs ----
    @Test public void plainHttpsSitesAreSafe() {
        assertLevel(RiskLevel.APPEARS_SAFE, "https://example.com");
        assertLevel(RiskLevel.APPEARS_SAFE, "https://www.wikipedia.org/wiki/Phishing");
        assertLevel(RiskLevel.APPEARS_SAFE, "www.example.com");
        assertEquals(0, RiskAnalyzer.analyze("https://example.com").score());
    }

    @Test public void wellKnownFirstPartyDomainsAreNotFlagged() {
        assertLevel(RiskLevel.APPEARS_SAFE, "https://accounts.google.com/signin");
        assertLevel(RiskLevel.APPEARS_SAFE, "https://www.google.co.in/");
        assertLevel(RiskLevel.APPEARS_SAFE, "https://www.amazon.in/gp/css/order-history");
        assertLevel(RiskLevel.APPEARS_SAFE, "https://www.paypal.com/signin");
        assertLevel(RiskLevel.APPEARS_SAFE, "https://www.onlinesbi.sbi/");
    }

    @Test public void ordinaryWordsContainingShortBrandNamesAreNotFlagged() {
        assertLevel(RiskLevel.APPEARS_SAFE, "https://appleinsider.com");
        assertLevel(RiskLevel.APPEARS_SAFE, "https://pineapple.com");
        assertLevel(RiskLevel.APPEARS_SAFE, "https://examp1e.com");
    }

    @Test public void minorIndicatorsStaySafeButAreListed() {
        AnalysisResult r = RiskAnalyzer.analyze("https://example.com:4444/");
        assertEquals(RiskLevel.APPEARS_SAFE, r.level());
        assertTrue(has(r, "HOST-PORT"));
        assertEquals(RiskLevel.APPEARS_SAFE, RiskAnalyzer.analyze("https://example.com:8443/").level());
        assertEquals(RiskLevel.APPEARS_SAFE, RiskAnalyzer.analyze("https://a.b.c.d.example.com/").level());
        assertEquals(RiskLevel.APPEARS_SAFE, RiskAnalyzer.analyze("https://example.com/r?u=https%3A%2F%2Fother.example").level());
    }

    @Test public void missingSchemeIsNotedWithZeroPoints() {
        AnalysisResult r = RiskAnalyzer.analyze("www.example.com");
        assertTrue(has(r, "SCHEME-MISSING"));
        assertEquals("https://www.example.com", r.url());
    }

    // ---- Moderate ----
    @Test public void plainHttpIsModerate() {
        AnalysisResult r = RiskAnalyzer.analyze("http://example.com");
        assertEquals(RiskLevel.SUSPICIOUS, r.level());
        assertEquals(20, r.score());
    }

    @Test public void shortenersAreModerateAndMarkTheScanIncomplete() {
        AnalysisResult r = RiskAnalyzer.analyze("https://bit.ly/abc123");
        assertEquals(RiskLevel.SUSPICIOUS, r.level());
        assertFalse(r.incompleteReasons().isEmpty());
        assertTrue(has(r, "HOST-SHORTENER"));
    }

    @Test public void credentialsInLinkAreModerate() {
        assertLevel(RiskLevel.SUSPICIOUS, "https://user:pw@example.com/");
        assertLevel(RiskLevel.SUSPICIOUS, "ftp://example.com/file");
        assertLevel(RiskLevel.SUSPICIOUS, "https://192.168.1.1/login");
        assertLevel(RiskLevel.SUSPICIOUS, "https://secure-login.verify-account.example.com/");
    }

    @Test public void hiddenCharactersAreModerate() {
        AnalysisResult r = RiskAnalyzer.analyze("https://example.com/\u202Epath");
        assertEquals(RiskLevel.SUSPICIOUS, r.level());
        assertTrue(has(r, "SYNTAX-HIDDEN"));
    }

    @Test public void veryLongLinkIsIncompleteSoNeverSafe() {
        StringBuilder b = new StringBuilder("https://example.com/");
        for (int i = 0; i < 6000; i++) b.append('a');
        AnalysisResult r = RiskAnalyzer.analyze(b.toString());
        assertEquals(RiskLevel.SUSPICIOUS, r.level());
        assertFalse(r.incompleteReasons().isEmpty());
    }

    @Test public void truncatedSourceTextIsIncomplete() {
        AnalysisResult r = RiskAnalyzer.analyze("https://example.com", "hello", true);
        assertEquals(RiskLevel.SUSPICIOUS, r.level());
        assertFalse(r.incompleteReasons().isEmpty());
    }

    // ---- Risky ----
    @Test public void deceptiveAtSignIsRisky() {
        assertLevel(RiskLevel.HIGH_RISK, "https://paypal.com@evil.example/");
    }

    @Test public void lookalikeSpellingsOfKnownBrandsAreRisky() {
        assertLevel(RiskLevel.HIGH_RISK, "https://paypa1.com/login");
        assertLevel(RiskLevel.HIGH_RISK, "https://arnazon.com/");
        assertLevel(RiskLevel.HIGH_RISK, "https://gooogle.com/");
        assertLevel(RiskLevel.HIGH_RISK, "https://micr0soft-support.net/");
    }

    @Test public void brandNamesInUnrelatedDomainsAreFlagged() {
        assertLevel(RiskLevel.HIGH_RISK, "https://paypal-login.example.com/");
        assertLevel(RiskLevel.HIGH_RISK, "https://apple-support.example.com/");
        assertLevel(RiskLevel.HIGH_RISK, "https://amazon.xyz/");
        assertLevel(RiskLevel.HIGH_RISK, "https://paypal-login.github.io/");
        assertLevel(RiskLevel.HIGH_RISK, "https://paypal-fans.com/");
    }

    @Test public void realDomainInsideSubdomainIsRisky() {
        AnalysisResult r = RiskAnalyzer.analyze("https://paypal.com.account-verify.example.xyz/");
        assertEquals(RiskLevel.NOT_SAFE, r.level());
        assertTrue(has(r, "BRAND-REAL-DOMAIN-INSIDE"));
        assertLevel(RiskLevel.NOT_SAFE, "https://accounts.google.com.secure-login.example.net/");
    }

    @Test public void punycodeImpersonationIsRisky() {
        String spoof = IDN.toASCII("p\u0430ypal.com"); // Cyrillic "a"
        AnalysisResult r = RiskAnalyzer.analyze("https://" + spoof + "/");
        assertEquals(RiskLevel.NOT_SAFE, r.level());
        assertTrue(has(r, "HOST-PUNYCODE"));
        assertTrue(has(r, "HOST-MIXED-SCRIPT"));
    }

    @Test public void legitimateInternationalisedNameIsOnlyModerate() {
        AnalysisResult r = RiskAnalyzer.analyze("https://" + IDN.toASCII("m\u00FCnchen.de") + "/");
        assertEquals(RiskLevel.SUSPICIOUS, r.level());
        assertFalse(has(r, "HOST-MIXED-SCRIPT"));
    }

    @Test public void ipAddressesCombinedWithHttpAreRisky() {
        assertLevel(RiskLevel.HIGH_RISK, "http://192.0.2.5/login");
        assertLevel(RiskLevel.HIGH_RISK, "http://3232235777/");
        assertLevel(RiskLevel.HIGH_RISK, "http://0x7f.1/");
    }

    @Test public void scriptAndDataLinksAreRisky() {
        assertLevel(RiskLevel.HIGH_RISK, "javascript:alert(1)");
        assertLevel(RiskLevel.HIGH_RISK, "data:text/html,hello");
    }

    // ---- Message wording ----
    @Test public void messageWordingRaisesTheScore() {
        String msg = "URGENT: confirm your OTP immediately or pay now. https://example.com/x";
        AnalysisResult base = RiskAnalyzer.analyze("https://example.com/x");
        AnalysisResult r = RiskAnalyzer.analyze("https://example.com/x", msg, false);
        assertTrue(r.messageAnalysed());
        assertTrue(r.score() > base.score());
        assertEquals(RiskLevel.SUSPICIOUS, r.level());
        assertTrue(has(r, "TEXT-SENSITIVE"));
        assertTrue(has(r, "TEXT-URGENCY"));
        assertEquals(RiskLevel.HIGH_RISK, RiskAnalyzer.analyze("http://example.com/x", msg, false).level());
    }

    @Test public void warningsAgainstSharingCodesAreNotTreatedAsRequests() {
        AnalysisResult r = RiskAnalyzer.analyze("https://example.com/x",
                "Never share your OTP with anyone. Don't give your PIN to anyone.", false);
        assertFalse(has(r, "TEXT-SENSITIVE"));
    }

    @Test public void messageWordingIsCapped() {
        String msg = "urgent immediately act now final notice asap hurry pay now refund overdue unpaid "
                + "you have won congratulations lottery legal action arrest suspended court police "
                + "share your password otp cvv pin";
        int textPoints = 0;
        for (Finding f : RiskAnalyzer.analyze("https://example.com", msg, false).findings()) {
            if (f.source == Finding.Source.MESSAGE) textPoints += f.points;
        }
        assertTrue(textPoints <= TextRules.MAX_POINTS);
        assertTrue(textPoints > 0);
    }

    @Test public void wordsInsideOtherWordsDoNotMatch() {
        AnalysisResult r = RiskAnalyzer.analyze("https://example.com", "Please spin the pinwheel, the courtesy desk", false);
        assertTrue(r.findings().isEmpty());
    }

    // ---- Robustness ----
    @Test public void unreadableInputIsRejectedWithAMessage() {
        try {
            RiskAnalyzer.analyze("http://");
            fail("expected IllegalArgumentException");
        } catch (IllegalArgumentException e) {
            assertNotNull(e.getMessage());
        }
    }

    @Test(timeout = 5000) public void hostileInputsNeverCrashOrFreeze() {
        String[] hostile = {
                "https://" + repeat("a.", 5000) + "com/", "https://" + repeat("a", 5000) + ".com/",
                "http://[" + repeat(":", 100) + "]/", "https://example.com/" + repeat("%", 4000),
                "https://example.com/?" + repeat("u=https://x&", 3000), "https://" + repeat("\u202E", 200) + ".com",
                "https://\u0000.com", "https://.com", "https://-.com", "https://a..b.com", "HTTP://EXAMPLE.COM/%zz%2"};
        for (String h : hostile) {
            try {
                AnalysisResult r = RiskAnalyzer.analyze(h);
                assertNotNull(r.level());
            } catch (IllegalArgumentException expected) {
                // reported cleanly
            }
        }
    }

    @Test public void sameInputAlwaysGivesTheSameClassificationScoreAndEvidence() {
        AnalysisResult a = RiskAnalyzer.analyze("https://paypa1.com/login");
        AnalysisResult b = RiskAnalyzer.analyze("https://paypa1.com/login");
        assertEquals(a.level(), b.level());
        assertEquals(a.score(), b.score());
        assertEquals(ids(a), ids(b));
    }

    private static String repeat(String s, int n) {
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < n; i++) b.append(s);
        return b.toString();
    }
}
