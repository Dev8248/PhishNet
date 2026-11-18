package com.phishnet.app.analysis;

import static org.junit.Assert.*;

import org.junit.Test;

public class UrlParserTest {

    @Test public void parsesAllParts() {
        ParsedUrl u = UrlParser.parse("https://user:pw@Example.COM:8443/a/b?x=1#frag");
        assertTrue(u.valid);
        assertEquals("https", u.scheme);
        assertEquals("user:pw", u.userInfo);
        assertEquals("example.com", u.host);
        assertEquals(8443, u.port);
        assertEquals("/a/b", u.path);
        assertEquals("x=1", u.query);
        assertEquals("frag", u.fragment);
        assertFalse(u.schemeAssumed);
    }

    @Test public void usesLastAtSignAsHostBoundary() {
        ParsedUrl u = UrlParser.parse("https://paypal.com@evil.example/login");
        assertTrue(u.valid);
        assertEquals("evil.example", u.host);
        assertEquals("paypal.com", u.userInfo);
        u = UrlParser.parse("https://a@b@evil.example/");
        assertEquals("evil.example", u.host);
        assertEquals(2, u.atCount);
    }

    @Test public void assumesHttpsWhenSchemeMissing() {
        ParsedUrl u = UrlParser.parse("www.example.com/login");
        assertTrue(u.valid);
        assertTrue(u.schemeAssumed);
        assertEquals("https", u.scheme);
        assertEquals("www.example.com", u.host);
        assertEquals("https://www.example.com/login", u.normalized());
    }

    @Test public void hostWithPortIsNotMistakenForScheme() {
        ParsedUrl u = UrlParser.parse("example.com:8080/x");
        assertTrue(u.valid);
        assertTrue(u.schemeAssumed);
        assertEquals("example.com", u.host);
        assertEquals(8080, u.port);
        u = UrlParser.parse("localhost:3000");
        assertTrue(u.valid);
        assertEquals("localhost", u.host);
    }

    @Test public void handlesOddSlashes() {
        ParsedUrl u = UrlParser.parse("http:/example.com/x");
        assertTrue(u.valid);
        assertTrue(u.oddSlashes);
        assertEquals("example.com", u.host);
        u = UrlParser.parse("http:\\\\example.com\\x");
        assertTrue(u.valid);
        assertTrue(u.hasBackslash);
        assertEquals("example.com", u.host);
        u = UrlParser.parse("https:example.com");
        assertTrue(u.valid);
        assertTrue(u.oddSlashes);
    }

    @Test public void malformedInputIsReportedNotThrown() {
        String[] bad = {null, "", "   ", "http://", "http://:80", "https:///", "http://exa mple.com",
                "http://example.com:99999", "http://example.com:abc", "http://[::1", "mailto:a@b.c",
                "tel:12345", "foo:bar", "http://exa:mple.com"};
        for (String s : bad) {
            ParsedUrl u = UrlParser.parse(s);
            assertFalse("should be invalid: " + s, u.valid);
            assertNotNull(u.problem);
        }
    }

    @Test public void opaqueSchemesAreRecognised() {
        ParsedUrl u = UrlParser.parse("javascript:alert(1)");
        assertTrue(u.valid);
        assertTrue(u.opaque);
        assertEquals("javascript", u.scheme);
        assertTrue(UrlParser.parse("data:text/html,hi").opaque);
    }

    @Test public void detectsPlainAndObfuscatedIpAddresses() {
        assertEquals(ParsedUrl.IpKind.IPV4, UrlParser.parse("http://192.168.1.1/").ipKind);
        assertEquals(ParsedUrl.IpKind.IPV4_OBFUSCATED, UrlParser.parse("http://3232235777/").ipKind);
        assertEquals(ParsedUrl.IpKind.IPV4_OBFUSCATED, UrlParser.parse("http://0xC0.0xA8.1.1/").ipKind);
        assertEquals(ParsedUrl.IpKind.IPV4_OBFUSCATED, UrlParser.parse("http://0300.0250.1.1/").ipKind);
        assertEquals(ParsedUrl.IpKind.IPV4_OBFUSCATED, UrlParser.parse("http://0x7f.1/").ipKind);
        assertEquals(ParsedUrl.IpKind.IPV6, UrlParser.parse("http://[::1]:80/").ipKind);
        assertEquals(ParsedUrl.IpKind.NONE, UrlParser.parse("http://example.com/").ipKind);
        assertEquals(ParsedUrl.IpKind.NONE, UrlParser.parse("http://v1.2.3.example.com/").ipKind);
    }

    @Test public void percentEncodedHostIsDecodedAndFlagged() {
        ParsedUrl u = UrlParser.parse("https://%65xample.com/");
        assertTrue(u.valid);
        assertTrue(u.hostPercentEncoded);
        assertEquals("example.com", u.host);
    }

    @Test public void internationalisedHostGetsPunycodeAndUnicodeForms() {
        ParsedUrl u = UrlParser.parse("https://p\u0430ypal.com/");
        assertTrue(u.valid);
        assertTrue(u.host.startsWith("xn--"));
        assertEquals("p\u0430ypal.com", u.unicodeHost);
    }

    @Test public void invisibleCharactersAreFlaggedAndMadeVisible() {
        ParsedUrl u = UrlParser.parse("https://example.com/\u202Epath");
        assertTrue(u.valid);
        assertTrue(u.hasInvisible);
        assertTrue(UrlParser.visible(u.raw, 100).contains("<U+202E>"));
    }

    @Test(timeout = 5000) public void veryLongInputIsBoundedAndDoesNotCrash() {
        StringBuilder b = new StringBuilder("https://example.com/");
        for (int i = 0; i < 200_000; i++) b.append('a');
        ParsedUrl u = UrlParser.parse(b.toString());
        assertTrue(u.valid);
        assertTrue(u.truncated);
        assertEquals(Limits.MAX_URL_CHARS, u.raw.length());
        String shown = UrlParser.visible(b.toString(), Limits.MAX_DISPLAY_CHARS);
        assertTrue(shown.length() < Limits.MAX_DISPLAY_CHARS + 60);
    }

    @Test public void registrableDomainHandlesMultiPartSuffixes() {
        assertEquals("example.co.uk", HostUtils.registrableDomain("mail.example.co.uk"));
        assertEquals("example.com", HostUtils.registrableDomain("a.b.example.com"));
        assertEquals("example.com", HostUtils.registrableDomain("example.com"));
        assertEquals("co.uk", HostUtils.publicSuffix("example.co.uk"));
    }
}
