package com.phishnet.app.analysis;

import static org.junit.Assert.*;

import java.util.List;
import org.junit.Test;

public class UrlExtractorTest {

    @Test public void findsLinksAndIgnoresEmailsAndFileNames() {
        String text = "Hi! Your parcel is held. Pay at https://evil.example/pay?id=1, or visit www.fake-post.com. "
                + "Email me at bob@example.com. See report.pdf and file.txt (https://a.example/x).";
        List<String> urls = UrlExtractor.extract(text).urls;
        assertEquals(3, urls.size());
        assertEquals("https://evil.example/pay?id=1", urls.get(0));
        assertEquals("www.fake-post.com", urls.get(1));
        assertEquals("https://a.example/x", urls.get(2));
    }

    @Test public void acceptsBareDomainsWithKnownEndings() {
        List<String> urls = UrlExtractor.extract("go to example.com/login now").urls;
        assertEquals(1, urls.size());
        assertEquals("example.com/login", urls.get(0));
    }

    @Test public void removesDuplicatesAndKeepsOrder() {
        List<String> urls = UrlExtractor.extract("http://a.example http://b.example http://a.example").urls;
        assertEquals(2, urls.size());
        assertEquals("http://a.example", urls.get(0));
    }

    @Test public void capsTheNumberOfLinks() {
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < 40; i++) b.append("https://site").append(i).append(".example/ ");
        UrlExtractor.Extraction ex = UrlExtractor.extract(b.toString());
        assertEquals(Limits.MAX_URLS, ex.urls.size());
        assertTrue(ex.tooManyUrls);
    }

    @Test public void emptyAndNullInputGiveNoLinks() {
        assertTrue(UrlExtractor.extract(null).urls.isEmpty());
        assertTrue(UrlExtractor.extract("").urls.isEmpty());
        assertTrue(UrlExtractor.extract("no links here, just words.").urls.isEmpty());
    }

    @Test public void findsScriptLinks() {
        List<String> urls = UrlExtractor.extract("scan: javascript:alert(1)").urls;
        assertEquals(1, urls.size());
        assertEquals("javascript:alert(1)", urls.get(0));
    }

    @Test(timeout = 5000) public void veryLongTextIsBoundedAndFast() {
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < 30_000; i++) b.append("ab ");
        UrlExtractor.Extraction ex = UrlExtractor.extract(b.toString());
        assertTrue(ex.textTruncated);
    }

    @Test(timeout = 5000) public void pathologicalDottedTextDoesNotFreeze() {
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < 10_000; i++) b.append("a.");
        UrlExtractor.extract(b.toString());
        StringBuilder c = new StringBuilder();
        for (int i = 0; i < 20_000; i++) c.append('a');
        UrlExtractor.extract(c.toString());
    }
}
