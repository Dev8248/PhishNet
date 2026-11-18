package com.phishnet.app.analysis;

import static org.junit.Assert.*;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Random;
import java.util.Set;
import org.junit.Test;

public class SubtitlesTest {

    /** Random source that returns scripted values, to prove the pick is a direct draw. */
    private static final class Scripted extends Random {
        private final int[] values;
        private int i;
        Scripted(int... values) { this.values = values; }
        @Override public int nextInt(int bound) { return values[i++ % values.length] % bound; }
    }

    @Test public void eachLevelHasExactlyEightDistinctSubtitles() {
        for (RiskLevel level : RiskLevel.values()) {
            String[] s = Subtitles.options(level);
            assertEquals(8, s.length);
            assertEquals(8, new HashSet<>(Arrays.asList(s)).size());
        }
    }

    @Test public void subtitlesMatchTheSpecificationExactly() {
        assertEquals("No obvious warning signs found", Subtitles.SAFE[0]);
        assertEquals("Low risk by the checks available", Subtitles.SAFE[7]);
        assertEquals("Use caution before opening", Subtitles.MODERATE[0]);
        assertEquals("Proceed only if you accept the risk", Subtitles.MODERATE[7]);
        assertEquals("High risk \u2014 do not open", Subtitles.RISKY[0]);
        assertEquals("High risk \u2014 close this message", Subtitles.RISKY[7]);
    }

    @Test public void pickUsesTheDrawnIndexForTheMatchingLevel() {
        Subtitles s = new Subtitles(new Scripted(0, 3, 7));
        assertEquals(Subtitles.SAFE[0], s.pick(RiskLevel.APPEARS_SAFE));
        assertEquals(Subtitles.MODERATE[3], s.pick(RiskLevel.SUSPICIOUS));
        assertEquals(Subtitles.RISKY[7], s.pick(RiskLevel.HIGH_RISK));
    }

    @Test public void everySubtitleIsReachableAndStaysInTheRightSet() {
        Subtitles s = new Subtitles(new Random(42));
        for (RiskLevel level : RiskLevel.values()) {
            List<String> allowed = Arrays.asList(Subtitles.options(level));
            Set<String> seen = new HashSet<>();
            for (int i = 0; i < 2000; i++) {
                String pick = s.pick(level);
                assertTrue(allowed.contains(pick));
                seen.add(pick);
            }
            assertEquals(8, seen.size());
        }
    }

    @Test public void rescanningTheSameLinkDrawsIndependentlyWhileResultStaysIdentical() {
        Subtitles s = new Subtitles(new Scripted(1, 5, 2));
        AnalysisResult first = RiskAnalyzer.analyze("http://example.com");
        AnalysisResult second = RiskAnalyzer.analyze("http://example.com");
        String a = s.pick(first.level());
        String b = s.pick(second.level());
        String c = s.pick(second.level());
        assertEquals(Subtitles.MODERATE[1], a);
        assertEquals(Subtitles.MODERATE[5], b);
        assertEquals(Subtitles.MODERATE[2], c);
        assertEquals(first.level(), second.level());
        assertEquals(first.score(), second.score());
    }
}
