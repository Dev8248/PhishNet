package com.phishnet.app.analysis;

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.List;
import org.junit.Test;

public class RiskScorerTest {

    @Test public void classificationBoundaries() {
        assertEquals(RiskLevel.APPEARS_SAFE, RiskScorer.level(0, false));
        assertEquals(RiskLevel.APPEARS_SAFE, RiskScorer.level(19, false));
        assertEquals(RiskLevel.SUSPICIOUS, RiskScorer.level(20, false));
        assertEquals(RiskLevel.SUSPICIOUS, RiskScorer.level(39, false));
        assertEquals(RiskLevel.HIGH_RISK, RiskScorer.level(40, false));
        assertEquals(RiskLevel.NOT_SAFE, RiskScorer.level(70, false));
    }

    @Test public void incompleteChecksRaiseSafeToModerateButNeverLowerRisky() {
        assertEquals(RiskLevel.SUSPICIOUS, RiskScorer.level(0, true));
        assertEquals(RiskLevel.SUSPICIOUS, RiskScorer.level(19, true));
        assertEquals(RiskLevel.SUSPICIOUS, RiskScorer.level(35, true));
        assertEquals(RiskLevel.HIGH_RISK, RiskScorer.level(40, true));
    }

    @Test public void scoreIsSumCappedAtOneHundred() {
        List<Finding> f = new ArrayList<>();
        assertEquals(0, RiskScorer.total(f));
        f.add(new Finding("a", "a", "a", 60, Finding.Source.URL));
        f.add(new Finding("b", "b", "b", 70, Finding.Source.URL));
        assertEquals(100, RiskScorer.total(f));
    }
}
