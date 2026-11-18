package com.phishnet.app.analysis;

import java.security.SecureRandom;
import java.util.Random;

/**
 * Picks one subtitle at random for each completed scan. The choice is independent every time,
 * including for rescans of the same link, and never influences level, score or evidence.
 */
public final class Subtitles {
    public static final String[] SAFE = {
            "No obvious warning signs found",
            "Looks low risk based on this scan",
            "No known red flags detected",
            "This link appears low risk",
            "Nothing suspicious stood out",
            "Checks look clear so far",
            "No suspicious patterns found",
            "Low risk by the checks available"};

    public static final String[] MODERATE = {
            "Use caution before opening",
            "This link needs a closer look",
            "Some warning signs were found",
            "Open only if you trust the sender",
            "Verify the sender through another channel",
            "Pause and check the destination",
            "Not recommended without verification",
            "Proceed only if you accept the risk"};

    public static final String[] RISKY = {
            "High risk \u2014 do not open",
            "Danger \u2014 avoid this link",
            "Do not enter passwords here",
            "Do not share payment details",
            "This link appears dangerous",
            "Block and report this message",
            "Leave this link unopened",
            "High risk \u2014 close this message"};

    private final Random random;

    public Subtitles() {
        this(new SecureRandom());
    }

    public Subtitles(Random random) {
        this.random = random;
    }

    public String pick(RiskLevel level) {
        String[] set = options(level);
        return set[random.nextInt(set.length)];
    }

    public static String[] options(RiskLevel level) {
        switch (level) {
            case APPEARS_SAFE: return SAFE;
            case SUSPICIOUS: return MODERATE;
            default: return RISKY;
        }
    }
}
