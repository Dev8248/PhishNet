package com.phishnet.app.analysis;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Wording indicators for message text. Real organisations use some of these words too, and scammers
 * can avoid all of them, so these only nudge the score and are capped at {@link #MAX_POINTS}.
 */
final class TextRules {
    static final int MAX_POINTS = 40;

    private static final String[] URGENCY = {
            "urgent", "urgently", "immediately", "act now", "right away", "within 24 hours", "within 48 hours",
            "last warning", "final notice", "final warning", "expires today", "expires soon", "limited time",
            "asap", "hurry", "today only"};
    private static final String[] SENSITIVE = {
            "password", "passcode", "otp", "one-time code", "one time code", "one-time password", "one time password",
            "verification code", "security code", "cvv", "card number", "debit card", "credit card", "pin",
            "bank details", "bank account", "account number", "login details", "login credentials", "credentials",
            "seed phrase", "recovery phrase", "secret phrase", "aadhaar", "pan card", "ssn", "social security",
            "net banking", "internet banking"};
    private static final String[] REQUEST_VERBS = {
            "enter", "share", "send", "provide", "confirm", "reply", "update", "verify", "submit", "give", "tell",
            "reconfirm", "type", "fill"};
    private static final String[] PAYMENT = {
            "pay now", "payment failed", "payment pending", "pending payment", "outstanding payment", "unpaid",
            "processing fee", "customs fee", "delivery fee", "redelivery fee", "refund", "gift card",
            "wire transfer", "bitcoin", "crypto", "upi", "send money", "overdue", "kindly pay"};
    private static final String[] PRIZE = {
            "you have won", "you've won", "you won", "congratulations", "claim your", "lottery", "prize",
            "free gift", "cashback", "reward points", "lucky winner"};
    private static final String[] THREAT = {
            "legal action", "arrest", "will be suspended", "will be blocked", "will be closed", "will be deactivated",
            "account suspended", "account locked", "account blocked", "unauthorized", "unusual activity",
            "suspicious activity", "suspended", "deactivated", "court", "police"};

    static void apply(String message, List<Finding> out) {
        if (message == null) return;
        String text = message.length() > Limits.MAX_INPUT_CHARS ? message.substring(0, Limits.MAX_INPUT_CHARS) : message;
        text = text.toLowerCase(Locale.ROOT).replace('\u2019', '\'');
        int budget = MAX_POINTS;

        List<String> sensitive = matches(text, SENSITIVE);
        if (!sensitive.isEmpty() && hasUnnegatedRequest(text)) {
            int pts = Math.min(budget, Math.min(30, 20 + 8 * (sensitive.size() - 1)));
            budget -= pts;
            add(out, "TEXT-SENSITIVE", "Asks for sensitive information",
                    "The message appears to ask you to hand over " + quote(sensitive)
                            + ". Genuine banks and services do not ask for these in messages.", pts);
        }
        budget = tier(text, URGENCY, 6, 12, budget, out, "TEXT-URGENCY", "Urgent or pressuring wording",
                "Scam messages push you to act before you think.");
        budget = tier(text, PAYMENT, 6, 12, budget, out, "TEXT-PAYMENT", "Payment or fee demand",
                "Unexpected fees, refunds and payment demands are a common scam hook.");
        budget = tier(text, PRIZE, 8, 8, budget, out, "TEXT-PRIZE", "Prize or reward claim",
                "Unexpected prizes and rewards are a common scam hook.");
        tier(text, THREAT, 6, 12, budget, out, "TEXT-THREAT", "Threatening wording",
                "Threats of suspension, arrest or loss are used to cause panic.");
    }

    private static int tier(String text, String[] phrases, int each, int cap, int budget, List<Finding> out,
                            String id, String title, String why) {
        List<String> hit = matches(text, phrases);
        if (hit.isEmpty() || budget <= 0) return budget;
        int pts = Math.min(budget, Math.min(cap, each * hit.size()));
        add(out, id, title, "Matched " + quote(hit) + ". " + why + " Real organisations use some of these words too, "
                + "so this is only a hint.", pts);
        return budget - pts;
    }

    private static void add(List<Finding> out, String id, String title, String detail, int pts) {
        out.add(new Finding(id, title, detail, pts, Finding.Source.MESSAGE));
    }

    private static List<String> matches(String text, String[] phrases) {
        List<String> hit = new ArrayList<>();
        for (String p : phrases) {
            if (indexOfPhrase(text, p, 0) >= 0) hit.add(p);
        }
        return hit;
    }

    /** True if some request verb ("share", "enter"...) is not directly negated ("do not share"). */
    private static boolean hasUnnegatedRequest(String text) {
        for (String v : REQUEST_VERBS) {
            int from = 0;
            int idx;
            while ((idx = indexOfPhrase(text, v, from)) >= 0) {
                String before = text.substring(Math.max(0, idx - 20), idx);
                boolean negated = before.contains("not ") || before.contains("never ") || before.contains("n't ");
                if (!negated) return true;
                from = idx + v.length();
            }
        }
        return false;
    }

    /** indexOf that only accepts matches not glued to letters or digits. */
    private static int indexOfPhrase(String text, String phrase, int from) {
        int idx = from;
        while ((idx = text.indexOf(phrase, idx)) >= 0) {
            boolean startOk = idx == 0 || !Character.isLetterOrDigit(text.charAt(idx - 1));
            int end = idx + phrase.length();
            boolean endOk = end >= text.length() || !Character.isLetterOrDigit(text.charAt(end));
            if (startOk && endOk) return idx;
            idx++;
        }
        return -1;
    }

    private static String quote(List<String> words) {
        List<String> q = new ArrayList<>();
        for (int i = 0; i < words.size() && i < 3; i++) q.add("\"" + words.get(i) + "\"");
        return String.join(", ", q);
    }

    private TextRules() {}
}
