package com.phishnet.app.ui;

import android.content.Context;
import android.graphics.Typeface;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import com.phishnet.app.analysis.AnalysisResult;
import com.phishnet.app.analysis.Finding;
import com.phishnet.app.analysis.Limits;
import com.phishnet.app.analysis.OnlineStatus;
import com.phishnet.app.analysis.RiskLevel;
import com.phishnet.app.analysis.RiskScorer;
import com.phishnet.app.analysis.UrlParser;

/**
 * Result screen: level (written label + shape + colour), one subtitle, score with its meaning, the
 * analysed destination, scope (offline/online/incomplete), the evidence list and the limits.
 * Opening the link is never the default action and is not offered at all for Risky results.
 */
public final class ResultView implements ScreenView {
    public interface Listener {
        void onScanAnother();
        void onCheckOnline();
        void onCopy();
        void onOpen();
    }

    private final ScrollView root;
    private final TextView headline;

    public ResultView(Context c, AnalysisResult r, String subtitle, boolean onlineConfigured,
                      String onlineName, final Listener l) {
        LinearLayout col = Ui.column(c);
        RiskLevel level = r.level();

        col.addView(new RiskBadgeView(c, level), new LinearLayout.LayoutParams(Ui.dp(c, 88), Ui.dp(c, 88)));

        headline = Ui.heading(Ui.text(c, level.label(), 34, true, Ui.INK));
        headline.setContentDescription("Result: " + level.label() + ". " + subtitle);
        Ui.add(col, headline, 12);
        TextView sub = Ui.text(c, subtitle, 18, false, Ui.INK);
        sub.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO); // read as part of the headline
        Ui.add(col, sub, 2);

        Ui.add(col, Ui.text(c, "Risk score: " + r.score() + " / " + RiskScorer.MAX_SCORE, 16, true, Ui.INK), 14);
        Ui.add(col, Ui.text(c, "Worked out from the documented rules listed below. It is not a probability that "
                + "you will be attacked. Safe means only that no obvious warning signs were found by the checks "
                + "available; it is never a guarantee.", 14, false, Ui.MUTED), 2);

        // Destination
        Ui.add(col, section(c, "Destination analysed"), 22);
        TextView url = Ui.text(c, UrlParser.visible(r.url(), Limits.MAX_DISPLAY_CHARS), 14, false, Ui.INK);
        url.setTypeface(Typeface.MONOSPACE);
        url.setTextIsSelectable(true);
        int p = Ui.dp(c, 12);
        url.setPadding(p, p, p, p);
        url.setBackground(Ui.box(c, Ui.SOFT, true));
        Ui.add(col, url, 6);

        // Scope
        Ui.add(col, section(c, "What was checked"), 22);
        String scope;
        if (r.onlineStatus() == OnlineStatus.COMPLETED) {
            scope = "On this device, plus an online lookup with " + r.onlineServiceName()
                    + " that you chose to run. Local findings and online findings are labelled separately below.";
        } else {
            scope = "Offline: checked on this device only. No threat database or live reputation service was consulted"
                    + (r.messageAnalysed() ? ", and the message wording was checked too." : ".");
        }
        Ui.add(col, Ui.text(c, scope, 15, false, Ui.INK), 6);
        Ui.add(col, Ui.text(c, onlineLine(r, onlineConfigured, onlineName), 15, false, Ui.INK), 6);
        if (!r.incompleteReasons().isEmpty()) {
            StringBuilder b = new StringBuilder("This scan is incomplete, so it can't be rated Safe:");
            for (String s : r.incompleteReasons()) b.append("\n\u2022 ").append(s);
            Ui.add(col, Ui.text(c, b.toString(), 15, true, Ui.INK), 8);
        }

        // Evidence
        Ui.add(col, section(c, "Evidence"), 22);
        if (r.findings().isEmpty()) {
            Ui.add(col, Ui.text(c, "No warning signs were found by the checks that ran.", 15, false, Ui.INK), 6);
        }
        for (Finding f : r.findings()) {
            Ui.add(col, evidenceRow(c, f), 8);
        }

        Ui.add(col, section(c, "What PhishNet can't tell you"), 22);
        Ui.add(col, Ui.text(c, "It can't tell whether your device is infected, whether a link is connected to your "
                + "bank account, or who really sent a message. It does not scan your device or other apps, and it "
                + "cannot catch every attack, especially new ones.", 15, false, Ui.INK), 6);

        // Actions
        Ui.add(col, Ui.button(c, "Scan another", true, new View.OnClickListener() {
            @Override public void onClick(View v) { l.onScanAnother(); }
        }), 24);
        String onlineLabel = onlineConfigured ? "Check online\u2026" : "Check online (DNS & Redirects)\u2026";
        android.widget.Button online = Ui.button(c, onlineLabel, false, new View.OnClickListener() {
            @Override public void onClick(View v) { l.onCheckOnline(); }
        });
        Ui.add(col, online, 10);
        Ui.add(col, Ui.button(c, "Copy link", false, new View.OnClickListener() {
            @Override public void onClick(View v) { l.onCopy(); }
        }), 10);

        if (level == RiskLevel.NOT_SAFE || level == RiskLevel.HIGH_RISK) {
            Ui.add(col, Ui.text(c, "PhishNet doesn't offer an Open button for high-risk results. If this arrived in a "
                    + "message, don't reply or enter anything, and consider blocking and reporting the sender.",
                    14, false, Ui.MUTED), 14);
        } else if (r.isWebLink()) {
            TextView open = Ui.linkButton(c, "Open link in browser\u2026", new View.OnClickListener() {
                @Override public void onClick(View v) { l.onOpen(); }
            });
            Ui.add(col, open, 10);
        }
        root = Ui.scroll(c, col);
    }

    private static String onlineLine(AnalysisResult r, boolean configured, String name) {
        switch (r.onlineStatus()) {
            case COMPLETED:
                return "Online check: completed with " + r.onlineServiceName() + ".";
            case FAILED:
                return "Online check: failed. Local results are shown, marked incomplete.";
            case INCONCLUSIVE:
                return "Online check: no usable answer. Local results are shown, marked incomplete.";
            default:
                return configured
                        ? "Online check: not run. Nothing was sent anywhere. You can run one with \"Check online\" (DNS & Redirect checks + " + name + ")."
                        : "Online check: DNS & Redirect analysis available. Backend threat intelligence not configured. You can still run the online check to verify the link.";
        }
    }

    private static TextView section(Context c, String s) {
        return Ui.heading(Ui.text(c, s, 18, true, Ui.INK));
    }

    private static View evidenceRow(Context c, Finding f) {
        LinearLayout row = new LinearLayout(c);
        row.setOrientation(LinearLayout.VERTICAL);
        int p = Ui.dp(c, 12);
        row.setPadding(p, p, p, p);
        row.setBackground(Ui.box(c, Ui.BG, true));

        LinearLayout top = new LinearLayout(c);
        top.setOrientation(LinearLayout.HORIZONTAL);
        TextView title = Ui.text(c, f.title, 16, true, Ui.INK);
        top.addView(title, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        TextView pts = Ui.text(c, f.points > 0 ? "+" + f.points : "info", 16, true, Ui.MUTED);
        pts.setGravity(Gravity.END);
        pts.setContentDescription(f.points > 0 ? "plus " + f.points + " points" : "information only, no points");
        top.addView(pts, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));
        Ui.add(row, top, 0);

        String source;
        switch (f.source) {
            case MESSAGE: source = "Message wording \u00B7 local"; break;
            case ONLINE: source = "Online check"; break;
            default: source = "Link \u00B7 local"; break;
        }
        Ui.add(row, Ui.text(c, source, 12, false, Ui.MUTED), 2);
        Ui.add(row, Ui.text(c, f.detail, 14, false, Ui.INK), 4);
        return row;
    }

    @Override public View view() { return root; }
    @Override public View focusTarget() { return headline; }
}
