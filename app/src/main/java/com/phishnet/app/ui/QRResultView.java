package com.phishnet.app.ui;

import android.content.Context;
import android.graphics.Typeface;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import com.phishnet.app.analysis.Finding;
import com.phishnet.app.analysis.Limits;
import com.phishnet.app.analysis.RiskLevel;
import com.phishnet.app.analysis.RiskScorer;
import com.phishnet.app.analysis.UrlParser;
import com.phishnet.app.models.QRPayload;
import com.phishnet.app.models.QRResult;

public final class QRResultView implements ScreenView {
    public interface Listener {
        void onScanAnother();
        void onCopy();
        void onOpen();
    }

    private final ScrollView root;
    private final TextView headline;

    public QRResultView(Context c, QRResult r, final Listener l) {
        LinearLayout col = Ui.column(c);
        RiskLevel level = r.level;

        col.addView(new RiskBadgeView(c, level), new LinearLayout.LayoutParams(Ui.dp(c, 88), Ui.dp(c, 88)));

        headline = Ui.heading(Ui.text(c, level.label(), 34, true, Ui.INK));
        Ui.add(col, headline, 12);

        TextView sub = Ui.text(c, "QR Payload: " + r.payload.type.name(), 18, false, Ui.INK);
        Ui.add(col, sub, 2);

        Ui.add(col, Ui.text(c, "Risk score: " + r.score + " / " + RiskScorer.MAX_SCORE, 16, true, Ui.INK), 14);

        // Destination / Content
        Ui.add(col, section(c, "QR Content"), 22);
        String visibleContent = r.payload.rawContent;
        if (visibleContent.length() > Limits.MAX_DISPLAY_CHARS) {
            visibleContent = visibleContent.substring(0, Limits.MAX_DISPLAY_CHARS) + "...";
        }

        TextView contentText = Ui.text(c, visibleContent, 14, false, Ui.INK);
        contentText.setTypeface(Typeface.MONOSPACE);
        contentText.setTextIsSelectable(true);
        int p = Ui.dp(c, 12);
        contentText.setPadding(p, p, p, p);
        contentText.setBackground(Ui.box(c, Ui.SOFT, true));
        Ui.add(col, contentText, 6);

        // Evidence
        Ui.add(col, section(c, "Evidence"), 22);
        if (r.qrFindings.isEmpty()) {
            Ui.add(col, Ui.text(c, "No warning signs were found by the checks that ran.", 15, false, Ui.INK), 6);
        }
        for (Finding f : r.qrFindings) {
            Ui.add(col, evidenceRow(c, f), 8);
        }

        // Actions
        Ui.add(col, Ui.button(c, "Scan another", true, new View.OnClickListener() {
            @Override public void onClick(View v) { l.onScanAnother(); }
        }), 24);
        Ui.add(col, Ui.button(c, "Copy content", false, new View.OnClickListener() {
            @Override public void onClick(View v) { l.onCopy(); }
        }), 10);
        
        if (r.payload.type == QRPayload.Type.HTTP_URL || r.payload.type == QRPayload.Type.HTTPS_URL) {
            if (level != RiskLevel.NOT_SAFE && level != RiskLevel.HIGH_RISK) {
                TextView open = Ui.linkButton(c, "Open link in browser\u2026", new View.OnClickListener() {
                    @Override public void onClick(View v) { l.onOpen(); }
                });
                Ui.add(col, open, 10);
            }
        }

        root = Ui.scroll(c, col);
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
        top.addView(pts, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));
        Ui.add(row, top, 0);
        Ui.add(row, Ui.text(c, f.detail, 14, false, Ui.INK), 4);
        return row;
    }

    @Override public View view() { return root; }
    @Override public View focusTarget() { return headline; }
}
