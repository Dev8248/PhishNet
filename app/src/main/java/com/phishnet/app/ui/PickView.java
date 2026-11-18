package com.phishnet.app.ui;

import android.content.Context;
import android.graphics.Typeface;
import android.util.TypedValue;
import android.view.View;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import com.phishnet.app.analysis.Limits;
import com.phishnet.app.analysis.UrlParser;

import java.util.List;

/**
 * Shows the destination(s) that were extracted, BEFORE any analysis, and lets the user choose which
 * one to inspect. Nothing here opens a link.
 */
public final class PickView implements ScreenView {
    public interface Listener {
        void onChoose(String url);
        void onBack();
    }

    private final ScrollView root;
    private final TextView heading;

    public PickView(Context c, String source, List<String> urls, boolean messageText, final Listener l) {
        LinearLayout col = Ui.column(c);
        boolean one = urls.size() == 1;
        heading = Ui.heading(Ui.text(c, one ? "Link found" : "Which link do you want to check?", 26, true, Ui.INK));
        Ui.add(col, heading, 0);
        Ui.add(col, Ui.text(c, "Found in " + source + ". PhishNet has not opened "
                + (one ? "it." : "any of them."), 16, false, Ui.MUTED), 6);
        if (messageText) {
            Ui.add(col, Ui.text(c, "The wording of your message will be checked too.", 16, false, Ui.MUTED), 4);
        }
        for (final String url : urls) {
            LinearLayout card = new LinearLayout(c);
            card.setOrientation(LinearLayout.VERTICAL);
            int p = Ui.dp(c, 12);
            card.setPadding(p, p, p, p);
            card.setBackground(Ui.box(c, Ui.SOFT, true));
            TextView t = Ui.text(c, UrlParser.visible(url, Limits.MAX_DISPLAY_CHARS), 14, false, Ui.INK);
            t.setTypeface(Typeface.MONOSPACE);
            t.setTextSize(TypedValue.COMPLEX_UNIT_SP, 14);
            t.setTextIsSelectable(true);
            Ui.add(card, t, 0);
            Ui.add(card, Ui.button(c, "Check this link", true, new View.OnClickListener() {
                @Override public void onClick(View v) { l.onChoose(url); }
            }), 10);
            Ui.add(col, card, 14);
        }
        Ui.add(col, Ui.button(c, "Back", false, new View.OnClickListener() {
            @Override public void onClick(View v) { l.onBack(); }
        }), 20);
        root = Ui.scroll(c, col);
    }

    @Override public View view() { return root; }
    @Override public View focusTarget() { return heading; }
}
