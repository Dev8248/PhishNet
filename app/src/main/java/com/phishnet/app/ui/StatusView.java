package com.phishnet.app.ui;

import android.content.Context;
import android.view.Gravity;
import android.view.View;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.TextView;

/** Loading and error screens. */
public final class StatusView implements ScreenView {
    private final View root;
    private final View focus;

    private StatusView(View root, View focus) {
        this.root = root;
        this.focus = focus;
    }

    /** Indeterminate progress with a Cancel action. */
    public static StatusView loading(Context c, String message, View.OnClickListener cancel) {
        LinearLayout col = Ui.column(c);
        col.setGravity(Gravity.CENTER);
        ProgressBar bar = new ProgressBar(c);
        bar.setIndeterminate(true);
        col.addView(bar, new LinearLayout.LayoutParams(Ui.dp(c, 56), Ui.dp(c, 56)));
        TextView t = Ui.text(c, message, 18, true, Ui.INK);
        t.setGravity(Gravity.CENTER);
        t.setAccessibilityLiveRegion(View.ACCESSIBILITY_LIVE_REGION_POLITE);
        Ui.add(col, t, 16);
        Ui.add(col, Ui.button(c, "Cancel", false, cancel), 24);
        return new StatusView(Ui.scroll(c, col), t);
    }

    /** Plain-language explanation and one recovery action. */
    public static StatusView error(Context c, String title, String message, String actionLabel,
                                   View.OnClickListener action) {
        LinearLayout col = Ui.column(c);
        TextView h = Ui.heading(Ui.text(c, title, 26, true, Ui.INK));
        Ui.add(col, h, 8);
        TextView m = Ui.text(c, message, 16, false, Ui.INK);
        m.setTextIsSelectable(true);
        Ui.add(col, m, 12);
        Ui.add(col, Ui.button(c, actionLabel, true, action), 24);
        return new StatusView(Ui.scroll(c, col), h);
    }

    @Override public View view() { return root; }
    @Override public View focusTarget() { return focus; }
}
