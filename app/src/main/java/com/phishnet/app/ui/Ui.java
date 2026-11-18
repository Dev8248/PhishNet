package com.phishnet.app.ui;

import android.content.Context;
import android.content.res.ColorStateList;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.RippleDrawable;
import android.os.Build;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

/** Small helpers for the programmatic, monochrome UI. Text sizes are in sp so system font scaling applies. */
public final class Ui {
    public static final int BG = 0xFF0B1220; // Main background
    public static final int SECONDARY_BG = 0xFF111C2E;
    public static final int CARD_BG = 0xFF17243A;
    public static final int PRIMARY_BLUE = 0xFF38BDF8;
    public static final int SECONDARY_BLUE = 0xFF2563EB;
    
    public static final int INK = 0xFFF8FAFC; // Main text
    public static final int MUTED = 0xFFAAB8CC; // Secondary text
    public static final int LINE = 0xFF2563EB; // Re-using secondary blue for lines
    public static final int SOFT = 0xFF17243A; // Re-using card bg

    // Risk indicator colours
    public static final int GREEN = 0xFF22C55E;
    public static final int YELLOW = 0xFFFBBF24;
    public static final int ORANGE = 0xFFF97316;
    public static final int RED = 0xFFEF4444;

    public static int dp(Context c, float v) {
        return Math.round(v * c.getResources().getDisplayMetrics().density);
    }

    public static TextView text(Context c, CharSequence s, float sp, boolean bold, int color) {
        TextView t = new TextView(c);
        t.setText(s);
        t.setTextSize(TypedValue.COMPLEX_UNIT_SP, sp);
        t.setTextColor(color);
        t.setLineSpacing(0f, 1.12f);
        if (bold) t.setTypeface(Typeface.DEFAULT_BOLD);
        return t;
    }

    /** Marks a text view as a heading for screen readers (API 28+). */
    public static TextView heading(TextView t) {
        if (Build.VERSION.SDK_INT >= 28) t.setAccessibilityHeading(true);
        return t;
    }

    public static Button button(Context c, String label, boolean filled, View.OnClickListener l) {
        Button b = new Button(c);
        b.setText(label);
        b.setAllCaps(false);
        b.setTextSize(TypedValue.COMPLEX_UNIT_SP, 16);
        b.setTypeface(Typeface.DEFAULT_BOLD);
        b.setMinHeight(dp(c, 52));
        b.setMinimumHeight(dp(c, 52));
        GradientDrawable bg = new GradientDrawable();
        bg.setCornerRadius(dp(c, 12));
        if (filled) {
            bg.setColor(PRIMARY_BLUE);
            b.setTextColor(BG);
        } else {
            bg.setColor(CARD_BG);
            bg.setStroke(dp(c, 2), PRIMARY_BLUE);
            b.setTextColor(PRIMARY_BLUE);
        }
        b.setBackground(new RippleDrawable(ColorStateList.valueOf(0x33FFFFFF), bg, null));
        b.setStateListAnimator(null);
        b.setOnClickListener(l);
        return b;
    }

    /** Low-emphasis text button (at least 48dp tall). */
    public static TextView linkButton(Context c, String label, View.OnClickListener l) {
        TextView t = text(c, label, 16, true, PRIMARY_BLUE);
        t.setPaintFlags(t.getPaintFlags() | android.graphics.Paint.UNDERLINE_TEXT_FLAG);
        t.setGravity(Gravity.CENTER);
        t.setMinHeight(dp(c, 48));
        t.setClickable(true);
        t.setFocusable(true);
        t.setOnClickListener(l);
        return t;
    }

    public static GradientDrawable box(Context c, int fill, boolean outlined) {
        GradientDrawable g = new GradientDrawable();
        g.setColor(fill);
        g.setCornerRadius(dp(c, 16));
        if (outlined) g.setStroke(dp(c, 2), SECONDARY_BLUE);
        return g;
    }

    public static LinearLayout column(Context c) {
        LinearLayout l = new LinearLayout(c);
        l.setOrientation(LinearLayout.VERTICAL);
        int p = dp(c, 20);
        l.setPadding(p, p, p, p);
        return l;
    }

    public static ScrollView scroll(Context c, View content) {
        ScrollView s = new ScrollView(c);
        s.setFillViewport(true);
        s.setBackgroundColor(BG);
        s.addView(content, new ViewGroup.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));
        return s;
    }

    public static void add(LinearLayout parent, View child, int topDp) {
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.topMargin = dp(parent.getContext(), topDp);
        parent.addView(child, lp);
    }

    private Ui() {}
}
