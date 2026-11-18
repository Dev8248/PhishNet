package com.phishnet.app.ui;

import android.animation.AnimatorSet;
import android.animation.ObjectAnimator;
import android.animation.ValueAnimator;
import android.content.Context;
import android.graphics.drawable.GradientDrawable;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.animation.LinearInterpolator;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.TextView;

import java.util.ArrayList;
import java.util.List;

public class ScanProgressView implements ScreenView {

    public enum StageStatus { PENDING, RUNNING, SUCCESS, WARNING, FAILURE }

    public static class Stage {
        public final int id;
        public final String name;
        public StageStatus status = StageStatus.PENDING;
        public LinearLayout view;
        public ImageView iconView;
        public TextView nameView;
        public ProgressBar progressView;

        public Stage(int id, String name) {
            this.id = id;
            this.name = name;
        }
    }

    private final ScrollView root;
    private final LinearLayout column;
    private final TextView title;
    private final ImageView shieldIcon;
    private final ProgressBar mainProgress;

    private final List<Stage> stages = new ArrayList<>();
    private AnimatorSet pulseAnim;

    public ScanProgressView(Context c) {
        column = Ui.column(c);
        column.setGravity(Gravity.CENTER_HORIZONTAL);

        title = Ui.heading(Ui.text(c, "Analyzing...", 24, true, Ui.INK));
        title.setGravity(Gravity.CENTER);
        Ui.add(column, title, 24);

        // Shield Animation
        FrameLayout shieldContainer = new FrameLayout(c);
        int size = Ui.dp(c, 100);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(size, size);
        lp.topMargin = Ui.dp(c, 32);
        lp.bottomMargin = Ui.dp(c, 32);
        shieldContainer.setLayoutParams(lp);

        shieldIcon = new ImageView(c);
        // We need a shield icon. If not available, we can draw something or use a built-in.
        // For now, let's draw a rounded shield using GradientDrawable.
        GradientDrawable shieldDrawable = new GradientDrawable();
        shieldDrawable.setShape(GradientDrawable.OVAL);
        shieldDrawable.setColor(Ui.PRIMARY_BLUE);
        shieldIcon.setBackground(shieldDrawable);

        FrameLayout.LayoutParams iconLp = new FrameLayout.LayoutParams(size, size, Gravity.CENTER);
        shieldContainer.addView(shieldIcon, iconLp);

        column.addView(shieldContainer);

        startShieldAnimation();

        mainProgress = new ProgressBar(c, null, android.R.attr.progressBarStyleHorizontal);
        mainProgress.setIndeterminate(true);
        Ui.add(column, mainProgress, 16);

        // Add stages list
        LinearLayout stagesList = new LinearLayout(c);
        stagesList.setOrientation(LinearLayout.VERTICAL);
        Ui.add(column, stagesList, 32);

        stages.add(new Stage(1, "Validating URL"));
        stages.add(new Stage(2, "Checking Google Safe Browsing"));
        stages.add(new Stage(3, "Analyzing domain reputation"));
        stages.add(new Stage(4, "Checking HTTPS and certificate information"));
        stages.add(new Stage(5, "Inspecting redirects"));
        stages.add(new Stage(6, "Analyzing website content"));
        stages.add(new Stage(7, "Detecting phishing indicators"));
        stages.add(new Stage(8, "Calculating final risk score"));

        for (Stage s : stages) {
            s.view = new LinearLayout(c);
            s.view.setOrientation(LinearLayout.HORIZONTAL);
            s.view.setGravity(Gravity.CENTER_VERTICAL);
            s.view.setPadding(0, Ui.dp(c, 8), 0, Ui.dp(c, 8));

            s.iconView = new ImageView(c);
            GradientDrawable circle = new GradientDrawable();
            circle.setShape(GradientDrawable.OVAL);
            circle.setColor(Ui.MUTED);
            s.iconView.setBackground(circle);
            s.view.addView(s.iconView, new LinearLayout.LayoutParams(Ui.dp(c, 24), Ui.dp(c, 24)));

            s.nameView = Ui.text(c, s.name, 16, false, Ui.MUTED);
            LinearLayout.LayoutParams nameLp = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
            nameLp.leftMargin = Ui.dp(c, 16);
            s.view.addView(s.nameView, nameLp);

            s.progressView = new ProgressBar(c);
            s.progressView.setIndeterminate(true);
            s.progressView.setVisibility(View.GONE);
            s.view.addView(s.progressView, new LinearLayout.LayoutParams(Ui.dp(c, 20), Ui.dp(c, 20)));

            stagesList.addView(s.view);
        }

        root = Ui.scroll(c, column);
    }

    private void startShieldAnimation() {
        ObjectAnimator scaleX = ObjectAnimator.ofFloat(shieldIcon, "scaleX", 1f, 1.1f, 1f);
        scaleX.setRepeatCount(ValueAnimator.INFINITE);
        scaleX.setDuration(1500);

        ObjectAnimator scaleY = ObjectAnimator.ofFloat(shieldIcon, "scaleY", 1f, 1.1f, 1f);
        scaleY.setRepeatCount(ValueAnimator.INFINITE);
        scaleY.setDuration(1500);

        pulseAnim = new AnimatorSet();
        pulseAnim.playTogether(scaleX, scaleY);
        pulseAnim.start();
    }

    public void updateStage(int stageId, StageStatus status) {
        for (Stage s : stages) {
            if (s.id == stageId) {
                s.status = status;
                updateStageUi(s);
                break;
            }
        }
    }

    private void updateStageUi(Stage s) {
        GradientDrawable bg = (GradientDrawable) s.iconView.getBackground();
        s.progressView.setVisibility(View.GONE);
        s.nameView.setTextColor(Ui.INK);
        s.iconView.setImageDrawable(null);

        switch (s.status) {
            case PENDING:
                bg.setColor(Ui.SECONDARY_BG);
                s.nameView.setTextColor(Ui.MUTED);
                break;
            case RUNNING:
                bg.setColor(Ui.PRIMARY_BLUE);
                s.progressView.setVisibility(View.VISIBLE);
                break;
            case SUCCESS:
                bg.setColor(Ui.GREEN);
                s.iconView.setImageResource(android.R.drawable.checkbox_on_background);
                break;
            case WARNING:
                bg.setColor(Ui.ORANGE);
                s.iconView.setImageResource(android.R.drawable.stat_sys_warning);
                break;
            case FAILURE:
                bg.setColor(Ui.RED);
                s.iconView.setImageResource(android.R.drawable.ic_delete);
                break;
        }
        s.iconView.invalidate();
    }

    public void stopAnimation() {
        if (pulseAnim != null) {
            pulseAnim.cancel();
        }
    }

    @Override public View view() { return root; }
    @Override public View focusTarget() { return title; }
}
