package com.phishnet.app.ui;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.Path;
import android.view.View;

import com.phishnet.app.analysis.RiskLevel;

/**
 * Risk indicator drawn in code. Colour is never the only signal: each level has its own shape and
 * symbol (circle + check, triangle + "!", octagon + cross), and the written label is shown beside it.
 */
public final class RiskBadgeView extends View {
    private final RiskLevel level;
    private final Paint fill = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint glyph = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Path path = new Path();

    public RiskBadgeView(Context context, RiskLevel level) {
        super(context);
        this.level = level;
        fill.setStyle(Paint.Style.FILL);
        glyph.setStyle(Paint.Style.STROKE);
        glyph.setStrokeCap(Paint.Cap.ROUND);
        glyph.setStrokeJoin(Paint.Join.ROUND);
        // The adjacent text states the level; hide the drawing from screen readers to avoid repeating it.
        setImportantForAccessibility(IMPORTANT_FOR_ACCESSIBILITY_NO);
    }

    @Override
    protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        int s = Ui.dp(getContext(), 88);
        setMeasuredDimension(s, s);
    }

    @Override
    protected void onDraw(Canvas c) {
        float s = Math.min(getWidth(), getHeight());
        path.reset();
        switch (level) {
            case APPEARS_SAFE:
                fill.setColor(Ui.GREEN);
                glyph.setColor(0xFFFFFFFF);
                c.drawCircle(s / 2, s / 2, s * 0.48f, fill);
                glyph.setStrokeWidth(s * 0.09f);
                path.moveTo(s * 0.27f, s * 0.52f);
                path.lineTo(s * 0.43f, s * 0.67f);
                path.lineTo(s * 0.74f, s * 0.34f);
                c.drawPath(path, glyph);
                break;
            case SUSPICIOUS:
                fill.setColor(Ui.YELLOW);
                glyph.setColor(Ui.YELLOW);
                path.moveTo(s * 0.5f, s * 0.10f);
                path.lineTo(s * 0.92f, s * 0.86f);
                path.lineTo(s * 0.08f, s * 0.86f);
                path.close();
                c.drawPath(path, fill);
                glyph.setStrokeWidth(s * 0.07f); // rounds the triangle's corners
                c.drawPath(path, glyph);
                glyph.setColor(Ui.INK);
                glyph.setStrokeWidth(s * 0.085f);
                c.drawLine(s * 0.5f, s * 0.38f, s * 0.5f, s * 0.62f, glyph);
                fill.setColor(Ui.INK);
                c.drawCircle(s * 0.5f, s * 0.75f, s * 0.05f, fill);
                break;
            case HIGH_RISK:
                fill.setColor(Ui.ORANGE);
                glyph.setColor(Ui.ORANGE);
                // Draw a diamond shape for HIGH_RISK
                path.moveTo(s * 0.5f, s * 0.05f);
                path.lineTo(s * 0.95f, s * 0.5f);
                path.lineTo(s * 0.5f, s * 0.95f);
                path.lineTo(s * 0.05f, s * 0.5f);
                path.close();
                c.drawPath(path, fill);
                glyph.setStrokeWidth(s * 0.07f);
                c.drawPath(path, glyph);
                glyph.setColor(Ui.INK);
                glyph.setStrokeWidth(s * 0.085f);
                c.drawLine(s * 0.5f, s * 0.3f, s * 0.5f, s * 0.62f, glyph);
                fill.setColor(Ui.INK);
                c.drawCircle(s * 0.5f, s * 0.75f, s * 0.05f, fill);
                break;
            default:
                fill.setColor(Ui.RED);
                glyph.setColor(0xFFFFFFFF);
                for (int k = 0; k < 8; k++) {
                    double a = Math.toRadians(22.5 + 45.0 * k);
                    float x = s / 2 + (float) (Math.cos(a) * s * 0.48f);
                    float y = s / 2 + (float) (Math.sin(a) * s * 0.48f);
                    if (k == 0) path.moveTo(x, y); else path.lineTo(x, y);
                }
                path.close();
                c.drawPath(path, fill);
                glyph.setStrokeWidth(s * 0.09f);
                c.drawLine(s * 0.34f, s * 0.34f, s * 0.66f, s * 0.66f, glyph);
                c.drawLine(s * 0.66f, s * 0.34f, s * 0.34f, s * 0.66f, glyph);
                break;
        }
    }
}
