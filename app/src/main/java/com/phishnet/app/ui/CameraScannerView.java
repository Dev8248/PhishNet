package com.phishnet.app.ui;

import android.content.Context;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.Button;

import androidx.camera.view.PreviewView;

public class CameraScannerView extends FrameLayout implements ScreenView {
    public interface Listener {
        void onCancel();
    }

    private final PreviewView previewView;
    private final Button btnCancel;

    public CameraScannerView(Context context, final Listener listener) {
        super(context);

        previewView = new PreviewView(context);
        addView(previewView, new FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));

        btnCancel = Ui.button(context, "Cancel", false, new View.OnClickListener() {
            @Override public void onClick(View v) { listener.onCancel(); }
        });

        FrameLayout.LayoutParams lp = new FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.setMargins(Ui.dp(context, 16), Ui.dp(context, 16), Ui.dp(context, 16), Ui.dp(context, 32));
        lp.gravity = android.view.Gravity.BOTTOM;
        addView(btnCancel, lp);
    }

    public PreviewView getPreviewView() {
        return previewView;
    }

    @Override
    public View view() {
        return this;
    }

    @Override
    public View focusTarget() {
        return btnCancel;
    }
}
