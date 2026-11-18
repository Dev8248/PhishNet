package com.phishnet.app.ui;

import android.view.View;

/** A full-screen piece of UI that MainActivity can swap in. */
public interface ScreenView {
    View view();

    /** The element a screen reader should land on when this screen appears; may be null. */
    View focusTarget();
}
