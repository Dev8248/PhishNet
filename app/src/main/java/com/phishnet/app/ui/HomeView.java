package com.phishnet.app.ui;

import android.content.Context;
import android.graphics.Color;
import android.graphics.drawable.GradientDrawable;
import android.os.Build;
import android.text.Editable;
import android.text.InputFilter;
import android.text.InputType;
import android.text.TextWatcher;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.inputmethod.EditorInfo;
import android.view.inputmethod.InputMethodManager;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import com.phishnet.app.analysis.Limits;

/** Home screen: Dashboard with cards for actions and recent history. */
public final class HomeView implements ScreenView {
    public interface Listener {
        void onScan(String text);
        void onPaste();
        void onPickQr();
        void onScanCameraQr();
        void onMenu(View anchor);
        void onOpenBrowser();
    }

    private final ScrollView root;
    private final TextView title;
    private final EditText input;
    private final TextView note;
    private boolean limitNoteShown;

    public HomeView(final Context c, final Listener l) {
        LinearLayout col = Ui.column(c);

        // Header
        LinearLayout header = new LinearLayout(c);
        header.setOrientation(LinearLayout.HORIZONTAL);
        header.setGravity(Gravity.CENTER_VERTICAL);
        
        TextView appName = Ui.heading(Ui.text(c, "PhishNet", 22, true, Ui.PRIMARY_BLUE));
        header.addView(appName, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        
        TextView menu = Ui.text(c, "\u22EE", 28, true, Ui.INK);
        menu.setGravity(Gravity.CENTER);
        menu.setContentDescription("More options: About, Privacy, Donate to developers");
        menu.setClickable(true);
        menu.setFocusable(true);
        menu.setOnClickListener(v -> l.onMenu(v));
        header.addView(menu, new LinearLayout.LayoutParams(Ui.dp(c, 48), Ui.dp(c, 48)));
        Ui.add(col, header, 0);

        // Heading & Subtitle
        TextView heading = Ui.heading(Ui.text(c, "Your Digital Security", 32, true, Ui.INK));
        Ui.add(col, heading, 16);
        
        TextView subtitle = Ui.text(c, "Protect yourself from malicious websites and phishing attacks. All checks run locally.", 16, false, Ui.MUTED);
        Ui.add(col, subtitle, 8);

        // Overall protection info
        LinearLayout protectionInfo = new LinearLayout(c);
        protectionInfo.setOrientation(LinearLayout.HORIZONTAL);
        protectionInfo.setGravity(Gravity.CENTER_VERTICAL);
        protectionInfo.setPadding(Ui.dp(c, 16), Ui.dp(c, 16), Ui.dp(c, 16), Ui.dp(c, 16));
        GradientDrawable protBg = Ui.box(c, Ui.CARD_BG, false);
        protectionInfo.setBackground(protBg);
        
        TextView protText = Ui.text(c, "Real-time protection is active", 14, true, Ui.GREEN);
        protectionInfo.addView(protText);
        Ui.add(col, protectionInfo, 24);

        // Input field for Scan Website
        input = new EditText(c);
        input.setId(View.generateViewId());
        input.setHint("Paste or type a link to scan");
        input.setHintTextColor(Ui.MUTED);
        input.setTextColor(Ui.INK);
        input.setTextSize(TypedValue.COMPLEX_UNIT_SP, 16);
        input.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        input.setImeOptions(EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING);
        if (Build.VERSION.SDK_INT >= 26) input.setImportantForAutofill(View.IMPORTANT_FOR_AUTOFILL_NO);
        input.setGravity(Gravity.CENTER_VERTICAL | Gravity.START);
        int pad = Ui.dp(c, 16);
        input.setPadding(pad, pad, pad, pad);
        GradientDrawable inputBg = Ui.box(c, Ui.SECONDARY_BG, true);
        input.setBackground(inputBg);
        input.setFilters(new InputFilter[]{new InputFilter.LengthFilter(Limits.MAX_INPUT_CHARS)});
        Ui.add(col, input, 24);

        note = Ui.text(c, "", 12, false, Ui.YELLOW);
        note.setAccessibilityLiveRegion(View.ACCESSIBILITY_LIVE_REGION_POLITE);
        note.setVisibility(View.GONE);
        Ui.add(col, note, 4);

        input.addTextChangedListener(new TextWatcher() {
            @Override public void beforeTextChanged(CharSequence s, int a, int b, int d) { }
            @Override public void onTextChanged(CharSequence s, int a, int b, int d) { }
            @Override public void afterTextChanged(Editable e) {
                if (e.length() >= Limits.MAX_INPUT_CHARS) {
                    limitNoteShown = true;
                    showNote("Limit reached: only the first " + Limits.MAX_INPUT_CHARS + " characters are analysed.");
                } else if (limitNoteShown) {
                    limitNoteShown = false;
                    hideNote();
                }
            }
        });

        // Scan Website Button
        Button btnScan = Ui.button(c, "Scan Website", true, v -> {
            InputMethodManager imm = (InputMethodManager) c.getSystemService(Context.INPUT_METHOD_SERVICE);
            if (imm != null) imm.hideSoftInputFromWindow(input.getWindowToken(), 0);
            l.onScan(input.getText().toString());
        });
        btnScan.setCompoundDrawablesWithIntrinsicBounds(android.R.drawable.ic_menu_search, 0, 0, 0);
        btnScan.setCompoundDrawablePadding(Ui.dp(c, 8));
        Ui.add(col, btnScan, 12);

        // QR Code Buttons
        LinearLayout qrRow = new LinearLayout(c);
        qrRow.setOrientation(LinearLayout.HORIZONTAL);
        
        Button scanCamBtn = Ui.button(c, "Camera QR", false, v -> l.onScanCameraQr());
        scanCamBtn.setCompoundDrawablesWithIntrinsicBounds(android.R.drawable.ic_menu_camera, 0, 0, 0);
        scanCamBtn.setCompoundDrawablePadding(Ui.dp(c, 8));
        LinearLayout.LayoutParams camLp = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        camLp.rightMargin = Ui.dp(c, 8);
        qrRow.addView(scanCamBtn, camLp);
        
        Button pickImgBtn = Ui.button(c, "Image QR", false, v -> l.onPickQr());
        pickImgBtn.setCompoundDrawablesWithIntrinsicBounds(android.R.drawable.ic_menu_gallery, 0, 0, 0);
        pickImgBtn.setCompoundDrawablePadding(Ui.dp(c, 8));
        LinearLayout.LayoutParams imgLp = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        imgLp.leftMargin = Ui.dp(c, 8);
        qrRow.addView(pickImgBtn, imgLp);
        
        Ui.add(col, qrRow, 16);

        // Secure Browser Card
        Button browserBtn = Ui.button(c, "Open Secure Browser", false, v -> l.onOpenBrowser());
        browserBtn.setCompoundDrawablesWithIntrinsicBounds(android.R.drawable.ic_menu_view, 0, 0, 0);
        browserBtn.setCompoundDrawablePadding(Ui.dp(c, 8));
        Ui.add(col, browserBtn, 16);

        // Recent Scan History Placeholder
        TextView historyHeading = Ui.heading(Ui.text(c, "Recent Scans", 20, true, Ui.INK));
        Ui.add(col, historyHeading, 32);
        
        TextView historyEmpty = Ui.text(c, "Your recent scan results will appear here.", 14, false, Ui.MUTED);
        Ui.add(col, historyEmpty, 8);

        root = Ui.scroll(c, col);
        title = heading;
    }

    @Override public View view() { return root; }
    @Override public View focusTarget() { return title; }

    public String text() { return input.getText().toString(); }

    public void setText(CharSequence s) {
        input.setText(s);
        input.setSelection(input.getText().length());
    }

    public void clear() {
        input.setText("");
        hideNote();
    }

    public void showNote(String s) {
        note.setText(s);
        note.setVisibility(View.VISIBLE);
    }

    public void hideNote() {
        note.setVisibility(View.GONE);
    }

    public void focusInput() {
        input.requestFocus();
    }
}
