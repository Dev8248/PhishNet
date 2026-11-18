package com.phishnet.app;

import android.content.Context;
import android.content.Intent;
import android.graphics.Bitmap;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.Gravity;
import android.view.KeyEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.inputmethod.EditorInfo;
import android.view.inputmethod.InputMethodManager;
import android.webkit.SafeBrowsingResponse;
import android.webkit.WebChromeClient;
import android.webkit.WebResourceError;
import android.webkit.WebResourceRequest;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.ComponentActivity;
import androidx.activity.OnBackPressedCallback;

import com.phishnet.app.analysis.AnalysisResult;
import com.phishnet.app.analysis.RiskAnalyzer;
import com.phishnet.app.analysis.RiskLevel;
import com.phishnet.app.online.OnlineCheck;
import com.phishnet.app.online.ReputationService;
import com.phishnet.app.ui.Dialogs;
import com.phishnet.app.ui.RiskBadgeView;
import com.phishnet.app.ui.Ui;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

public class InAppBrowserActivity extends ComponentActivity {

    public static final String EXTRA_URL = "extra_url";

    private final Handler mainHandler = new Handler(Looper.getMainLooper());
    private final ReputationService reputation = AppConfig.reputationService();
    private ExecutorService executor;
    private Future<?> task;

    private LinearLayout root;
    private EditText urlInput;
    private ProgressBar progressBar;
    private WebView webView;
    private FrameLayout warningOverlay;
    private RiskBadgeView securityBadge;

    private AnalysisResult currentAnalysisResult;
    private String pendingUrlToLoad;
    private boolean isUserOverridingWarning = false;
    
    // Simple cache for recently scanned URLs
    private final java.util.Map<String, AnalysisResult> scanCache = new java.util.HashMap<>();
    private final java.util.Map<String, Long> scanCacheTime = new java.util.HashMap<>();
    private static final long CACHE_EXPIRATION_MS = 5 * 60 * 1000; // 5 minutes

    public static void start(Context context, String url) {
        Intent intent = new Intent(context, InAppBrowserActivity.class);
        intent.putExtra(EXTRA_URL, url);
        context.startActivity(intent);
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        executor = Executors.newSingleThreadExecutor();

        buildUi();

        getOnBackPressedDispatcher().addCallback(this, new OnBackPressedCallback(true) {
            @Override
            public void handleOnBackPressed() {
                if (warningOverlay.getVisibility() == View.VISIBLE) {
                    finish();
                } else if (webView.canGoBack()) {
                    webView.goBack();
                } else {
                    finish();
                }
            }
        });

        String url = getIntent().getStringExtra(EXTRA_URL);
        if (url != null && !url.isEmpty()) {
            urlInput.setText(url);
            performSecurityScan(url);
        }
    }

    @Override
    protected void onDestroy() {
        if (task != null) {
            task.cancel(true);
        }
        executor.shutdownNow();
        webView.destroy();
        super.onDestroy();
    }

    private void buildUi() {
        root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(Ui.BG);
        root.setFitsSystemWindows(true);

        // Top bar
        LinearLayout topBar = new LinearLayout(this);
        topBar.setOrientation(LinearLayout.HORIZONTAL);
        topBar.setGravity(Gravity.CENTER_VERTICAL);
        int pad = Ui.dp(this, 8);
        topBar.setPadding(pad, pad, pad, pad);
        topBar.setBackgroundColor(Ui.SOFT);

        // Security badge indicator (tiny)
        securityBadge = new RiskBadgeView(this, RiskLevel.APPEARS_SAFE); // default
        topBar.addView(securityBadge, new LinearLayout.LayoutParams(Ui.dp(this, 32), Ui.dp(this, 32)));

        // URL input
        urlInput = new EditText(this);
        urlInput.setSingleLine();
        urlInput.setImeOptions(EditorInfo.IME_ACTION_GO);
        urlInput.setInputType(android.text.InputType.TYPE_TEXT_VARIATION_URI);
        urlInput.setSelectAllOnFocus(true);
        urlInput.setBackground(Ui.box(this, Ui.BG, true));
        urlInput.setPadding(Ui.dp(this, 8), Ui.dp(this, 8), Ui.dp(this, 8), Ui.dp(this, 8));
        urlInput.setTextSize(14);
        LinearLayout.LayoutParams urlLp = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        urlLp.setMargins(Ui.dp(this, 8), 0, Ui.dp(this, 8), 0);
        topBar.addView(urlInput, urlLp);

        urlInput.setOnEditorActionListener((v, actionId, event) -> {
            if (actionId == EditorInfo.IME_ACTION_GO || (event != null && event.getKeyCode() == KeyEvent.KEYCODE_ENTER)) {
                String inputUrl = urlInput.getText().toString().trim();
                if (!inputUrl.isEmpty()) {
                    hideKeyboard();
                    performSecurityScan(inputUrl);
                }
                return true;
            }
            return false;
        });

        // Scan details button
        TextView detailsBtn = Ui.linkButton(this, "Details", v -> showScanDetails());
        topBar.addView(detailsBtn);

        root.addView(topBar, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        // Loading bar
        progressBar = new ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal);
        progressBar.setMax(100);
        progressBar.setVisibility(View.GONE);
        root.addView(progressBar, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, Ui.dp(this, 4)));

        // Frame for WebView and Overlays
        FrameLayout contentFrame = new FrameLayout(this);

        // WebView
        webView = new WebView(this);
        configureWebView();
        contentFrame.addView(webView, new FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));

        // Warning Overlay
        warningOverlay = new FrameLayout(this);
        warningOverlay.setBackgroundColor(Ui.RED);
        warningOverlay.setVisibility(View.GONE);

        LinearLayout warningContent = Ui.column(this);
        warningContent.setGravity(Gravity.CENTER);

        TextView warningTitle = Ui.heading(Ui.text(this, "DANGEROUS WEBSITE DETECTED", 24, true, 0xFFFFFFFF));
        warningTitle.setGravity(Gravity.CENTER);
        Ui.add(warningContent, warningTitle, 0);

        TextView warningText = Ui.text(this, "PhishNet and/or Google Safe Browsing identified this website as a confirmed threat.", 16, false, 0xFFFFFFFF);
        warningText.setGravity(Gravity.CENTER);
        Ui.add(warningContent, warningText, 16);

        View backToSafety = Ui.button(this, "Back to safety", true, v -> {
            warningOverlay.setVisibility(View.GONE);
            if (webView.canGoBack()) {
                webView.goBack();
            } else {
                finish();
            }
        });
        Ui.add(warningContent, backToSafety, 32);

        TextView proceedUnsafe = Ui.linkButton(this, "Proceed (Unsafe)", v -> {
            isUserOverridingWarning = true;
            warningOverlay.setVisibility(View.GONE);
            if (pendingUrlToLoad != null) {
                if (pendingUrlToLoad.startsWith("http://") || pendingUrlToLoad.startsWith("https://")) {
                    webView.loadUrl(pendingUrlToLoad);
                } else {
                    Toast.makeText(this, "Unsafe protocol blocked.", Toast.LENGTH_SHORT).show();
                }
                pendingUrlToLoad = null;
            }
        });
        proceedUnsafe.setTextColor(0xAAFFFFFF);
        Ui.add(warningContent, proceedUnsafe, 24);

        warningOverlay.addView(warningContent, new FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, Gravity.CENTER));
        contentFrame.addView(warningOverlay, new FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));

        root.addView(contentFrame, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));

        // Navigation bottom bar
        LinearLayout navBar = new LinearLayout(this);
        navBar.setOrientation(LinearLayout.HORIZONTAL);
        navBar.setBackgroundColor(Ui.SOFT);

        TextView backBtn = Ui.linkButton(this, "\u25C0 Back", v -> { if (webView.canGoBack()) webView.goBack(); });
        TextView fwdBtn = Ui.linkButton(this, "Fwd \u25B6", v -> { if (webView.canGoForward()) webView.goForward(); });
        TextView reloadBtn = Ui.linkButton(this, "\u21BB Reload", v -> webView.reload());
        TextView homeBtn = Ui.linkButton(this, "\u2302 Home", v -> finish());

        LinearLayout.LayoutParams btnLp = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        navBar.addView(backBtn, btnLp);
        navBar.addView(fwdBtn, btnLp);
        navBar.addView(reloadBtn, btnLp);
        navBar.addView(homeBtn, btnLp);

        root.addView(navBar, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        setContentView(root);
    }

    private void configureWebView() {
        WebSettings settings = webView.getSettings();
        settings.setJavaScriptEnabled(false); // DO NOT ENABLE JS FOR UNTRUSTED PAGES by default
        settings.setAllowFileAccess(false);
        settings.setAllowContentAccess(false);

        webView.setWebChromeClient(new WebChromeClient() {
            @Override
            public void onProgressChanged(WebView view, int newProgress) {
                if (newProgress == 100) {
                    progressBar.setVisibility(View.GONE);
                } else {
                    progressBar.setVisibility(View.VISIBLE);
                    progressBar.setProgress(newProgress);
                }
            }
        });

        webView.setWebViewClient(new WebViewClient() {
            @Override
            public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
                String url = request.getUrl().toString();
                
                // Anti-intent scheme execution protection
                if (!url.startsWith("http://") && !url.startsWith("https://")) {
                    Toast.makeText(InAppBrowserActivity.this, "Blocked unsafe protocol execution", Toast.LENGTH_SHORT).show();
                    return true;
                }

                // Verify domain is public to prevent SSRF against localhost/private networks inside WebView context
                if (isLocalOrPrivateIp(request.getUrl().getHost())) {
                    Toast.makeText(InAppBrowserActivity.this, "Blocked access to internal network", Toast.LENGTH_SHORT).show();
                    return true;
                }

                urlInput.setText(url);
                performSecurityScan(url);
                return true; // We handle the loading after scan
            }

            @Override
            public void onPageStarted(WebView view, String url, Bitmap favicon) {
                urlInput.setText(url);
            }

            @Override
            public void onSafeBrowsingHit(WebView view, WebResourceRequest request, int threatType, SafeBrowsingResponse callback) {
                // Built-in WebView Safe Browsing integration
                if (Build.VERSION.SDK_INT >= 27) {
                    callback.backToSafety(true);
                }
                
                String threatUrl = request.getUrl().toString();
                
                // Update the analysis result dynamically to reflect the native detection
                if (currentAnalysisResult != null) {
                    java.util.List<com.phishnet.app.analysis.Finding> extra = new java.util.ArrayList<>();
                    extra.add(new com.phishnet.app.analysis.Finding("WEBVIEW-SAFE-BROWSING", "Dangerous site blocked", 
                            "Android WebView's built-in Safe Browsing flagged this site as a threat.", 100, com.phishnet.app.analysis.Finding.Source.ONLINE));
                    
                    currentAnalysisResult = currentAnalysisResult.withOnline(com.phishnet.app.analysis.OnlineStatus.COMPLETED, 
                            "Google Safe Browsing (Native)", extra, null);
                    updateSecurityBadge(currentAnalysisResult.level());
                }
                
                showWarningOverlay(threatUrl);
            }
        });
    }

    private void performSecurityScan(String url) {
        if (task != null) task.cancel(true);
        isUserOverridingWarning = false;

        // Ensure scheme exists for RiskAnalyzer
        final String scanUrl;
        if (url.matches("^[a-zA-Z][a-zA-Z0-9+.-]*:.*")) {
            scanUrl = url;
        } else {
            scanUrl = "https://" + url;
        }

        // Check cache
        if (scanCache.containsKey(scanUrl) && scanCacheTime.containsKey(scanUrl)) {
            long time = scanCacheTime.get(scanUrl);
            if (System.currentTimeMillis() - time < CACHE_EXPIRATION_MS) {
                AnalysisResult cached = scanCache.get(scanUrl);
                handleScanResult(cached, scanUrl);
                return;
            }
        }

        progressBar.setVisibility(View.VISIBLE);
        progressBar.setProgress(10);

        task = executor.submit(() -> {
            AnalysisResult localResult = null;
            try {
                localResult = RiskAnalyzer.analyze(scanUrl, null, false);
            } catch (Exception e) {
                // Invalid URL
            }

            final AnalysisResult finalLocal = localResult;
            AnalysisResult combinedResult = null;

            if (finalLocal != null) {
                // Run online checks (Safe Browsing & DNS/Redirect)
                combinedResult = OnlineCheck.run(finalLocal, reputation, null);
            }

            final AnalysisResult finalCombined = combinedResult;

            mainHandler.post(() -> {
                progressBar.setVisibility(View.GONE);
                if (finalCombined != null) {
                    scanCache.put(scanUrl, finalCombined);
                    scanCacheTime.put(scanUrl, System.currentTimeMillis());
                }
                handleScanResult(finalCombined, scanUrl);
            });
        });
    }

    private void handleScanResult(AnalysisResult finalCombined, String scanUrl) {
        if (finalCombined == null) {
            Toast.makeText(this, "Invalid URL format.", Toast.LENGTH_SHORT).show();
            return;
        }
        
        currentAnalysisResult = finalCombined;
        updateSecurityBadge(finalCombined.level());
        
        if (finalCombined.level() == RiskLevel.NOT_SAFE || finalCombined.level() == RiskLevel.HIGH_RISK) {
            showWarningOverlay(scanUrl);
        } else {
            warningOverlay.setVisibility(View.GONE);
            if (scanUrl.startsWith("http://") || scanUrl.startsWith("https://")) {
                webView.loadUrl(scanUrl);
            } else {
                Toast.makeText(this, "Unsafe protocol blocked.", Toast.LENGTH_SHORT).show();
            }
        }
    }

    private void updateSecurityBadge(RiskLevel level) {
        ViewGroup parent = (ViewGroup) securityBadge.getParent();
        if (parent != null) {
            int index = parent.indexOfChild(securityBadge);
            parent.removeView(securityBadge);
            securityBadge = new RiskBadgeView(this, level);
            parent.addView(securityBadge, index, new LinearLayout.LayoutParams(Ui.dp(this, 32), Ui.dp(this, 32)));
        }
    }

    private void showWarningOverlay(String url) {
        pendingUrlToLoad = url;
        warningOverlay.setVisibility(View.VISIBLE);
        hideKeyboard();
    }

    private void showScanDetails() {
        if (currentAnalysisResult == null) return;
        // Launch a dialog showing the ResultView
        android.app.Dialog dialog = new android.app.Dialog(this, android.R.style.Theme_DeviceDefault_Light_NoActionBar);
        dialog.setContentView(new com.phishnet.app.ui.ResultView(this, currentAnalysisResult, "Scan report", false, "", new com.phishnet.app.ui.ResultView.Listener() {
            @Override public void onScanAnother() { dialog.dismiss(); }
            @Override public void onCheckOnline() { }
            @Override public void onCopy() { }
            @Override public void onOpen() { dialog.dismiss(); }
        }).view());
        dialog.show();
    }

    private void hideKeyboard() {
        InputMethodManager imm = (InputMethodManager) getSystemService(Context.INPUT_METHOD_SERVICE);
        if (imm != null) {
            imm.hideSoftInputFromWindow(urlInput.getWindowToken(), 0);
        }
    }

    private boolean isLocalOrPrivateIp(String host) {
        if (host == null) return false;
        return host.startsWith("10.") || host.startsWith("192.168.") 
               || host.matches("172\\.(1[6-9]|2[0-9]|3[0-1])\\..*") 
               || host.startsWith("127.") || host.equals("localhost");
    }
}