package com.phishnet.app;

import android.Manifest;
import android.content.ActivityNotFoundException;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.ContentResolver;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.transition.AutoTransition;
import android.transition.TransitionManager;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.view.accessibility.AccessibilityNodeInfo;
import android.widget.FrameLayout;
import android.widget.PopupMenu;
import android.widget.Toast;

import androidx.activity.ComponentActivity;
import androidx.activity.OnBackPressedCallback;
import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.PickVisualMediaRequest;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.camera.core.CameraSelector;
import androidx.camera.core.ImageAnalysis;
import androidx.camera.core.ImageProxy;
import androidx.camera.core.Preview;
import androidx.camera.lifecycle.ProcessCameraProvider;
import androidx.core.content.ContextCompat;

import com.google.common.util.concurrent.ListenableFuture;

import com.phishnet.app.analysis.AnalysisResult;
import com.phishnet.app.analysis.Limits;
import com.phishnet.app.analysis.RiskAnalyzer;
import com.phishnet.app.analysis.RiskLevel;
import com.phishnet.app.analysis.Subtitles;
import com.phishnet.app.analysis.UrlExtractor;
import com.phishnet.app.analysis.UrlParser;
import com.phishnet.app.online.OnlineCheck;
import com.phishnet.app.online.ReputationService;
import com.phishnet.app.models.QRResult;
import com.phishnet.app.scanner.QRDispatcher;
import com.phishnet.app.ui.CameraScannerView;
import com.phishnet.app.ui.QRResultView;
import com.phishnet.app.ui.Dialogs;
import com.phishnet.app.ui.HomeView;
import com.phishnet.app.ui.PickView;
import com.phishnet.app.ui.ResultView;
import com.phishnet.app.ui.ScanProgressView;
import com.phishnet.app.ui.ScreenView;
import com.phishnet.app.ui.StatusView;
import com.phishnet.app.ui.Ui;
import com.phishnet.app.db.ScanHistoryDbHelper;
import com.phishnet.app.qr.QrImageReader;
import com.phishnet.app.qr.QrDecoder;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Single-activity host. It owns screen switching, Back navigation, and background work.
 *
 * Safety properties kept here: scanning never starts an Intent or loads a WebView; the only places a
 * link can leave the app are the two explicit, confirmed "Open" actions; nothing is logged or stored.
 */
public class MainActivity extends ComponentActivity {

    private enum Screen { HOME, LOADING, PICK, RESULT, ERROR, CAMERA_SCAN }

    /** Background step. Returns the UI continuation to run on the main thread. */
    private interface Work {
        Runnable run() throws Exception;
    }

    private final Handler mainHandler = new Handler(Looper.getMainLooper());
    private final AtomicInteger generation = new AtomicInteger();
    private final Subtitles subtitles = new Subtitles();
    private final ReputationService reputation = AppConfig.reputationService();

    private ExecutorService executor;
    private Future<?> task;
    private FrameLayout root;
    private HomeView home;
    private PickView lastPick;
    private ActivityResultLauncher<PickVisualMediaRequest> imagePicker;
    private ActivityResultLauncher<String> requestCameraPermissionLauncher;
    private CameraScannerView cameraScannerView;

    private Screen screen = Screen.HOME;
    private Runnable loadingBack;
    private AnalysisResult result;
    private String subtitle = "";
    private boolean resultFromPick;

    // ------------------------------------------------------------------ lifecycle

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        if (Build.VERSION.SDK_INT >= 33) {
            setRecentsScreenshotEnabled(false); // don't leave pasted messages in the recents thumbnail
        }
        executor = Executors.newSingleThreadExecutor();
        root = new FrameLayout(this);
        root.setBackgroundColor(Ui.BG);
        root.setFitsSystemWindows(true);
        setContentView(root);

        imagePicker = registerForActivityResult(new ActivityResultContracts.PickVisualMedia(),
                uri -> onImagePicked(uri));
        requestCameraPermissionLauncher = registerForActivityResult(new ActivityResultContracts.RequestPermission(),
                isGranted -> {
                    if (isGranted) {
                        startCameraScan();
                    } else {
                        Toast.makeText(this, "Camera permission is required to scan QR codes.", Toast.LENGTH_LONG).show();
                    }
                });
        getOnBackPressedDispatcher().addCallback(this, new OnBackPressedCallback(true) {
            @Override public void handleOnBackPressed() { onBack(); }
        });

        home = newHome();
        showHome();
        if (state == null) {
            handleShare(getIntent());
        }
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        if (intent != null && Intent.ACTION_SEND.equals(intent.getAction())) {
            showHome();
            handleShare(intent);
        }
    }

    @Override
    protected void onDestroy() {
        cancelWork();
        executor.shutdownNow();
        super.onDestroy();
    }

    // ------------------------------------------------------------------ screens

    private HomeView newHome() {
        return new HomeView(this, new HomeView.Listener() {
            @Override public void onScan(String text) { startScan(text); }
            @Override public void onPaste() { paste(); }
            @Override public void onPickQr() { launchImagePicker(); }
            @Override public void onScanCameraQr() { requestCameraScan(); }
            @Override public void onMenu(View anchor) { showMenu(anchor); }
            @Override public void onOpenBrowser() {
                openInBrowser("");
            }
        });
    }

    private void setContent(ScreenView s) {
        AutoTransition transition = new AutoTransition();
        transition.setDuration(250);
        TransitionManager.beginDelayedTransition(root, transition);
        root.removeAllViews();
        root.addView(s.view(), new FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT));
        final View focus = s.focusTarget();
        if (focus != null) {
            focus.post(new Runnable() {
                @Override public void run() {
                    // Moves TalkBack to the new screen's headline; does nothing when no screen reader is on.
                    focus.performAccessibilityAction(AccessibilityNodeInfo.ACTION_ACCESSIBILITY_FOCUS, null);
                }
            });
        }
    }

    private void showHome() {
        cancelWork();
        screen = Screen.HOME;
        setContent(home);
    }



    private void showError(String title, String message, String actionLabel, final Runnable action) {
        screen = Screen.ERROR;
        setContent(StatusView.error(this, title, message, actionLabel, new View.OnClickListener() {
            @Override public void onClick(View v) { action.run(); }
        }));
    }

    private void showPick(String source, List<String> urls, final String messageContext, final boolean truncated) {
        screen = Screen.PICK;
        lastPick = new PickView(this, source, urls, messageContext != null, new PickView.Listener() {
            @Override public void onChoose(final String url) {
                background(new Runnable() {
                    @Override public void run() { showLastPick(); }
                }, new Work() {
                    @Override public Runnable run() { return analyzeToUi(url, messageContext, truncated, true); }
                });
            }
            @Override public void onBack() { showHome(); }
        });
        setContent(lastPick);
    }

    private void showLastPick() {
        if (lastPick == null) {
            showHome();
            return;
        }
        screen = Screen.PICK;
        setContent(lastPick);
    }

    private void showResult(AnalysisResult r, boolean fromPick) {
        result = r;
        subtitle = subtitles.pick(r.level()); // fresh random draw for every completed scan
        resultFromPick = fromPick;
        renderResult();
    }

    private void renderResult() {
        screen = Screen.RESULT;
        setContent(new ResultView(this, result, subtitle, reputation.isConfigured(), reputation.name(),
                new ResultView.Listener() {
                    @Override public void onScanAnother() {
                        home.clear();
                        lastPick = null;
                        showHome();
                    }
                    @Override public void onCheckOnline() { checkOnline(); }
                    @Override public void onCopy() { copyToClipboard(result.url()); }
                    @Override public void onOpen() { confirmOpen(); }
                }));
    }

    private void onBack() {
        switch (screen) {
            case HOME:
                finish();
                break;
            case LOADING: {
                Runnable back = loadingBack;
                cancelWork();
                if (back != null) back.run(); else showHome();
                break;
            }
            case RESULT:
                if (resultFromPick && lastPick != null) showLastPick(); else showHome();
                break;
            default:
                showHome();
        }
    }

    // ------------------------------------------------------------------ background work

    private void cancelWork() {
        generation.incrementAndGet(); // any late result from cancelled work is ignored
        if (task != null) {
            task.cancel(true);
            task = null;
        }
    }

    private void background(Runnable backTarget, final Work work) {
        cancelWork();
        final int gen = generation.incrementAndGet();
        loadingBack = backTarget;
        screen = Screen.LOADING;
        
        final ScanProgressView progressView = new ScanProgressView(this);
        setContent(progressView);
        
        task = executor.submit(new Runnable() {
            @Override public void run() {
                Runnable ui;
                try {
                    ui = work.run();
                } catch (InterruptedException e) {
                    return;
                } catch (Throwable t) {
                    ui = new Runnable() {
                        @Override public void run() {
                            progressView.stopAnimation();
                            showError("Something went wrong",
                                    "PhishNet couldn't finish this check. Nothing was sent anywhere. Please try again.",
                                    "Back", new Runnable() {
                                        @Override public void run() { showHome(); }
                                    });
                        }
                    };
                }
                final Runnable finalUi = ui;
                mainHandler.post(new Runnable() {
                    @Override public void run() {
                        if (gen == generation.get()) {
                            progressView.stopAnimation();
                            finalUi.run();
                        }
                    }
                });
            }
        });
    }

    // ------------------------------------------------------------------ actions

    private void startScan(String raw) {
        final String text = raw == null ? "" : raw.trim();
        if (text.isEmpty()) {
            home.showNote("Enter or paste a link or message first.");
            home.focusInput();
            return;
        }
        final boolean truncated = text.length() >= Limits.MAX_INPUT_CHARS;
        background(new Runnable() {
            @Override public void run() { showHome(); }
        }, new Work() {
            @Override public Runnable run() {
                final UrlExtractor.Extraction ex = UrlExtractor.extract(text);
                final boolean trunc = truncated || ex.textTruncated;
                if (ex.urls.isEmpty()) {
                    return new Runnable() {
                        @Override public void run() {
                            showError("No link found",
                                    "PhishNet couldn't find a web link in that text. Paste the link itself, or a "
                                            + "message that contains one.", "Back", new Runnable() {
                                        @Override public void run() { showHome(); }
                                    });
                        }
                    };
                }
                if (ex.urls.size() == 1 && ex.urls.get(0).equals(text)) {
                    return analyzeToUi(text, null, trunc, false); // a bare link: nothing more to choose
                }
                return new Runnable() {
                    @Override public void run() {
                        showPick("your text" + (ex.tooManyUrls ? " (only the first " + Limits.MAX_URLS
                                + " links are listed)" : ""), ex.urls, text, trunc);
                    }
                };
            }
        });
    }

    /** Runs the analysis (on the worker thread) and returns the matching UI step. */
    private Runnable analyzeToUi(String url, String messageContext, boolean truncated, final boolean fromPick) {
        try {
            final AnalysisResult r = RiskAnalyzer.analyze(url, messageContext, truncated);
            return new Runnable() {
                @Override public void run() { showResult(r, fromPick); }
            };
        } catch (final IllegalArgumentException e) {
            return new Runnable() {
                @Override public void run() {
                    String msg = e.getMessage() == null ? "It doesn't look like a valid web link." : e.getMessage();
                    showError("Can't read this link", msg, "Back", new Runnable() {
                        @Override public void run() { if (fromPick) showLastPick(); else showHome(); }
                    });
                }
            };
        }
    }

    private void requestCameraScan() {
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED) {
            startCameraScan();
        } else {
            requestCameraPermissionLauncher.launch(Manifest.permission.CAMERA);
        }
    }

    private void startCameraScan() {
        screen = Screen.CAMERA_SCAN;
        cameraScannerView = new CameraScannerView(this, new CameraScannerView.Listener() {
            @Override
            public void onCancel() {
                showHome();
            }
        });
        setContent(cameraScannerView);
        
        ListenableFuture<ProcessCameraProvider> cameraProviderFuture = ProcessCameraProvider.getInstance(this);
        cameraProviderFuture.addListener(() -> {
            try {
                ProcessCameraProvider cameraProvider = cameraProviderFuture.get();
                bindCameraUseCases(cameraProvider);
            } catch (ExecutionException | InterruptedException e) {
                Toast.makeText(this, "Failed to start camera.", Toast.LENGTH_SHORT).show();
                showHome();
            }
        }, ContextCompat.getMainExecutor(this));
    }
    
    private byte[] cachedYuvBuffer = null;

    private void bindCameraUseCases(ProcessCameraProvider cameraProvider) {
        Preview preview = new Preview.Builder().build();
        preview.setSurfaceProvider(cameraScannerView.getPreviewView().getSurfaceProvider());

        ImageAnalysis imageAnalysis = new ImageAnalysis.Builder()
                .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                .build();
                
        imageAnalysis.setAnalyzer(executor, imageProxy -> {
            @androidx.camera.core.ExperimentalGetImage
            android.media.Image mediaImage = imageProxy.getImage();
            if (mediaImage != null && mediaImage.getFormat() == android.graphics.ImageFormat.YUV_420_888) {
                android.media.Image.Plane yPlane = mediaImage.getPlanes()[0];
                ByteBuffer yBuffer = yPlane.getBuffer();
                int size = yBuffer.remaining();
                if (cachedYuvBuffer == null || cachedYuvBuffer.length < size) {
                    cachedYuvBuffer = new byte[size];
                }
                yBuffer.get(cachedYuvBuffer, 0, size);
                
                int width = mediaImage.getWidth();
                int height = mediaImage.getHeight();
                int rowStride = yPlane.getRowStride();
                
                // Use rowStride as dataWidth for ZXing to handle alignment correctly
                String payload = QrDecoder.decodeYuv(cachedYuvBuffer, rowStride, height, width, height);
                if (payload != null && !payload.isEmpty()) {
                    imageProxy.close();
                    // Process result on main thread
                    mainHandler.post(() -> {
                        cameraProvider.unbindAll();
                        final QRResult qrResult = QRDispatcher.dispatch(payload);
                        showQRResult(qrResult);
                    });
                    return;
                }
            }
            imageProxy.close();
        });

        CameraSelector cameraSelector = CameraSelector.DEFAULT_BACK_CAMERA;
        cameraProvider.unbindAll();
        cameraProvider.bindToLifecycle(this, cameraSelector, preview, imageAnalysis);
    }

    private void launchImagePicker() {
        imagePicker.launch(new PickVisualMediaRequest.Builder()
                .setMediaType(ActivityResultContracts.PickVisualMedia.ImageOnly.INSTANCE)
                .build());
    }

    private void onImagePicked(final Uri uri) {
        if (uri == null) return; // the user closed the picker
        final ContentResolver resolver = getContentResolver();
        background(new Runnable() {
            @Override public void run() { showHome(); }
        }, new Work() {
            @Override public Runnable run() {
                final String payload = QrImageReader.read(resolver, uri);
                if (payload == null) {
                    return new Runnable() {
                        @Override public void run() {
                            showError("No QR code found",
                                    "PhishNet couldn't read a QR code in that image. Try a sharper image with the whole "
                                            + "code in view. The image was read on this device only and not uploaded.",
                                    "Choose another image", new Runnable() {
                                        @Override public void run() { launchImagePicker(); }
                                    });
                        }
                    };
                }
                
                final QRResult qrResult = QRDispatcher.dispatch(payload);
                return new Runnable() {
                    @Override public void run() { showQRResult(qrResult); }
                };
            }
        });
    }

    private void showQRResult(QRResult r) {
        screen = Screen.RESULT;
        
        // Save to scan history safely
        new ScanHistoryDbHelper(this).insertScan(r);
        
        setContent(new QRResultView(this, r, new QRResultView.Listener() {
            @Override public void onScanAnother() {
                home.clear();
                lastPick = null;
                showHome();
            }
            @Override public void onCopy() { copyToClipboard(r.payload.rawContent); }
            @Override public void onOpen() { 
                if (r.urlAnalysisResult != null) {
                    openInBrowser(r.urlAnalysisResult.url());
                } else {
                    openInBrowser(r.payload.rawContent);
                }
            }
        }));
    }

    private void paste() {
        ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        ClipData data = cm == null ? null : cm.getPrimaryClip(); // only ever read because the user tapped Paste
        CharSequence t = (data != null && data.getItemCount() > 0) ? data.getItemAt(0).coerceToText(this) : null;
        String s = t == null ? "" : t.toString();
        if (s.trim().isEmpty()) {
            home.showNote("The clipboard is empty or has no text.");
            return;
        }
        boolean cut = s.length() > Limits.MAX_INPUT_CHARS;
        if (cut) s = s.substring(0, Limits.MAX_INPUT_CHARS);
        home.setText(s);
        if (!cut) home.showNote("Pasted. Tap Scan when you're ready.");
    }

    /** Text shared from another app is only placed in the input box. It is not stored and not scanned yet. */
    private void handleShare(Intent intent) {
        if (intent == null || !Intent.ACTION_SEND.equals(intent.getAction())) return;
        String s = null;
        try {
            CharSequence t = intent.getCharSequenceExtra(Intent.EXTRA_TEXT);
            if (t != null) s = t.toString();
            intent.removeExtra(Intent.EXTRA_TEXT);
        } catch (RuntimeException e) {
            // malformed extras: treat as nothing shared
        }
        if (s == null || s.trim().isEmpty()) return;
        boolean cut = s.length() > Limits.MAX_INPUT_CHARS;
        if (cut) s = s.substring(0, Limits.MAX_INPUT_CHARS);
        home.setText(s);
        home.showNote("Shared text loaded. Review it, then tap Scan. Nothing has been opened or sent.");
    }

    private void showMenu(View anchor) {
        PopupMenu menu = new PopupMenu(this, anchor);
        menu.getMenu().add(0, 1, 0, "About");
        menu.getMenu().add(0, 2, 1, "Privacy");
        menu.getMenu().add(0, 3, 2, "Donate to developers");
        menu.setOnMenuItemClickListener(new PopupMenu.OnMenuItemClickListener() {
            @Override public boolean onMenuItemClick(MenuItem item) {
                switch (item.getItemId()) {
                    case 1:
                        Dialogs.about(MainActivity.this, versionName());
                        return true;
                    case 2:
                        Dialogs.privacy(MainActivity.this);
                        return true;
                    case 3:
                        Dialogs.donate(MainActivity.this, AppConfig.DONATION_URL, new Runnable() {
                            @Override public void run() { openInBrowser(AppConfig.DONATION_URL); }
                        });
                        return true;
                    default:
                        return false;
                }
            }
        });
        menu.show();
    }

    private void checkOnline() {
        final AnalysisResult base = result;
        final String name = reputation.isConfigured() ? reputation.name() : "DNS & Redirect Analysis";
        final String description = reputation.isConfigured() ? reputation.dataSentDescription() : "Performs live DNS, TLS, and website redirect/content checks. No backend threat service is configured.";
        
        Dialogs.onlineConsent(this, name, description,
                UrlParser.visible(base.url(), 300), new Runnable() {
                    @Override public void run() {
                        final ScanProgressView progressView = new ScanProgressView(MainActivity.this);
                        backgroundProgress(progressView, new Runnable() {
                            @Override public void run() { renderResult(); }
                        }, new Work() {
                            @Override public Runnable run() {
                                com.phishnet.app.analysis.ScanProgressListener listener = new com.phishnet.app.analysis.ScanProgressListener() {
                                    @Override
                                    public void onStageStatusChanged(final int stageId, final int status) {
                                        mainHandler.post(new Runnable() {
                                            @Override public void run() {
                                                progressView.updateStage(stageId, com.phishnet.app.ui.ScanProgressView.StageStatus.values()[status]);
                                            }
                                        });
                                    }
                                };
                                // Local stages finish instantly, just mark them success.
                                listener.onStageStatusChanged(1, 2);
                                listener.onStageStatusChanged(7, 2);
                                listener.onStageStatusChanged(8, 2);
                                
                                final AnalysisResult updated = OnlineCheck.run(base, reputation, listener);
                                return new Runnable() {
                                    @Override public void run() {
                                        progressView.stopAnimation();
                                        showResult(updated, resultFromPick);
                                    }
                                };
                            }
                        });
                    }
                });
    }

    private void backgroundProgress(final ScanProgressView progressView, Runnable backTarget, final Work work) {
        cancelWork();
        final int gen = generation.incrementAndGet();
        loadingBack = backTarget;
        screen = Screen.LOADING;
        setContent(progressView);
        task = executor.submit(new Runnable() {
            @Override public void run() {
                Runnable ui;
                try {
                    ui = work.run();
                } catch (InterruptedException e) {
                    return;
                } catch (Throwable t) {
                    ui = new Runnable() {
                        @Override public void run() {
                            progressView.stopAnimation();
                            showError("Something went wrong",
                                    "PhishNet couldn't finish this check. Nothing was sent anywhere. Please try again.",
                                    "Back", new Runnable() {
                                        @Override public void run() { showHome(); }
                                    });
                        }
                    };
                }
                final Runnable finalUi = ui;
                mainHandler.post(new Runnable() {
                    @Override public void run() {
                        if (gen == generation.get()) {
                            progressView.stopAnimation();
                            finalUi.run();
                        }
                    }
                });
            }
        });
    }

    private void confirmOpen() {
        if (result == null || !result.isWebLink() || result.level() == RiskLevel.NOT_SAFE || result.level() == RiskLevel.HIGH_RISK) return;
        final String url = result.url();
        Dialogs.confirmOpen(this, UrlParser.visible(url, 300), new Runnable() {
            @Override public void run() { openInBrowser(url); }
        });
    }

    private void openInBrowser(String url) {
        InAppBrowserActivity.start(this, url);
    }

    private void copyToClipboard(String text) {
        ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        if (cm == null) return;
        cm.setPrimaryClip(ClipData.newPlainText("Link", text));
        if (Build.VERSION.SDK_INT < 33) { // Android 13+ shows its own confirmation
            Toast.makeText(this, "Link copied", Toast.LENGTH_SHORT).show();
        }
    }

    private String versionName() {
        try {
            String v = getPackageManager().getPackageInfo(getPackageName(), 0).versionName;
            return v == null ? "1.0" : v;
        } catch (PackageManager.NameNotFoundException e) {
            return "1.0";
        }
    }
}
