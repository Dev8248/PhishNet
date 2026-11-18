package com.phishnet.app.ui;

import android.app.AlertDialog;
import android.content.Context;
import android.content.DialogInterface;

/** Plain system dialogs: About, Privacy, Donate, and the explicit confirmations. */
public final class Dialogs {

    public static void about(Context c, String version) {
        show(c, "About PhishNet",
                "PhishNet helps you judge a suspicious link, message or QR code before you open it.\n\n"
                        + "How it works\n"
                        + "\u2022 Everything is analysed on this device by documented rules that look for warning signs: "
                        + "odd or disguised web addresses, look-alike names, link shorteners, hidden characters, "
                        + "pressuring wording and similar.\n"
                        + "\u2022 Each rule adds points. The total (0\u2013100) gives the level: 0\u201319 Safe, "
                        + "20\u201349 Moderate, 50 or more Risky. The score is not a probability of being attacked.\n"
                        + "\u2022 Safe means only that no obvious warning signs were found by the checks available. "
                        + "It is never a guarantee.\n\n"
                        + "What PhishNet cannot do\n"
                        + "\u2022 It has no threat-intelligence feed, so it can't know a site is new, hacked or reported.\n"
                        + "\u2022 It can't tell whether your device is infected, whether a link relates to your bank "
                        + "account, or who really sent a message.\n"
                        + "\u2022 It never opens, downloads or runs the link you give it, so it can't see redirects or page content.\n\n"
                        + "Version " + version + ". QR decoding uses the open-source ZXing library (Apache License 2.0).",
                null, null);
    }

    public static void privacy(Context c) {
        show(c, "Privacy",
                "Processed on this device\n"
                        + "\u2022 Links, message text and QR images you give PhishNet are analysed locally.\n"
                        + "\u2022 Nothing is uploaded. This build does not even have the internet permission.\n"
                        + "\u2022 The clipboard is read only when you tap Paste.\n"
                        + "\u2022 QR images are chosen with Android's photo picker. PhishNet can only see the one image "
                        + "you pick, and does not keep it.\n"
                        + "\u2022 Text shared to PhishNet from another app is only placed in the input box. It is not stored.\n\n"
                        + "Optional online check\n"
                        + "\u2022 Not available in this build. If a developer configures a service, PhishNet will name it, "
                        + "say exactly what is sent, and ask first. Only the link is ever sent, never message text. "
                        + "The service would also see your device's internet address, as with any online request.\n\n"
                        + "History and tracking\n"
                        + "\u2022 No accounts, analytics, advertising or tracking.\n"
                        + "\u2022 No scan history is saved. Results exist only in memory while the app is open.",
                null, null);
    }

    public static void donate(Context c, String donationUrl, final Runnable open) {
        if (donationUrl == null || donationUrl.isEmpty()) {
            show(c, "Donate to developers",
                    "Donations are not configured yet. This build has no donation page or payment account, "
                            + "and PhishNet does not collect payments.", null, null);
        } else {
            show(c, "Donate to developers",
                    "This will hand the following address to your browser:\n\n" + donationUrl
                            + "\n\nPhishNet does not handle any payment itself.", "Open", open);
        }
    }

    public static void onlineUnavailable(Context c) {
        show(c, "Online check not available",
                "No reputation service is configured in this build, so online checking is unavailable. "
                        + "Nothing was sent anywhere. The result shown comes from local checks only.", null, null);
    }

    public static void onlineConsent(Context c, String service, String dataSent, String visibleUrl,
                                     Runnable send) {
        show(c, "Check online?",
                "This will send the link below to " + service + ":\n\n" + visibleUrl + "\n\n" + dataSent
                        + "\n\nMessage text is never sent. The service will also see your device's internet address, "
                        + "as with any online request. The link itself is not opened.",
                "Send link", send);
    }

    public static void confirmOpen(Context c, String visibleUrl, Runnable open) {
        show(c, "Open this link?",
                "PhishNet will hand this link to your browser:\n\n" + visibleUrl
                        + "\n\nPhishNet can't guarantee that it is safe. Nothing has been loaded so far.",
                "Open link", open);
    }

    private static void show(Context c, String title, String message, String positive, final Runnable onPositive) {
        AlertDialog.Builder b = new AlertDialog.Builder(c)
                .setTitle(title)
                .setMessage(message);
        if (positive != null) {
            b.setNegativeButton("Cancel", null);
            b.setPositiveButton(positive, new DialogInterface.OnClickListener() {
                @Override public void onClick(DialogInterface d, int which) { onPositive.run(); }
            });
        } else {
            b.setPositiveButton("OK", null);
        }
        b.show();
    }

    public static void showScanReportDialog(Context c, com.phishnet.app.analysis.AnalysisResult result) {
        android.app.Dialog dialog = new android.app.Dialog(c, android.R.style.Theme_DeviceDefault_Light_NoActionBar);
        dialog.setContentView(new ResultView(c, result, "Scan report", false, "", new ResultView.Listener() {
            @Override public void onScanAnother() { dialog.dismiss(); }
            @Override public void onCheckOnline() { }
            @Override public void onCopy() { }
            @Override public void onOpen() { dialog.dismiss(); }
        }).view());
        dialog.show();
    }

    private Dialogs() {}
}
