package com.phishnet.app.online;

import com.phishnet.app.analysis.AnalysisResult;
import com.phishnet.app.analysis.Finding;
import com.phishnet.app.analysis.OnlineStatus;
import com.phishnet.app.analysis.ParsedUrl;
import com.phishnet.app.analysis.ScanProgressListener;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.cert.Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import javax.net.ssl.HttpsURLConnection;
import java.net.URL;

/**
 * Applies an explicit, user-requested online check to a local result. Local findings are always kept
 * and online findings are labelled separately. Call off the main thread, only after user consent.
 */
public final class OnlineCheck {

    public static AnalysisResult run(AnalysisResult local, ReputationService service, ScanProgressListener listener) {
        List<Finding> extra = new ArrayList<>();
        
        if (listener != null) listener.onStageStatusChanged(4, 1); // 4 = HTTPS/Cert
        // DNS verification (Check 10)
        ParsedUrl pUrl = com.phishnet.app.analysis.UrlParser.parse(local.url());
        if (pUrl != null && !pUrl.host.isEmpty() && pUrl.ipKind == ParsedUrl.IpKind.NONE) {
            try {
                InetAddress[] addresses = InetAddress.getAllByName(pUrl.host);
                boolean isPrivate = false;
                if (addresses.length > 0) {
                    for (InetAddress addr : addresses) {
                        if (addr.isLoopbackAddress() || addr.isSiteLocalAddress() || addr.isAnyLocalAddress() || addr.isLinkLocalAddress()) {
                            isPrivate = true;
                            break;
                        }
                    }
                    if (isPrivate) {
                        extra.add(new Finding("NET-PRIVATE-IP", "Internal network target",
                                "The link points to a private or local network address, which is unsafe to follow.", 80, Finding.Source.ONLINE));
                    } else {
                        extra.add(new Finding("DNS-RESOLVED", "Domain resolved successfully",
                                "The domain name was resolved to " + addresses[0].getHostAddress() + ".", 0, Finding.Source.ONLINE));
                    }
                }
                
                // HTTPS & Certificate checks (Checks 27-31)
                if (!isPrivate && "https".equals(pUrl.scheme)) {
                    try {
                        URL httpsUrl = new URL(local.url());
                        HttpsURLConnection connection = (HttpsURLConnection) httpsUrl.openConnection();
                        connection.setConnectTimeout(5000);
                        connection.setReadTimeout(5000);
                        connection.setRequestMethod("HEAD");
                        connection.connect();
                        
                        extra.add(new Finding("HTTPS-AVAILABLE", "HTTPS connection available",
                                "The server supports secure HTTPS connections.", 0, Finding.Source.ONLINE));
                                
                        Certificate[] certs = connection.getServerCertificates();
                        if (certs.length > 0 && certs[0] instanceof X509Certificate) {
                            X509Certificate x509 = (X509Certificate) certs[0];
                            try {
                                x509.checkValidity();
                                extra.add(new Finding("CERT-VALID", "Certificate is valid",
                                        "The SSL/TLS certificate is currently valid and not expired.", 0, Finding.Source.ONLINE));
                            } catch (CertificateExpiredException e) {
                                extra.add(new Finding("CERT-EXPIRED", "Certificate is expired",
                                        "The SSL/TLS certificate has expired, which is a major security risk.", 60, Finding.Source.ONLINE));
                            } catch (CertificateNotYetValidException e) {
                                extra.add(new Finding("CERT-NOT-YET-VALID", "Certificate not yet valid",
                                        "The SSL/TLS certificate is not yet valid.", 50, Finding.Source.ONLINE));
                            }
                        }
                        connection.disconnect();
                        if (listener != null) listener.onStageStatusChanged(4, 2);
                    } catch (IOException e) {
                        extra.add(new Finding("HTTPS-FAILED", "HTTPS connection failed",
                                "Could not establish a secure connection or verify the certificate. The site might be unsafe.", 30, Finding.Source.ONLINE));
                        if (listener != null) listener.onStageStatusChanged(4, 3);
                    }
                } else {
                    if (listener != null) listener.onStageStatusChanged(4, 2);
                }
            } catch (UnknownHostException e) {
                extra.add(new Finding("DNS-FAILED", "Domain does not exist",
                        "The domain name could not be resolved. It might be dead, fake, or local.", 40, Finding.Source.ONLINE));
                if (listener != null) listener.onStageStatusChanged(4, 4);
            }
        } else {
            if (listener != null) listener.onStageStatusChanged(4, 2);
        }
        
        // Redirect and Website Analysis (Checks 32-39)
        if (listener != null) listener.onStageStatusChanged(5, 1);
        if (listener != null) listener.onStageStatusChanged(6, 1);
        if (pUrl != null && !pUrl.host.isEmpty()) {
            extra.addAll(RedirectAnalyzer.analyze(local.url()));
        }
        if (listener != null) listener.onStageStatusChanged(5, 2);
        if (listener != null) listener.onStageStatusChanged(6, 2);

        if (listener != null) listener.onStageStatusChanged(2, 1);
        if (listener != null) listener.onStageStatusChanged(3, 1);
        if (service == null || !service.isConfigured()) {
            if (listener != null) {
                listener.onStageStatusChanged(2, 2);
                listener.onStageStatusChanged(3, 2);
            }
            return local.withOnline(OnlineStatus.UNAVAILABLE, null, extra, null);
        }
        String name = service.name();
        ReputationResult r;
        try {
            r = service.check(local.url());
        } catch (IOException | RuntimeException e) {
            if (listener != null) {
                listener.onStageStatusChanged(2, 4);
                listener.onStageStatusChanged(3, 4);
            }
            return local.withOnline(OnlineStatus.FAILED, name, extra,
                    "The online check with " + name + " could not be completed.");
        }
        if (r == null || r.verdict == ReputationResult.Verdict.UNKNOWN) {
            if (listener != null) {
                listener.onStageStatusChanged(2, 3);
                listener.onStageStatusChanged(3, 3);
            }
            return local.withOnline(OnlineStatus.INCONCLUSIVE, name, extra,
                    name + " did not give a usable answer, so the online check is incomplete.");
        }
        if (r.verdict == ReputationResult.Verdict.THREAT_MATCH) {
            String d = r.detail.isEmpty() ? "" : " (" + r.detail + ")";
            extra.add(new Finding("ONLINE-LISTED", "Listed as a threat by " + name,
                    name + " reports this link as a known threat" + d + ".", 70, Finding.Source.ONLINE));
            if (listener != null) {
                listener.onStageStatusChanged(2, 4);
                listener.onStageStatusChanged(3, 4);
            }
        } else {
            extra.add(new Finding("ONLINE-NO-MATCH", "Not found in " + name + "'s lists",
                    "No record was found. That is not a guarantee: new threats take time to be listed.", 0,
                    Finding.Source.ONLINE));
            if (listener != null) {
                listener.onStageStatusChanged(2, 2);
                listener.onStageStatusChanged(3, 2);
            }
        }
        return local.withOnline(OnlineStatus.COMPLETED, name, extra, null);
    }

    private OnlineCheck() {}
}
