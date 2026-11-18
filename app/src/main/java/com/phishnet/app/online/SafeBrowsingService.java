package com.phishnet.app.online;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;

/**
 * Implementation of Google Safe Browsing v4 threat intelligence (Check 40).
 * Configured securely via a backend proxy to protect API keys.
 */
public final class SafeBrowsingService implements ReputationService {
    private final String backendProxyUrl;

    public SafeBrowsingService(String backendProxyUrl) {
        this.backendProxyUrl = backendProxyUrl;
    }

    @Override
    public String name() {
        return "Safe Browsing Threat Intelligence";
    }

    @Override
    public String dataSentDescription() {
        return "Checks the URL against a database of known threats. The link is sent to our secure backend.";
    }

    @Override
    public boolean isConfigured() {
        return backendProxyUrl != null && !backendProxyUrl.isEmpty();
    }

    @Override
    public ReputationResult check(String urlToCheck) throws IOException {
        if (!isConfigured()) {
            return ReputationResult.unknown("Service not configured");
        }

        try {
            URL url = new URL(backendProxyUrl);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setConnectTimeout(10000);
            conn.setReadTimeout(10000);
            conn.setDoOutput(true);

            // Constructing Safe Browsing v4 compatible request body to proxy
            JSONObject threatInfo = new JSONObject();
            JSONArray threatTypes = new JSONArray();
            threatTypes.put("MALWARE");
            threatTypes.put("SOCIAL_ENGINEERING");
            threatTypes.put("UNWANTED_SOFTWARE");
            threatTypes.put("POTENTIALLY_HARMFUL_APPLICATION");
            threatInfo.put("threatTypes", threatTypes);

            JSONArray platformTypes = new JSONArray();
            platformTypes.put("ANY_PLATFORM");
            threatInfo.put("platformTypes", platformTypes);

            JSONArray threatEntryTypes = new JSONArray();
            threatEntryTypes.put("URL");
            threatInfo.put("threatEntryTypes", threatEntryTypes);

            JSONArray threatEntries = new JSONArray();
            JSONObject entry = new JSONObject();
            entry.put("url", urlToCheck);
            threatEntries.put(entry);
            threatInfo.put("threatEntries", threatEntries);

            JSONObject requestBody = new JSONObject();
            requestBody.put("client", new JSONObject().put("clientId", "phishnet").put("clientVersion", "1.0.0"));
            requestBody.put("threatInfo", threatInfo);

            try (OutputStream os = conn.getOutputStream()) {
                byte[] input = requestBody.toString().getBytes(StandardCharsets.UTF_8);
                os.write(input, 0, input.length);
            }

            int status = conn.getResponseCode();
            if (status != 200) {
                return ReputationResult.unknown("API returned status " + status);
            }

            StringBuilder response = new StringBuilder();
            try (BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
                String responseLine;
                while ((responseLine = br.readLine()) != null) {
                    response.append(responseLine.trim());
                }
            }
            conn.disconnect();

            JSONObject jsonResponse = new JSONObject(response.toString());
            if (jsonResponse.has("matches") && jsonResponse.getJSONArray("matches").length() > 0) {
                String threatType = jsonResponse.getJSONArray("matches").getJSONObject(0).optString("threatType", "Unknown Threat");
                return ReputationResult.threat("Identified as " + threatType);
            }

            return ReputationResult.noMatch();
        } catch (JSONException e) {
            throw new IOException("JSON Parsing error during threat intelligence check", e);
        }
    }
}
