/*
 * This file is part of PCAPdroid.
 *
 * PCAPdroid is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */
package com.emanuelef.remote_capture;

import androidx.annotation.NonNull;

import org.json.JSONObject;

/** Small, bounded projection of untrusted RDAP JSON onto fields useful for an IP investigation. */
public final class RdapResultParser {
    private RdapResultParser() {}

    public static @NonNull String parse(@NonNull String ip, @NonNull String json,
                                        @NonNull String sourceUrl, @NonNull String retrieved) throws Exception {
        if (!sourceUrl.startsWith("https://")) throw new IllegalArgumentException("RDAP source must use HTTPS");
        JSONObject body = new JSONObject(json);
        StringBuilder summary = new StringBuilder("RDAP result for ").append(clean(ip)).append('\n')
                .append("Source: ").append(clean(sourceUrl)).append('\n')
                .append("Retrieved: ").append(clean(retrieved)).append('\n');
        append(summary, "Network name", body.optString("name", ""));
        append(summary, "Handle", body.optString("handle", ""));
        append(summary, "Country", body.optString("country", ""));
        append(summary, "Network start", body.optString("startAddress", ""));
        append(summary, "Network end", body.optString("endAddress", ""));
        append(summary, "RDAP object type", body.optString("type", ""));
        summary.append("\nThis is current registration data. It does not establish who controlled the IP at the capture time.");
        return summary.toString();
    }

    private static void append(StringBuilder out, String label, String value) {
        String safe = clean(value);
        if (!safe.isEmpty()) out.append(label).append(": ").append(safe).append('\n');
    }

    private static String clean(String value) {
        StringBuilder safe = new StringBuilder();
        for (int i = 0; i < value.length() && safe.length() < 160; i++) {
            char c = value.charAt(i);
            safe.append(Character.isISOControl(c) ? ' ' : c);
        }
        return safe.toString().trim();
    }
}
