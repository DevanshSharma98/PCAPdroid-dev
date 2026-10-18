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

import java.net.InetAddress;

/** Projects untrusted IP reputation responses onto a small, labelled summary. */
public final class ReputationResultParser {
    private ReputationResultParser() {}

    public static @NonNull String virusTotal(@NonNull String ip, @NonNull String json, @NonNull String retrieved) throws Exception {
        JSONObject root = new JSONObject(json).getJSONObject("data").getJSONObject("attributes");
        JSONObject stats = root.optJSONObject("last_analysis_stats");
        if(stats == null) stats = new JSONObject();
        return "VirusTotal IP report · Retrieved " + retrieved + "\nIndicator: " + clean(ip) +
                "\nMalicious detections: " + stats.optInt("malicious", 0) +
                " · Suspicious: " + stats.optInt("suspicious", 0) +
                " · Harmless: " + stats.optInt("harmless", 0) +
                " · Undetected: " + stats.optInt("undetected", 0) +
                "\nNetwork owner: " + clean(root.optString("as_owner", "unavailable")) +
                " · ASN: " + root.optLong("asn", 0) +
                " · Country: " + clean(root.optString("country", "unavailable")) +
                "\nVirusTotal community data is a lead, not a malware verdict or proof of what this connection did.";
    }

    public static @NonNull String abuseIpDb(@NonNull String ip, @NonNull String json, @NonNull String retrieved) throws Exception {
        JSONObject data = new JSONObject(json).getJSONObject("data");
        return "AbuseIPDB report · Retrieved " + retrieved + "\nIndicator: " + clean(ip) +
                "\nAbuse confidence score: " + data.optInt("abuseConfidenceScore", 0) + "%" +
                " · Reports: " + data.optInt("totalReports", 0) +
                " · Distinct reporters: " + data.optInt("numDistinctUsers", 0) +
                "\nLast reported: " + clean(data.optString("lastReportedAt", "unavailable")) +
                "\nUsage type: " + clean(data.optString("usageType", "unavailable")) +
                " · ISP: " + clean(data.optString("isp", "unavailable")) +
                "\nAbuse reports are community submissions; score and report age need context and do not establish malicious activity in this capture.";
    }

    /** Conservative gate: prevent external services from receiving private or special-use addresses. */
    public static boolean isPublicIpLiteral(String value) {
        if(value == null || value.isEmpty()) return false;
        try {
            if(value.indexOf(':') < 0) {
                if(!value.matches("[0-9]{1,3}(\\.[0-9]{1,3}){3}")) return false;
            } else if(!value.matches("[0-9A-Fa-f:.]+")) return false;
            byte[] bytes = InetAddress.getByName(value).getAddress();
            if(bytes.length == 4) {
                int a = bytes[0] & 255, b = bytes[1] & 255, c = bytes[2] & 255;
                if(a == 0 || a == 10 || a == 127 || a >= 224 || (a == 100 && b >= 64 && b <= 127) ||
                        (a == 169 && b == 254) || (a == 172 && b >= 16 && b <= 31) ||
                        (a == 192 && (b == 0 || b == 168)) || (a == 198 && (b == 18 || b == 19 || b == 51)) ||
                        (a == 203 && b == 0) || (a == 192 && b == 0 && c == 2)) return false;
                return true;
            }
            boolean mappedIpv4 = true;
            for(int i = 0; i < 10; i++) if(bytes[i] != 0) mappedIpv4 = false;
            if(mappedIpv4 && (bytes[10] & 255) == 255 && (bytes[11] & 255) == 255)
                return isPublicIpLiteral((bytes[12] & 255) + "." + (bytes[13] & 255) + "." + (bytes[14] & 255) + "." + (bytes[15] & 255));
            InetAddress address = InetAddress.getByAddress(bytes);
            int first = bytes[0] & 255, second = bytes[1] & 255;
            return !address.isAnyLocalAddress() && !address.isLoopbackAddress() && !address.isLinkLocalAddress() && !address.isSiteLocalAddress() &&
                    !address.isMulticastAddress() && (first & 0xfe) != 0xfc &&
                    !(first == 0x20 && second == 0x01 && (bytes[2] & 255) == 0x0d && (bytes[3] & 255) == 0xb8);
        } catch(Exception e) { return false; }
    }

    public static boolean isPublicLookupHostname(String value) {
        if(value == null) return false;
        String host = value.trim().toLowerCase(java.util.Locale.ROOT);
        if(host.endsWith(".")) host = host.substring(0, host.length() - 1);
        if(host.length() > 253 || !host.contains(".") || !host.matches("[a-z0-9.-]+") ||
                host.startsWith(".") || host.endsWith(".") || host.contains("..")) return false;
        for(String suffix: new String[]{"localhost", "local", "internal", "test", "example", "invalid", "onion", "lan", "home", "corp"})
            if(host.equals(suffix) || host.endsWith("." + suffix)) return false;
        return true;
    }

    private static String clean(String value) {
        if(value == null) return "";
        StringBuilder out = new StringBuilder();
        for(int i = 0; i < value.length() && out.length() < 256; i++) {
            char c = value.charAt(i);
            out.append(Character.isISOControl(c) ? ' ' : c);
        }
        return out.toString().trim();
    }
}
