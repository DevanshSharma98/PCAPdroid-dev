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

import com.emanuelef.remote_capture.model.AppDescriptor;
import com.emanuelef.remote_capture.model.ConnectionDescriptor;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/** Evidence-only heuristics over connections already observed in the current capture. */
public final class SigintAnalyzer {
    private static final int MIN_BEACON_SAMPLES = 4;
    private static final long MIN_BEACON_INTERVAL_MS = 5_000;

    private SigintAnalyzer() {}

    private static final class Endpoint {
        final int uid;
        final String ip;
        final int port;
        final int protocol;
        final List<Long> starts = new ArrayList<>();

        Endpoint(ConnectionDescriptor conn) {
            uid = conn.uid;
            ip = conn.dst_ip;
            port = conn.dst_port;
            protocol = conn.ipproto;
        }

        String key() { return uid + "/" + ip + "/" + port + "/" + protocol; }
    }

    public static @NonNull List<String> analyze(@NonNull List<ConnectionDescriptor> connections,
                                                 @NonNull AppsResolver apps) {
        List<String> findings = new ArrayList<>();
        Map<String, Endpoint> endpoints = new HashMap<>();
        Set<String> dnsBypass = new HashSet<>();
        Set<String> encodedDns = new HashSet<>();
        int blocked = 0;

        for(ConnectionDescriptor conn: connections) {
            Endpoint endpoint = new Endpoint(conn);
            Endpoint group = endpoints.get(endpoint.key());
            if(group == null) {
                group = endpoint;
                endpoints.put(group.key(), group);
            }
            group.starts.add(conn.first_seen);

            String host = conn.info == null ? "" : conn.info.toLowerCase(Locale.ROOT);
            if(conn.dst_port == 853 || conn.dst_port == 784 || conn.dst_port == 8853 || isKnownDohHost(host))
                dnsBypass.add(appName(apps, conn.uid) + " → " + destination(conn, host));

            if("DNS".equalsIgnoreCase(conn.l7proto) && hasLongHighEntropyLabel(host))
                encodedDns.add(appName(apps, conn.uid) + " → " + host);

            if(conn.is_blocked)
                blocked++;
        }

        List<Endpoint> beacons = new ArrayList<>();
        for(Endpoint endpoint: endpoints.values()) {
            if(isPeriodic(endpoint.starts))
                beacons.add(endpoint);
        }
        Collections.sort(beacons, (a, b) -> Integer.compare(b.starts.size(), a.starts.size()));
        for(int i = 0; i < Math.min(5, beacons.size()); i++) {
            Endpoint e = beacons.get(i);
            long interval = medianIntervals(e.starts);
            findings.add("Possible periodic contact — " + appName(apps, e.uid) + " contacted " +
                    e.ip + ":" + e.port + " " + e.starts.size() + " times, about every " +
                    formatInterval(interval) + ". Check whether this is expected background activity.");
        }

        for(String clue: dnsBypass)
            findings.add("Encrypted DNS clue — " + clue + ". This traffic may bypass PHANTOM’s domain list; endpoint matching is indicative, not proof of DNS use.");

        int dnsShown = 0;
        for(String clue: encodedDns) {
            if(dnsShown++ >= 5) break;
            findings.add("Unusual DNS label — " + clue + ". Long, high-entropy labels can come from tracking or encoded data; review the app and query pattern.");
        }

        if(blocked > 0)
            findings.add("Block activity — " + blocked + " blocked connection record(s) are present in this capture.");

        if(findings.isEmpty())
            findings.add("No strong hunt signals found in the connections currently retained for this capture.");

        return findings;
    }

    private static boolean isKnownDohHost(String host) {
        return host.equals("dns.google") || host.endsWith(".dns.google") ||
                host.equals("cloudflare-dns.com") || host.endsWith(".cloudflare-dns.com") ||
                host.equals("dns.quad9.net") || host.equals("doh.opendns.com") ||
                host.equals("dns.nextdns.io");
    }

    private static boolean hasLongHighEntropyLabel(String host) {
        if(host.isEmpty()) return false;
        for(String label: host.split("\\.")) {
            if(label.length() < 24) continue;
            int[] counts = new int[128];
            for(int i = 0; i < label.length(); i++) {
                char c = label.charAt(i);
                if(c < counts.length) counts[c]++;
            }
            double entropy = 0;
            for(int count: counts) {
                if(count == 0) continue;
                double p = (double) count / label.length();
                entropy -= p * (Math.log(p) / Math.log(2));
            }
            if(entropy >= 3.5)
                return true;
        }
        return false;
    }

    private static boolean isPeriodic(List<Long> starts) {
        if(starts.size() < MIN_BEACON_SAMPLES) return false;
        Collections.sort(starts);
        List<Long> intervals = new ArrayList<>();
        for(int i = 1; i < starts.size(); i++) {
            long interval = starts.get(i) - starts.get(i - 1);
            if(interval >= MIN_BEACON_INTERVAL_MS)
                intervals.add(interval);
        }
        if(intervals.size() < MIN_BEACON_SAMPLES - 1) return false;
        long median = median(intervals);
        if(median == 0) return false;
        List<Long> deviations = new ArrayList<>();
        for(long interval: intervals)
            deviations.add(Math.abs(interval - median));
        // Median absolute deviation is robust to one delayed/background connection.
        return (double) median(deviations) / median <= 0.20;
    }

    private static long medianIntervals(List<Long> starts) {
        Collections.sort(starts);
        List<Long> intervals = new ArrayList<>();
        for(int i = 1; i < starts.size(); i++) {
            long interval = starts.get(i) - starts.get(i - 1);
            if(interval >= MIN_BEACON_INTERVAL_MS)
                intervals.add(interval);
        }
        return median(intervals);
    }

    private static long median(List<Long> values) {
        if(values.isEmpty()) return 0;
        Collections.sort(values);
        return values.get(values.size() / 2);
    }

    private static String formatInterval(long ms) {
        if(ms >= 3_600_000) return String.format(Locale.ROOT, "%.1f h", ms / 3_600_000.0);
        if(ms >= 60_000) return String.format(Locale.ROOT, "%.1f min", ms / 60_000.0);
        return String.format(Locale.ROOT, "%.0f s", ms / 1_000.0);
    }

    private static String appName(AppsResolver apps, int uid) {
        AppDescriptor app = apps.getAppByUid(uid, 0);
        return app == null ? "UID " + uid : app.getName();
    }

    private static String destination(ConnectionDescriptor conn, String host) {
        return host.isEmpty() ? conn.dst_ip + ":" + conn.dst_port : host + ":" + conn.dst_port;
    }
}
