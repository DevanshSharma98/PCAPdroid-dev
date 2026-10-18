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
import com.emanuelef.remote_capture.model.PayloadChunk;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.LinkedHashSet;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.nio.charset.StandardCharsets;

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
        final List<Integer> connectionIds = new ArrayList<>();

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
        return analyze(connections, apps, Collections.emptyList(), CaptureService.getHttpLog());
    }

    public static @NonNull List<String> analyze(@NonNull List<ConnectionDescriptor> connections,
                                                 @NonNull AppsResolver apps,
                                                 @NonNull List<String> newHistory,
                                                 HttpLog httpLog) {
        List<String> findings = new ArrayList<>();
        Map<String, Endpoint> endpoints = new HashMap<>();
        Set<String> dnsBypass = new HashSet<>();
        Set<String> encodedDns = new HashSet<>();
        Map<String, Set<Integer>> endpointApps = new HashMap<>();
        Map<String, Set<String>> domainIps = new HashMap<>();
        int blocked = 0;
        int largeUploads = 0;

        for(ConnectionDescriptor conn: connections) {
            Endpoint endpoint = new Endpoint(conn);
            Endpoint group = endpoints.get(endpoint.key());
            if(group == null) {
                group = endpoint;
                endpoints.put(group.key(), group);
            }
            group.starts.add(conn.first_seen);
            group.connectionIds.add(conn.incr_id);
            String host = conn.info == null ? "" : conn.info.toLowerCase(Locale.ROOT);
            endpointApps.computeIfAbsent(conn.dst_ip, k -> new HashSet<>()).add(conn.uid);
            if(!host.isEmpty() && !conn.dst_ip.isEmpty())
                domainIps.computeIfAbsent(host, k -> new LinkedHashSet<>()).add(conn.dst_ip);
            if(conn.sent_bytes >= 256 * 1024 && conn.sent_bytes > Math.max(1, conn.rcvd_bytes) * 2)
                largeUploads++;

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
                    formatInterval(interval) + " (connection IDs " + connectionIds(e.connectionIds) +"). Check whether this is expected background activity.");
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

        int shared = 0;
        for(Map.Entry<String, Set<Integer>> entry: endpointApps.entrySet()) {
            if(entry.getValue().size() > 1 && shared++ < 5)
                findings.add("Shared infrastructure — " + entry.getKey() + " was contacted by " + entry.getValue().size() +
                        " app UIDs. This can be a common CDN or service; it does not imply the apps are related.");
        }
        for(Map.Entry<String, Set<String>> entry: domainIps.entrySet()) {
            if(entry.getValue().size() > 1)
                findings.add("Observed domain mapping — " + entry.getKey() + " was associated with " + entry.getValue().size() +
                        " destination IPs in this capture. DNS rotation and CDNs commonly cause this.");
        }
        if(largeUploads > 0)
            findings.add("Large outbound transfer — " + largeUploads + " connection(s) sent at least 256 KiB and over twice the received bytes. Byte counts describe captured network traffic, not confirmed file contents.");

        if(httpLog != null) {
            int count = httpLog.getSize();
            int readable = 0;
            int websocket = 0;
            int cleartext = 0;
            Set<String> contentTypes = new LinkedHashSet<>();
            Set<String> sampleFingerprints = new LinkedHashSet<>();
            Set<String> cleartextFields = new LinkedHashSet<>();
            for(int i = 0; i < count; i++) {
                HttpLog.HttpRequest request = httpLog.getRequest(i);
                if(request == null) continue;
                readable++;
                if(request.hasWebsocketData()) websocket++;
                if(request.conn.isCleartext()) {
                    cleartext++;
                    PayloadChunk reqChunk = request.firstChunkPos >= 0 ? request.conn.getPayloadChunk(request.firstChunkPos) : null;
                    if(reqChunk != null && reqChunk.payload != null) {
                        String fields = new String(reqChunk.payload, StandardCharsets.ISO_8859_1).toLowerCase(Locale.ROOT);
                        for(String field: new String[]{"authorization", "cookie", "set-cookie", "password", "passwd", "token"}) {
                            if(fields.contains(field + ":") || fields.contains(field + "=")) cleartextFields.add(field);
                        }
                    }
                }
                if(request.reply != null && request.reply.contentType != null && !request.reply.contentType.isEmpty())
                    contentTypes.add(request.reply.contentType.split(";")[0]);
                if(request.reply != null) {
                    PayloadChunk response = request.reply.firstChunkPos >= 0 ? request.conn.getPayloadChunk(request.reply.firstChunkPos) : null;
                    if(response != null && response.payload != null && response.payload.length > 0)
                        sampleFingerprints.add(sampleType(response.payload) + " sample SHA-256 " + sampleHash(response.payload));
                }
            }
            if(readable > 0)
                findings.add("HTTP transaction metadata — " + readable + " request(s) were parsed" +
                        (contentTypes.isEmpty() ? "." : "; response types include " + contentTypes + ".") +
                        " URL query strings and body contents are not included in this report. HTTPS details require traffic the capture can decrypt.");
            if(cleartext > 0)
                findings.add("Cleartext HTTP — " + cleartext + " parsed request(s) were not encrypted in the captured connection. Anyone able to observe that network path may read their contents.");
            if(!cleartextFields.isEmpty())
                findings.add("Sensitive field names in cleartext — observed field names: " + cleartextFields + ". Values were not read or stored. A field name alone does not show whether a valid secret was sent.");
            if(websocket > 0)
                findings.add("WebSocket activity — " + websocket + " HTTP connection(s) upgraded to WebSocket; this is activity metadata, not a body inspection.");
            int shownSamples = 0;
            for(String fingerprint: sampleFingerprints) {
                if(shownSamples++ >= 5) break;
                findings.add("Captured response sample — " + fingerprint + ". The hash covers at most the first 4096 captured bytes of one in-memory HTTP response chunk, not the complete file.");
            }
        }

        int historyShown = 0;
        for(String item: newHistory) {
            if(historyShown++ >= 8) break;
            findings.add("New since the previous recorded capture — " + item + ". This means the app/domain/IP/ASN combination was not present in that session's retained connection records.");
        }

        if(findings.isEmpty())
            findings.add("No strong hunt signals found in the connections currently retained for this capture. Missing history can also mean an app was not active during earlier captures.");

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
        return periodicMedianInterval(starts) > 0;
    }

    /** Returns a representative beacon interval in milliseconds, or zero if the samples are too sparse/noisy. */
    public static long periodicMedianInterval(List<Long> starts) {
        if(starts.size() < MIN_BEACON_SAMPLES) return 0;
        Collections.sort(starts);
        List<Long> intervals = new ArrayList<>();
        for(int i = 1; i < starts.size(); i++) {
            long interval = starts.get(i) - starts.get(i - 1);
            if(interval >= MIN_BEACON_INTERVAL_MS)
                intervals.add(interval);
        }
        if(intervals.size() < MIN_BEACON_SAMPLES - 1) return 0;
        long median = median(intervals);
        if(median == 0) return 0;
        List<Long> deviations = new ArrayList<>();
        for(long interval: intervals)
            deviations.add(Math.abs(interval - median));
        // Median absolute deviation is robust to one delayed/background connection.
        return (double) median(deviations) / median <= 0.20 ? median : 0;
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

    private static String sampleHash(byte[] bytes) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(bytes, 0, Math.min(bytes.length, 4096));
            byte[] hash = digest.digest();
            StringBuilder out = new StringBuilder();
            for(byte value: hash) out.append(String.format(Locale.ROOT, "%02x", value & 0xff));
            return out.toString();
        } catch(NoSuchAlgorithmException e) {
            return "unavailable";
        }
    }

    private static String sampleType(byte[] bytes) {
        if(bytes.length >= 4 && bytes[0] == '%' && bytes[1] == 'P' && bytes[2] == 'D' && bytes[3] == 'F') return "PDF-like";
        if(bytes.length >= 8 && (bytes[0] & 0xff) == 0x89 && bytes[1] == 'P' && bytes[2] == 'N' && bytes[3] == 'G') return "PNG-like";
        if(bytes.length >= 4 && bytes[0] == 'P' && bytes[1] == 'K' && bytes[2] == 3 && bytes[3] == 4) return "ZIP-like";
        if(bytes.length >= 3 && (bytes[0] & 0xff) == 0xff && (bytes[1] & 0xff) == 0xd8 && (bytes[2] & 0xff) == 0xff) return "JPEG-like";
        if(bytes.length >= 2 && bytes[0] == 'G' && bytes[1] == 'I') return "GIF-like";
        return "unclassified";
    }

    private static String connectionIds(List<Integer> ids) {
        StringBuilder out = new StringBuilder();
        for(int i = 0; i < Math.min(5, ids.size()); i++) {
            if(i > 0) out.append(", ");
            out.append(ids.get(i));
        }
        if(ids.size() > 5) out.append(" …");
        return out.toString();
    }
}
