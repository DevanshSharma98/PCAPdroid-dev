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

import com.emanuelef.remote_capture.model.ConnectionDescriptor;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Locale;
import java.util.Set;

/** Deterministic, evidence-linked findings for one flow. No reputation or malware label is inferred. */
public final class ConnectionAnomalyAnalyzer {
    private ConnectionAnomalyAnalyzer() {}

    public static final class Finding {
        public final String observation, evidence, hypotheses, confidence, unknowns, nextTest;

        Finding(String observation, String evidence, String hypotheses, String confidence,
                String unknowns, String nextTest) {
            this.observation = observation;
            this.evidence = evidence;
            this.hypotheses = hypotheses;
            this.confidence = confidence;
            this.unknowns = unknowns;
            this.nextTest = nextTest;
        }

        public String render() {
            return "OBSERVATION\n" + observation + "\nEVIDENCE\n" + evidence +
                    "\nPLAUSIBLE EXPLANATIONS\n" + hypotheses + "\nCONFIDENCE\n" + confidence +
                    "\nUNKNOWN\n" + unknowns + "\nNEXT TEST\n" + nextTest;
        }
    }

    public static @NonNull List<Finding> analyze(@NonNull ConnectionDescriptor target,
                                                  @NonNull List<ConnectionDescriptor> current,
                                                  @NonNull List<SigintHistory.FlowEvidence> previous) {
        List<Finding> out = new ArrayList<>();
        String endpoint = target.dst_ip + ":" + target.dst_port + "/" + target.ipproto;
        String domain = normalize(target.info);
        String evidence = "Connection #" + (target.incr_id + 1) + " · UID " + target.uid + " · " + endpoint +
                " · first seen " + target.first_seen + " · last seen " + target.last_seen;

        if(target.is_blocked || target.blocked_pkts > 0) {
            out.add(new Finding("PCAPdroid marked this flow or " + target.blocked_pkts + " packets as blocked.",
                    evidence, "A user firewall rule, DNS ad-block rule, or another configured blocklist may explain the attempt.",
                    "High for the recorded block status; no claim about intent.",
                    "The block reason and app purpose are not established by this flow record.",
                    "Open the firewall entry and compare its rule and timestamp with this connection."));
        }

        if(!previous.isEmpty()) {
            boolean seenBefore = false;
            boolean sameDomainDifferentIp = false;
            Set<Long> comparedSessions = new HashSet<>();
            for(SigintHistory.FlowEvidence old: previous) {
                comparedSessions.add(old.sessionId);
                if(old.uid != target.uid) continue;
                if(old.dstIp.equals(target.dst_ip) &&
                        (domain.isEmpty() || old.domain.isEmpty() || domain.equalsIgnoreCase(old.domain)))
                    seenBefore = true;
                if(!domain.isEmpty() && domain.equalsIgnoreCase(old.domain) && !old.dstIp.equals(target.dst_ip))
                    sameDomainDifferentIp = true;
            }
            int retainedSessions = comparedSessions.size();
            if(sameDomainDifferentIp) {
                out.add(new Finding("The observed domain was associated with a different destination IP in retained capture history.",
                        evidence + ". Domain attribution is the name observed in connection metadata; historical DNS TTL is unavailable.",
                        "CDN rotation, load balancing, hosting changes, or a network-specific resolver answer can explain the change.",
                        "Medium for the difference between retained records; low for its cause.",
                        "The old IP may have belonged to the domain only at the earlier capture time.",
                        "Compare current and historical DNS answers on the same network."));
            } else if(!seenBefore) {
                out.add(new Finding("This app endpoint was not present in the retained historical capture sample.",
                        evidence + ". Comparison uses up to " + retainedSessions + " historical sessions (maximum 9) and at most 10,000 retained flows total.",
                        "The app may have updated, used a new feature, contacted a rotating CDN, or performed normal first-run work.",
                        "Low: absence in retained history is not proof the endpoint is new to the app.",
                        "Earlier sessions may not have run this app or retained this flow.",
                        "Repeat a short capture before and after one controlled app action and compare destinations."));
            }

            String currentFingerprint = fingerprint(target.protocol_details);
            if(!currentFingerprint.isEmpty()) {
                for(SigintHistory.FlowEvidence old: previous) {
                    if(old.uid == target.uid && old.dstIp.equals(target.dst_ip) && old.dstPort == target.dst_port) {
                        String oldFingerprint = fingerprint(old.protocolDetails);
                        if(!oldFingerprint.isEmpty() && !oldFingerprint.equals(currentFingerprint)) {
                            out.add(new Finding("The observed server certificate SHA-1 fingerprint differs from retained capture history.",
                                    evidence + ". Previous fingerprint: " + oldFingerprint + "; current fingerprint: " + currentFingerprint + ".",
                                    "Certificate renewal, a CDN edge, server migration, or an interception proxy are possible explanations.",
                                    "High that the captured fingerprint strings differ; low about why.",
                                    "This passive capture does not establish whether the app accepted the certificate or whether validation succeeded.",
                                    "Compare issuer, subject, validity dates, SNI, and the app's behavior on a trusted network."));
                            break;
                        }
                    }
                }
            }
        }

        if(target.sent_bytes >= 256 * 1024 && target.sent_bytes > Math.max(1, target.rcvd_bytes) * 2) {
            out.add(new Finding("Captured outbound bytes exceed inbound bytes by more than 2:1 and exceed 256 KiB.",
                    evidence + ". Sent " + target.sent_bytes + " bytes; received " + target.rcvd_bytes + " bytes.",
                    "An upload, synchronization, telemetry batch, backup, or user-initiated transfer could produce this pattern.",
                    "High for byte counters; low for interpretation.",
                    "Traffic volume does not reveal payload contents, recipient control, or user data.",
                    "Repeat capture around a known app action and compare the direction and volume."));
        }

        List<Long> starts = new ArrayList<>();
        Map<Long, List<Long>> historicalStarts = new HashMap<>();
        Set<Integer> sharedApps = new HashSet<>();
        int endpointErrors = 0;
        for(ConnectionDescriptor conn: current) {
            if(conn == null) continue;
            if(conn.dst_ip.equals(target.dst_ip)) sharedApps.add(conn.uid);
            if(conn.uid == target.uid && conn.dst_ip.equals(target.dst_ip) && conn.dst_port == target.dst_port &&
                    conn.ipproto == target.ipproto) {
                if(conn.incr_id != target.incr_id) starts.add(conn.first_seen);
                if(conn.error > 0) endpointErrors++;
            }
        }
        for(SigintHistory.FlowEvidence old: previous) {
            if(old.uid == target.uid && old.dstIp.equals(target.dst_ip) && old.dstPort == target.dst_port && old.ipProto == target.ipproto) {
                historicalStarts.computeIfAbsent(old.sessionId, ignored -> new ArrayList<>()).add(old.firstSeen);
                if(old.error > 0) endpointErrors++;
            }
        }
        starts.add(target.first_seen);
        long interval = SigintAnalyzer.periodicMedianInterval(starts);
        boolean historicalPattern = false;
        if(interval == 0) {
            for(List<Long> sessionStarts: historicalStarts.values()) {
                long sessionInterval = SigintAnalyzer.periodicMedianInterval(sessionStarts);
                if(sessionInterval > interval) {
                    interval = sessionInterval;
                    historicalPattern = interval > 0;
                }
            }
        }
        if(interval > 0) {
            out.add(new Finding("Repeated connections to this endpoint have a stable median interval of about " + interval / 1000 + " seconds within one " + (historicalPattern ? "historical" : "current") + " capture session.",
                    evidence + ". Timings from different sessions were not mixed.",
                    "Scheduled sync, keep-alive traffic, background refresh, or periodic telemetry are plausible.",
                    "Medium for the timing pattern; low for purpose.",
                    "A regular interval does not prove beaconing or surveillance.",
                    "Capture across several intervals, then pause one app feature and see whether the pattern changes."));
        }
        if(endpointErrors >= 3) {
            out.add(new Finding("At least three retained attempts to this endpoint have a socket error.",
                    evidence + ". Error-bearing attempts in the retained sample: " + endpointErrors + ".",
                    "A server outage, transient network, DNS/address rotation, or a client retry policy could explain repeated failures.",
                    "High for the retained error count; low for cause.",
                    "The capture may miss attempts or the remote service may behave differently from this phone's network.",
                    "Repeat one connection test after checking whether the destination is currently reachable."));
        }
        if(sharedApps.size() > 1) {
            out.add(new Finding("This destination IP is shared by connections from " + sharedApps.size() + " app UIDs in the retained current session.",
                    evidence + ". Other apps may use the same IP.",
                    "A CDN, shared hosting, or a common vendor service can explain shared infrastructure.",
                    "High for the current connection list; low for app relationship.",
                    "Shared IP does not show that the apps share an operator or data.",
                    "Compare observed hostnames and certificate metadata for the other flows to this IP."));
        }

        if(out.size() > 8) return new ArrayList<>(out.subList(0, 8));
        return out;
    }

    private static String fingerprint(String details) {
        if(details == null) return "";
        String key = "Certificate SHA-1 fingerprint: ";
        int start = details.indexOf(key);
        if(start < 0) return "";
        start += key.length();
        int end = details.indexOf('\n', start);
        if(end < 0) end = details.length();
        return details.substring(start, end).trim().toLowerCase(Locale.ROOT);
    }

    private static String normalize(String value) {
        if(value == null) return "";
        return value.trim().toLowerCase(Locale.ROOT);
    }
}
