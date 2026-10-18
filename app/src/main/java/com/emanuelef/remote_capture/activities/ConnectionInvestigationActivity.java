/*
 * This file is part of PCAPdroid.
 *
 * PCAPdroid is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */
package com.emanuelef.remote_capture.activities;

import android.app.AlertDialog;
import android.content.Intent;
import android.net.DnsResolver;
import android.os.Build;
import android.os.CancellationSignal;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
import android.widget.TextView;
import android.widget.EditText;
import android.text.InputType;
import android.text.SpannableString;
import android.text.Spanned;
import android.text.TextPaint;
import android.text.method.LinkMovementMethod;
import android.text.style.ClickableSpan;
import android.view.View;

import androidx.annotation.NonNull;

import com.emanuelef.remote_capture.AppsResolver;
import com.emanuelef.remote_capture.CaptureService;
import com.emanuelef.remote_capture.ConnectionsRegister;
import com.emanuelef.remote_capture.ConnectionAnomalyAnalyzer;
import com.emanuelef.remote_capture.RdapResultParser;
import com.emanuelef.remote_capture.PhantomApiKeyVault;
import com.emanuelef.remote_capture.ReputationResultParser;
import com.emanuelef.remote_capture.R;
import com.emanuelef.remote_capture.SigintHistory;
import com.emanuelef.remote_capture.Utils;
import com.emanuelef.remote_capture.model.Prefs;
import com.emanuelef.remote_capture.activities.prefs.SettingsActivity;
import com.emanuelef.remote_capture.interfaces.ConnectionsListener;
import com.emanuelef.remote_capture.model.AppDescriptor;
import com.emanuelef.remote_capture.model.ConnectionDescriptor;
import com.emanuelef.remote_capture.model.PayloadChunk;

import java.io.InputStream;
import java.io.ByteArrayOutputStream;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.InetAddress;
import java.net.Socket;
import java.net.URL;
import java.net.IDN;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.SNIHostName;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import org.json.JSONArray;
import org.json.JSONObject;

/** Live, connection-scoped evidence view. All protocol parsing remains in PCAPdroid's capture path. */
public class ConnectionInvestigationActivity extends BaseActivity implements ConnectionsListener {
    private static final String CACHE = "phantom_rdap";
    private static final long CACHE_TTL_MS = 24L * 60 * 60 * 1000;
    private static final int MAX_RDAP_BYTES = 256 * 1024;
    private int mConnId;
    private ConnectionDescriptor mConn;
    private boolean mListening;
    private final Handler mHandler = new Handler(Looper.getMainLooper());
    private TextView mState;
    private TextView mEvidence;
    private TextView mFindings;
    private TextView mIntelligence;
    private TextView mActiveResult;
    private boolean mProbeRunning;
    private boolean mLookupRunning;
    private List<SigintHistory.FlowEvidence> mPreviousFlows = Collections.emptyList();
    private final ExecutorService mHistoryIo = Executors.newSingleThreadExecutor(r -> new Thread(r, "phantom-history"));
    private final Runnable mHistoryTick = new Runnable() {
        @Override public void run() {
            persistHistory();
            mHandler.postDelayed(this, 15_000);
        }
    };
    private final Runnable mFindingsRefresh = this::refreshFindings;

    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
        displayBackAction();
        setContentView(R.layout.activity_connection_investigation);
        setTitle(R.string.investigate_connection);
        mConnId = getIntent().getIntExtra(ConnectionDetailsActivity.CONN_ID_KEY, -1);
        mState = findViewById(R.id.investigation_state);
        mEvidence = findViewById(R.id.investigation_evidence);
        mFindings = findViewById(R.id.investigation_findings);
        mIntelligence = findViewById(R.id.investigation_intelligence);
        mIntelligence.setMovementMethod(LinkMovementMethod.getInstance());
        mActiveResult = findViewById(R.id.investigation_active_result);
        findViewById(R.id.investigation_packets).setOnClickListener(v -> {
            android.content.Intent intent = new android.content.Intent(this, ConnectionDetailsActivity.class);
            intent.putExtra(ConnectionDetailsActivity.CONN_ID_KEY, mConnId);
            startActivity(intent);
        });
        findViewById(R.id.investigation_decryption_settings).setOnClickListener(v ->
                new AlertDialog.Builder(this).setTitle(R.string.investigation_decryption_settings)
                        .setMessage(R.string.investigation_decryption_explanation)
                        .setNegativeButton(android.R.string.cancel, null)
                        .setPositiveButton(R.string.investigation_decryption_settings, (d, w) -> {
                            Intent intent = new Intent(this, SettingsActivity.class);
                            intent.putExtra(SettingsActivity.TARGET_PREF_EXTRA, Prefs.PREF_TLS_DECRYPTION_KEY);
                            startActivity(intent);
                        }).show());
        findViewById(R.id.investigation_rdap).setOnClickListener(v -> confirmRdapLookup());
        findViewById(R.id.investigation_ct).setOnClickListener(v -> confirmCtLookup());
        findViewById(R.id.investigation_vt).setOnClickListener(v -> confirmReputationLookup("virustotal"));
        findViewById(R.id.investigation_abuseipdb).setOnClickListener(v -> confirmReputationLookup("abuseipdb"));
        findViewById(R.id.investigation_api_keys).setOnClickListener(v -> chooseApiKeyToConfigure());
        findViewById(R.id.investigation_tcp_test).setOnClickListener(v -> confirmTcpTest());
        findViewById(R.id.investigation_dns_test).setOnClickListener(v -> confirmDnsTest());
        findViewById(R.id.investigation_tls_test).setOnClickListener(v -> confirmTlsTest());
        findViewById(R.id.investigation_http_test).setOnClickListener(v -> confirmHttpTest());
        findViewById(R.id.investigation_share_report).setOnClickListener(v -> shareReport());
        refresh();
    }

    @Override protected void onResume() {
        super.onResume();
        ConnectionsRegister reg = CaptureService.getConnsRegister();
        if (reg != null && !mListening) {
            reg.addListener(this);
            mListening = true;
        }
        loadHistoryAndPersist();
        mHandler.removeCallbacks(mHistoryTick);
        mHandler.postDelayed(mHistoryTick, 15_000);
        refresh();
    }

    @Override protected void onPause() {
        mHandler.removeCallbacks(mHistoryTick);
        persistHistory();
        if (mListening) {
            ConnectionsRegister reg = CaptureService.getConnsRegister();
            if (reg != null) reg.removeListener(this);
            mListening = false;
        }
        super.onPause();
    }

    @Override protected void onDestroy() {
        mHistoryIo.shutdown();
        super.onDestroy();
    }

    private void refresh() {
        ConnectionsRegister reg = CaptureService.getConnsRegister();
        mConn = reg == null ? null : reg.getConnById(mConnId);
        if (mConn == null) {
            mState.setText(R.string.investigation_connection_unavailable);
            mEvidence.setText(R.string.investigation_capture_evidence_unavailable);
            findViewById(R.id.investigation_rdap).setEnabled(false);
            mFindings.setText(R.string.investigation_capture_evidence_unavailable);
            return;
        }

        boolean replay = CaptureService.isReadingFromPcapFile();
        boolean live = mConn.status < ConnectionDescriptor.CONN_STATUS_CLOSED;
        String detectedProto = safe(mConn.l7proto);
        boolean tlsFlow = "TLS".equalsIgnoreCase(detectedProto) || "HTTPS".equalsIgnoreCase(detectedProto) || "QUIC".equalsIgnoreCase(detectedProto);
        findViewById(R.id.investigation_decryption_settings).setVisibility(tlsFlow ? View.VISIBLE : View.GONE);
        mState.setText(replay ? R.string.investigation_replay :
                (live ? R.string.investigation_live : R.string.investigation_completed));
        String l4 = Utils.proto2str(mConn.ipproto);
        String host = safe(mConn.info);
        StringBuilder out = new StringBuilder();
        out.append("OBSERVED IN THIS CAPTURE\n")
                .append("Connection ID: ").append(mConn.incr_id).append("\n")
                .append("App UID: ").append(mConn.uid);
        AppDescriptor app = new AppsResolver(this).getAppByUid(mConn.uid, 0);
        if (app != null) out.append(" ( ").append(app.getName()).append(" )");
        out.append("\nTuple: ").append(safe(mConn.src_ip)).append(':').append(mConn.src_port)
                .append(" → ").append(safe(mConn.dst_ip)).append(':').append(mConn.dst_port)
                .append(" (IPv").append(mConn.ipver).append(' ').append(l4).append(")\n")
                .append("Detected protocol: ").append(safe(mConn.l7proto)).append("\n");
        if (!host.isEmpty()) {
            String label = "DNS".equalsIgnoreCase(mConn.l7proto) ? "Observed DNS query" :
                    ("HTTP".equalsIgnoreCase(mConn.l7proto) ? "Observed HTTP host" : "Observed host/SNI");
            out.append(label).append(": ").append(host).append("\n");
        } else out.append("Domain/SNI: not observed for this connection\n");
        out.append("First seen: ").append(Utils.formatEpochMillis(this, mConn.first_seen)).append("\n")
                .append("Last seen: ").append(Utils.formatEpochMillis(this, mConn.last_seen)).append("\n")
                .append("Duration: ").append(Utils.formatDuration(this, Math.max(0, (mConn.last_seen - mConn.first_seen) / 1000))).append("\n")
                .append("Packets (received / sent): ").append(mConn.rcvd_pkts).append(" / ").append(mConn.sent_pkts).append("\n")
                .append("Bytes (received / sent): ").append(Utils.formatBytes(mConn.rcvd_bytes)).append(" / ").append(Utils.formatBytes(mConn.sent_bytes)).append("\n")
                .append("Connection state: ").append(mConn.getStatusLabel(this)).append("\n")
                .append("Capture blocklist flags: ").append(mConn.isBlacklisted() ? "matched" : "no match recorded").append("\n")
                .append("TLS/application-data visibility: ").append(mConn.getDecryptionStatusLabel(this));
        if (mConn.decryption_error != null)
            out.append("\nDecryption error: ").append(mConn.decryption_error);
        if (mConn.isPayloadTruncated()) out.append("\nPayload retention: truncated by capture limits/add-on");

        out.append("\n\nINFRASTRUCTURE\n");
        if (mConn.asn != null && mConn.asn.isKnown())
            out.append("ASN: ").append(mConn.asn).append(" (from configured local GeoIP data)\n");
        else out.append("ASN/organisation: unavailable in current local GeoIP data\n");
        if (mConn.country != null && !mConn.country.isEmpty())
            out.append("Country: ").append(Utils.getCountryName(this, mConn.country)).append(" (local GeoIP data)\n");
        else out.append("Country: unavailable in current local GeoIP data\n");
        if (mConn.protocol_details != null && !mConn.protocol_details.isEmpty())
            out.append("\nPROTOCOL METADATA FROM PCAPDROID’S EXISTING nDPI PARSER\n").append(mConn.protocol_details);
        if ("DNS".equalsIgnoreCase(mConn.l7proto))
            out.append("DNS CNAME chains are not currently retained by the capture callback. Current public DNS is a separate, user-initiated test.\n");
        if ("TLS".equalsIgnoreCase(mConn.l7proto) || "HTTPS".equalsIgnoreCase(mConn.l7proto))
            out.append("Certificate details are present only when the passive handshake supplied them. PCAPdroid does not validate the remote app’s trust decision here.\n");
        out.append("Individual packet timestamps and flags are not retained by this screen; use PCAP export for packet-level review.\n");

        appendRelatedEvidence(out, host);
        appendHttpEvidence(out);
        appendChunkTimeline(out);
        if (mConn.is_blocked || mConn.blocked_pkts > 0)
            out.append("\nOBSERVATION: PCAPdroid reports this flow or some packets as blocked. Review the firewall rule and timestamps; this does not identify the reason the app attempted the connection.");
        else if (mConn.sent_bytes > Math.max(1, mConn.rcvd_bytes) * 2 && mConn.sent_bytes >= 256 * 1024)
            out.append("\nOBSERVATION: Captured outbound bytes exceed inbound bytes by more than 2:1 and exceed 256 KiB. This is a traffic-volume clue only; payload contents and intent are not inferred.");
        else out.append("\nNo connection-specific anomaly threshold was met from the metadata currently available.");
        mEvidence.setText(out.toString());
        scheduleFindingsRefresh();
    }

    private void appendRelatedEvidence(StringBuilder out, String host) {
        List<ConnectionDescriptor> current = snapshotConnections();
        out.append("\nRELATED CONNECTIONS / RETAINED SESSION HISTORY\n");
        int shown = 0;
        int related = 0;
        for (ConnectionDescriptor other: current) {
            if (other.incr_id == mConnId) continue;
            if (mConn.dst_ip.equals(other.dst_ip) || (!host.isEmpty() && host.equalsIgnoreCase(safe(other.info)))) {
                related++;
                if (shown++ < 10) {
                    out.append("#").append(other.incr_id + 1).append(" · UID ").append(other.uid).append(" · ")
                            .append(safe(other.l7proto)).append(" · ").append(other.dst_ip).append(':').append(other.dst_port);
                    if (other.info != null && !other.info.isEmpty()) out.append(" · ").append(other.info);
                    out.append(" · ").append(Utils.formatEpochMillis(this, other.first_seen)).append('\n');
                }
            }
        }
        out.append("Shared-IP/domain connections retained in this capture: ").append(related).append("\n");
        int dnsShown = 0;
        for (ConnectionDescriptor other: current) {
            if (other.uid == mConn.uid && "DNS".equalsIgnoreCase(safe(other.l7proto))) {
                out.append("Current DNS flow #").append(other.incr_id + 1).append(": ").append(safe(other.info));
                if (other.protocol_details != null && !other.protocol_details.isEmpty())
                    out.append(" · ").append(other.protocol_details.replace('\n', ';'));
                out.append('\n');
                if (++dnsShown >= 8) break;
            }
        }
        int oldShown = 0;
        Set<Long> historicalSessions = new HashSet<>();
        Set<String> historicalEndpoints = new HashSet<>();
        int historicalAppFlows = 0;
        for (SigintHistory.FlowEvidence old: mPreviousFlows) {
            if(old.uid == mConn.uid) {
                historicalSessions.add(old.sessionId);
                historicalEndpoints.add(old.dstIp + ":" + old.dstPort + "/" + old.domain);
                historicalAppFlows++;
            }
            if (old.uid == mConn.uid && "DNS".equalsIgnoreCase(old.l7Proto)) {
                out.append("Historical DNS flow #").append(old.connectionId + 1).append(" from session ")
                        .append(Utils.formatEpochMillis(this, old.sessionStarted)).append(" at ")
                        .append(Utils.formatEpochMillis(this, old.firstSeen)).append(": ").append(old.info);
                if (!old.protocolDetails.isEmpty()) out.append(" · ").append(old.protocolDetails.replace('\n', ';'));
                out.append('\n');
                if (++oldShown >= 8) break;
            }
        }
        out.append("Historical baseline for UID ").append(mConn.uid).append(": ").append(historicalAppFlows)
                .append(" flows across ").append(historicalSessions.size()).append(" retained sessions, ")
                .append(historicalEndpoints.size()).append(" distinct endpoints (maximum 9 previous sessions and 10,000 flows total).\n");
        if (dnsShown == 0 && oldShown == 0) out.append("No retained DNS flows for this app in the current or historical sessions.\n");
    }

    private void appendHttpEvidence(StringBuilder out) {
        com.emanuelef.remote_capture.HttpLog http = CaptureService.getHttpLog();
        if (http == null) return;
        int shown = 0;
        int total = 0;
        for (int i = 0; i < http.getSize(); i++) {
            com.emanuelef.remote_capture.HttpLog.HttpRequest request = http.getRequest(i);
            if (request == null || request.conn.incr_id != mConnId) continue;
            total++;
            if (shown < 10) {
                if (shown == 0) out.append("\nHTTP METADATA (PCAPdroid HTTP parser)\n");
                shown++;
                out
                        .append(request.method).append(" ").append(request.host).append(" · ")
                        .append(Utils.formatEpochMillis(this, request.timestamp));
                if (request.reply != null) out.append(" · response ").append(request.reply.responseCode)
                        .append(" · ").append(safe(request.reply.contentType));
                else out.append(" · no response metadata captured");
                out.append("\n");
            }
        }
        if (total > 10) out.append("Additional HTTP transactions omitted from this view: ").append(total - 10).append("\n");
    }

    private void appendChunkTimeline(StringBuilder out) {
        int count = mConn.getNumPayloadChunks();
        out.append("\nCAPTURED PAYLOAD-CHUNK TIMELINE\n");
        if (count == 0) {
            out.append("No payload chunks are retained for this connection. Capture payload mode or protocol support may limit this data.\n");
            return;
        }
        out.append("These are PCAPdroid payload chunks; one chunk is not guaranteed to equal one network packet.\n");
        int first = Math.max(0, count - 40);
        if (first > 0) out.append("Earlier chunks omitted: ").append(first).append("\n");
        for (int i = first; i < count; i++) {
            PayloadChunk chunk = mConn.getPayloadChunk(i);
            if (chunk == null) {
                out.append("Chunk ").append(i + 1).append(": stored in PCAP file; open connection payload details to load it.\n");
                continue;
            }
            int length = chunk.payload == null ? chunk.file_len : chunk.payload.length;
            out.append(Utils.formatEpochMillis(this, chunk.timestamp)).append(" · ")
                    .append(chunk.is_sent ? "sent" : "received").append(" · ")
                    .append(chunk.type).append(" · ").append(length).append(" bytes\n");
        }
    }

    private List<ConnectionDescriptor> snapshotConnections() {
        ConnectionsRegister reg = CaptureService.getConnsRegister();
        if (reg == null) return Collections.emptyList();
        List<ConnectionDescriptor> current = new ArrayList<>();
        synchronized (reg) {
            for (int i = 0; i < reg.getConnCount(); i++) {
                ConnectionDescriptor conn = reg.getConn(i);
                if (conn != null) current.add(conn);
            }
        }
        return current;
    }

    private void loadHistoryAndPersist() {
        long sessionId = CaptureService.getCaptureStartTime();
        List<ConnectionDescriptor> current = snapshotConnections();
        if (sessionId <= 0 || mHistoryIo.isShutdown()) return;
        mHistoryIo.execute(() -> {
            List<SigintHistory.FlowEvidence> previous;
            try (SigintHistory history = new SigintHistory(getApplicationContext())) {
                previous = history.getPreviousSessionFlows(sessionId);
                history.record(sessionId, current);
            }
            List<SigintHistory.FlowEvidence> previousSnapshot = previous;
            mHandler.post(() -> {
                mPreviousFlows = previousSnapshot;
                scheduleFindingsRefresh();
            });
        });
    }

    private void persistHistory() {
        long sessionId = CaptureService.getCaptureStartTime();
        if (sessionId <= 0 || mHistoryIo.isShutdown()) return;
        List<ConnectionDescriptor> current = snapshotConnections();
        mHistoryIo.execute(() -> {
            try (SigintHistory history = new SigintHistory(getApplicationContext())) {
                history.record(sessionId, current);
            }
        });
    }

    private void scheduleFindingsRefresh() {
        mHandler.removeCallbacks(mFindingsRefresh);
        mHandler.postDelayed(mFindingsRefresh, 350);
    }

    private void refreshFindings() {
        if (mConn == null || mFindings == null) return;
        List<ConnectionAnomalyAnalyzer.Finding> findings = ConnectionAnomalyAnalyzer.analyze(
                mConn, snapshotConnections(), mPreviousFlows);
        if (findings.isEmpty()) {
            mFindings.setText(R.string.investigation_no_findings);
            return;
        }
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < findings.size(); i++) {
            out.append("FINDING ").append(i + 1).append('\n').append(findings.get(i).render());
            if (i + 1 < findings.size()) out.append("\n\n──────────\n\n");
        }
        mFindings.setText(out.toString());
    }

    private static String safe(String value) { return value == null ? "" : value; }

    private void confirmRdapLookup() {
        if(mLookupRunning) return;
        if (mConn == null) return;
        String ip = mConn.dst_ip;
        if(!ReputationResultParser.isPublicIpLiteral(ip)) {
            mIntelligence.setText("RDAP lookup is disabled for private, reserved, or invalid destination addresses. No indicator was sent.");
            return;
        }
        new AlertDialog.Builder(this)
                .setTitle(R.string.investigation_rdap_consent_title)
                .setMessage(getString(R.string.investigation_rdap_consent_message, ip))
                .setNegativeButton(android.R.string.cancel, null)
                .setPositiveButton(R.string.investigation_rdap_action, (dialog, which) -> fetchRdap(ip))
                .show();
    }

    private void confirmCtLookup() {
        if(mLookupRunning) return;
        String host = observedHostname();
        if (host.isEmpty()) {
            mIntelligence.setText("Certificate Transparency lookup unavailable: no observed hostname is present.");
            return;
        }
        if(!ReputationResultParser.isPublicLookupHostname(host)) {
            mIntelligence.setText("Certificate Transparency lookup is disabled for local or special-use hostnames. No hostname was sent.");
            return;
        }
        new AlertDialog.Builder(this).setTitle("Search public certificate records?")
                .setMessage("PHANTOM checks its 24-hour cache first. If no fresh result exists, it sends the observed hostname " + host + " to crt.sh over HTTPS. This discloses that hostname to the public Certificate Transparency search service. No IP, app identity, packet, or payload is sent. Results show certificate issuance records and do not establish that this connection used a listed certificate. Continue?")
                .setNegativeButton(android.R.string.cancel, null)
                .setPositiveButton("Search", (dialog, which) -> fetchCertificateTransparency(host)).show();
    }

    private void fetchCertificateTransparency(String host) {
        mLookupRunning = true;
        mIntelligence.setText("Searching crt.sh certificate records…");
        new Thread(() -> {
            HttpURLConnection connection = null;
            String result;
            long now = System.currentTimeMillis();
            String cacheKey = "result_ct_" + host;
            android.content.SharedPreferences cache = getSharedPreferences(CACHE, MODE_PRIVATE);
            String cached = cache.getString(cacheKey, null);
            long cachedAt = cache.getLong(cacheKey + "_time", 0);
            if(cached != null && now >= cachedAt && now - cachedAt < CACHE_TTL_MS) {
                result = cached + "\nCache: reused (maximum age 24 hours)";
            } else {
                try {
                URL url = new URL("https://crt.sh/?q=" + Uri.encode(host) + "&output=json");
                connection = (HttpURLConnection) url.openConnection();
                connection.setConnectTimeout(5000); connection.setReadTimeout(5000);
                connection.setInstanceFollowRedirects(false);
                connection.setRequestProperty("Accept", "application/json");
                int status = connection.getResponseCode();
                if(status >= 300 && status < 400) throw new IllegalStateException("HTTPS redirect not followed");
                if(status < 200 || status >= 300) throw new IllegalStateException("HTTP " + status);
                JSONArray rows = new JSONArray(readBounded(connection.getInputStream()));
                StringBuilder out = new StringBuilder("EXTERNAL CERTIFICATE TRANSPARENCY RESULTS\nProvider: crt.sh · Retrieved: ")
                        .append(Utils.formatEpochMillis(this, now)).append("\nQuery: ").append(host)
                        .append("\nMatching records returned: ").append(rows.length())
                        .append("\nCertificate log entries show issuance data; they do not prove this captured connection presented any listed certificate.\n");
                int count = Math.min(8, rows.length());
                for(int i = 0; i < count; i++) {
                    JSONObject row = rows.optJSONObject(i);
                    if(row == null) continue;
                    out.append("\nEntry ").append(cleanExternal(row.optString("id", "unknown")))
                            .append(" · issued ").append(cleanExternal(row.optString("not_before", "unknown")))
                            .append(" to ").append(cleanExternal(row.optString("not_after", "unknown")))
                            .append("\nNames: ").append(cleanExternal(row.optString("name_value", "unavailable")).replace('\n', ','))
                            .append("\nIssuer: ").append(cleanExternal(row.optString("issuer_name", "unavailable")));
                }
                if(rows.length() > count) out.append("\n\nMore records omitted from this view.");
                out.append("\nSource: https://crt.sh/?q=").append(Uri.encode(host));
                result = out.toString();
                cache.edit().putString(cacheKey, result).putLong(cacheKey + "_time", now).apply();
            } catch(Exception e) {
                result = "Certificate Transparency lookup failed for " + host + ": " + e.getClass().getSimpleName() +
                        (e.getMessage() == null ? "" : " (" + e.getMessage() + ")") +
                        "\nThe hostname query was the only indicator sent; no captured packet or payload was uploaded.";
                } finally { if(connection != null) connection.disconnect(); }
            }
            String text = result;
            mHandler.post(() -> { mLookupRunning = false; showIntelligenceResult(text); });
        }, "phantom-ct-lookup").start();
    }

    private static String cleanExternal(String value) {
        if(value == null) return "";
        StringBuilder clean = new StringBuilder();
        for(int i = 0; i < value.length() && clean.length() < 512; i++) {
            char c = value.charAt(i);
            clean.append(Character.isISOControl(c) ? ' ' : c);
        }
        return clean.toString();
    }

    private void chooseApiKeyToConfigure() {
        String[] providers = {"VirusTotal", "AbuseIPDB"};
        new AlertDialog.Builder(this).setTitle("Choose provider key")
                .setItems(providers, (dialog, which) -> configureApiKey(which == 0 ? "virustotal" : "abuseipdb", providers[which]))
                .show();
    }

    private void configureApiKey(String provider, String label) {
        EditText input = new EditText(this);
        input.setSingleLine(true);
        input.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        input.setHint("Paste API key");
        int pad = (int) (20 * getResources().getDisplayMetrics().density);
        input.setPadding(pad, pad, pad, pad);
        new AlertDialog.Builder(this).setTitle(label + " API key")
                .setMessage("The key is encrypted with Android Keystore and stored only on this device. It is sent only in the provider’s HTTPS authentication header when you explicitly run that provider lookup. Leave blank and tap Clear key to remove it.")
                .setView(input)
                .setNegativeButton(android.R.string.cancel, null)
                .setNeutralButton("Clear key", (dialog, which) -> {
                    try {
                        PhantomApiKeyVault.save(this, provider, "");
                        mIntelligence.setText(label + " API key removed.");
                    } catch(Exception e) { mIntelligence.setText("Could not remove key: " + e.getClass().getSimpleName()); }
                })
                .setPositiveButton("Save encrypted", (dialog, which) -> {
                    String key = input.getText().toString().trim();
                    if(key.length() < 8 || key.length() > 512 || key.matches(".*[\\r\\n\\t].*")) {
                        mIntelligence.setText("API key was not saved: enter a valid key between 8 and 512 characters.");
                        return;
                    }
                    try {
                        PhantomApiKeyVault.save(this, provider, key);
                        input.setText("");
                        mIntelligence.setText(label + " API key encrypted and saved on this device.");
                    } catch(Exception e) { mIntelligence.setText("Could not securely save key: " + e.getClass().getSimpleName()); }
                }).show();
    }

    private void confirmReputationLookup(String provider) {
        if(mLookupRunning) return;
        if(mConn == null) return;
        final String ip = mConn.dst_ip;
        if(!ReputationResultParser.isPublicIpLiteral(ip)) {
            mIntelligence.setText("External reputation lookup is disabled for private, reserved, or invalid destination addresses. No indicator was sent.");
            return;
        }
        String providerName = provider.equals("virustotal") ? "VirusTotal" : "AbuseIPDB";
        String providerNotice = provider.equals("virustotal") ?
                " VirusTotal documents that queried indicators are added to its community dataset; do not query sensitive or confidential indicators." :
                " AbuseIPDB may retain the lookup under its service policy.";
        try {
            String apiKey = PhantomApiKeyVault.get(this, provider);
            if(apiKey == null || apiKey.isEmpty()) {
                new AlertDialog.Builder(this).setTitle("Configure " + providerName + " first")
                        .setMessage("No encrypted API key is saved. Configure a key to use this optional provider.")
                        .setNegativeButton(android.R.string.cancel, null)
                        .setPositiveButton(R.string.investigation_api_keys_action, (d, w) -> configureApiKey(provider, providerName)).show();
                return;
            }
            new AlertDialog.Builder(this).setTitle("Send IP to " + providerName + "?")
                    .setMessage("PHANTOM checks its 24-hour cache first. If no fresh result exists, the exact destination IP " + ip + " and your " + providerName + " API key will be sent over HTTPS to " +
                            (provider.equals("virustotal") ? "virustotal.com" : "abuseipdb.com") +
                            ". The provider can associate the query with your account." + providerNotice +
                            " No hostname, app identity, packet, or payload is sent by PHANTOM. No rescan or report submission will be requested. Continue?")
                    .setNegativeButton(android.R.string.cancel, null)
                    .setPositiveButton("Look up IP", (d, w) -> fetchReputation(provider, ip))
                    .show();
        } catch(Exception e) {
            mIntelligence.setText("Could not read the encrypted " + providerName + " key: " + e.getClass().getSimpleName() +
                    ". Re-enter the key in Configure reputation API keys.");
        }
    }

    private void fetchReputation(String provider, String ip) {
        mLookupRunning = true;
        String providerName = provider.equals("virustotal") ? "VirusTotal" : "AbuseIPDB";
        mIntelligence.setText("Querying " + providerName + " for " + ip + "…");
        new Thread(() -> {
            HttpURLConnection connection = null;
            String result;
            String cacheKey = "result_" + provider + "_" + ip;
            long now = System.currentTimeMillis();
            android.content.SharedPreferences cache = getSharedPreferences(CACHE, MODE_PRIVATE);
            String cached = cache.getString(cacheKey, null);
            long cachedAt = cache.getLong(cacheKey + "_time", 0);
            if(cached != null && now >= cachedAt && now - cachedAt < CACHE_TTL_MS) {
                result = cached + "\nCache: reused (maximum age 24 hours)";
            } else {
                try {
                    String key = PhantomApiKeyVault.get(this, provider);
                    if(key == null || key.isEmpty()) throw new IllegalStateException("Provider key is not configured");
                    URL url;
                    if(provider.equals("virustotal"))
                        url = new URL("https://www.virustotal.com/api/v3/ip_addresses/" + Uri.encode(ip, ":."));
                    else
                        url = new URL("https://api.abuseipdb.com/api/v2/check?ipAddress=" + Uri.encode(ip) + "&maxAgeInDays=90");
                    connection = (HttpURLConnection) url.openConnection();
                    connection.setConnectTimeout(5000); connection.setReadTimeout(5000);
                    connection.setInstanceFollowRedirects(false);
                    connection.setRequestProperty("Accept", "application/json");
                    connection.setRequestProperty(provider.equals("virustotal") ? "x-apikey" : "Key", key);
                    int status = connection.getResponseCode();
                    if(status == 429) throw new IllegalStateException("provider rate limit reached (HTTP 429)");
                    if(status == 401 || status == 403) throw new IllegalStateException("provider rejected the API key (HTTP " + status + ")");
                    if(status < 200 || status >= 300) throw new IllegalStateException("provider returned HTTP " + status);
                    String json = readBounded(connection.getInputStream());
                    String retrieved = Utils.formatEpochMillis(this, now);
                    result = provider.equals("virustotal") ? ReputationResultParser.virusTotal(ip, json, retrieved) :
                            ReputationResultParser.abuseIpDb(ip, json, retrieved);
                    result += "\nSource: " + (provider.equals("virustotal") ?
                            "https://www.virustotal.com/gui/ip-address/" + Uri.encode(ip, ":.") :
                            "https://www.abuseipdb.com/check/" + Uri.encode(ip, ":."));
                    cache.edit().putString(cacheKey, result).putLong(cacheKey + "_time", now).apply();
                } catch(Exception e) {
                    result = providerName + " lookup failed for " + ip + ": " + e.getClass().getSimpleName() +
                            (e.getMessage() == null ? "" : " (" + e.getMessage() + ")") +
                            "\nNo packet capture or payload was uploaded. Check the key, quota, and network connection.";
                } finally { if(connection != null) connection.disconnect(); }
            }
            String text = result;
            mHandler.post(() -> { mLookupRunning = false; showIntelligenceResult(text); });
        }, "phantom-" + provider).start();
    }

    private void confirmTcpTest() {
        if (mConn == null || mProbeRunning) return;
        String ip = mConn.dst_ip;
        int port = mConn.dst_port;
        new AlertDialog.Builder(this)
                .setTitle(R.string.investigation_tcp_test_title)
                .setMessage(getString(R.string.investigation_tcp_test_consent, ip, port))
                .setNegativeButton(android.R.string.cancel, null)
                .setPositiveButton(R.string.investigation_tcp_test_action, (dialog, which) -> runTcpTest(ip, port))
                .show();
    }

    private void runTcpTest(String ip, int port) {
        mProbeRunning = true;
        mActiveResult.setText(R.string.investigation_tcp_test_running);
        new Thread(() -> {
            long started = SystemClock.elapsedRealtime();
            String result;
            try (Socket socket = new Socket()) {
                socket.connect(new InetSocketAddress(ip, port), 3000);
                long elapsed = SystemClock.elapsedRealtime() - started;
                result = getString(R.string.investigation_tcp_test_connected, ip, port, elapsed);
            } catch (Exception e) {
                long elapsed = SystemClock.elapsedRealtime() - started;
                result = getString(R.string.investigation_tcp_test_failed, ip, port,
                        e.getClass().getSimpleName(), elapsed);
            }
            String finalResult = result;
            mHandler.post(() -> {
                mProbeRunning = false;
                mActiveResult.setText(finalResult);
            });
        }, "phantom-tcp-test").start();
    }

    private String observedHostname() {
        if (mConn == null || mConn.info == null) return "";
        String host = mConn.info.trim();
        if (host.isEmpty() || host.indexOf('/') >= 0 || host.indexOf(' ') >= 0) return "";
        if (host.startsWith("[") && host.endsWith("]")) return "";
        if (host.matches("[0-9.]+") || host.indexOf(':') >= 0) return "";
        try { return IDN.toASCII(host); } catch (IllegalArgumentException e) { return ""; }
    }

    private void confirmDnsTest() {
        if (mConn == null || mProbeRunning) return;
        String host = observedHostname();
        if (host.isEmpty()) {
            mActiveResult.setText("DNS check unavailable: this connection has no observed hostname. No lookup was sent.");
            return;
        }
        new AlertDialog.Builder(this).setTitle("Resolve observed hostname?")
                .setMessage("Resolve " + host + " using Android’s configured system resolver (A and AAAA, one bounded request each). This is a current lookup from PCAPdroid and may differ from the captured app’s resolver or historical answer. Continue?")
                .setNegativeButton(android.R.string.cancel, null)
                .setPositiveButton("Resolve", (d, w) -> runDnsTest(host)).show();
    }

    private void runDnsTest(String host) {
        if (Build.VERSION.SDK_INT < 29) {
            mActiveResult.setText("DNS check requires Android 10 (API 29) or later; no lookup was sent.");
            return;
        }
        mProbeRunning = true;
        mActiveResult.setText("Resolving A and AAAA via Android system DNS…");
        new Thread(() -> {
            StringBuilder result = new StringBuilder("Active DNS check for ").append(host)
                    .append(" via Android system resolver (PCAPdroid context; current result, not capture evidence):\n");
            for (int type : new int[]{1, 28}) {
                final CountDownLatch latch = new CountDownLatch(1);
                final AtomicReference<String> answer = new AtomicReference<>("No answer before 3 second timeout");
                final CancellationSignal cancellation = new CancellationSignal();
                long start = SystemClock.elapsedRealtime();
                try {
                    DnsResolver.getInstance().query(null, host, DnsResolver.FLAG_EMPTY, type, Runnable::run,
                            cancellation, new DnsResolver.Callback<List<InetAddress>>() {
                                @Override public void onAnswer(List<InetAddress> addresses, int rcode) {
                                    StringBuilder value = new StringBuilder("rcode ").append(rcode);
                                    if (addresses != null) for (InetAddress address : addresses) value.append(" ").append(address.getHostAddress());
                                    if (addresses == null || addresses.isEmpty()) value.append(" (no address records)");
                                    answer.set(value.toString()); latch.countDown();
                                }
                                @Override public void onError(DnsResolver.DnsException error) {
                                    answer.set("error " + error.getClass().getSimpleName()); latch.countDown();
                                }
                            });
                    if (!latch.await(3, TimeUnit.SECONDS)) cancellation.cancel();
                } catch (Exception e) { answer.set("error " + e.getClass().getSimpleName()); }
                result.append(type == 1 ? "A: " : "AAAA: ").append(answer.get()).append(" · ")
                        .append(SystemClock.elapsedRealtime() - start).append(" ms\n");
            }
            String text = result.toString();
            mHandler.post(() -> { mProbeRunning = false; mActiveResult.setText(text); });
        }, "phantom-dns-test").start();
    }

    private void confirmTlsTest() {
        if (mConn == null || mProbeRunning) return;
        String host = observedHostname();
        if (host.isEmpty()) {
            mActiveResult.setText("TLS check unavailable: no observed hostname is available for certificate hostname validation.");
            return;
        }
        int port = mConn.dst_port;
        new AlertDialog.Builder(this).setTitle("Run a TLS certificate check?")
                .setMessage("Open one TLS connection to " + host + ":" + port + " (3 second connect and handshake timeout), using normal Android certificate and hostname validation. No app data is sent. This is a current PCAPdroid-originated test and may differ from the captured app. Continue?")
                .setNegativeButton(android.R.string.cancel, null)
                .setPositiveButton("Check TLS", (d, w) -> runTlsTest(host, mConn.dst_ip, port)).show();
    }

    private void runTlsTest(String host, String ip, int port) {
        mProbeRunning = true;
        mActiveResult.setText("Checking TLS handshake and certificate…");
        new Thread(() -> {
            long start = SystemClock.elapsedRealtime();
            String result;
            try (Socket raw = new Socket()) {
                raw.connect(new InetSocketAddress(ip, port), 3000);
                raw.setSoTimeout(3000);
                try (SSLSocket tls = (SSLSocket) SSLSocketFactory.getDefault().createSocket(raw, host, port, true)) {
                    SSLParameters parameters = tls.getSSLParameters();
                    parameters.setEndpointIdentificationAlgorithm("HTTPS");
                    if (Build.VERSION.SDK_INT >= 24) parameters.setServerNames(Collections.singletonList(new SNIHostName(host)));
                    tls.setSSLParameters(parameters);
                    tls.startHandshake();
                    X509Certificate cert = (X509Certificate) tls.getSession().getPeerCertificates()[0];
                    byte[] digest = MessageDigest.getInstance("SHA-256").digest(cert.getEncoded());
                    StringBuilder fp = new StringBuilder();
                    for (byte b : digest) fp.append(String.format(java.util.Locale.US, "%02X", b));
                    result = "Active TLS test to " + host + " (" + ip + "):" + port + " succeeded in " +
                            (SystemClock.elapsedRealtime() - start) + " ms\nTLS " + tls.getSession().getProtocol() +
                            " · cipher " + tls.getSession().getCipherSuite() + "\nCertificate subject: " + cert.getSubjectX500Principal() +
                            "\nIssuer: " + cert.getIssuerX500Principal() + "\nSHA-256: " + fp +
                            "\nNormal Android trust and hostname checks passed for this PCAPdroid test context; this is not the app’s captured trust decision.";
                }
            } catch (Exception e) {
                result = "Active TLS test to " + host + " (" + ip + "):" + port + " failed after " +
                        (SystemClock.elapsedRealtime() - start) + " ms: " + e.getClass().getSimpleName() +
                        (e.getMessage() == null ? "" : " (" + e.getMessage() + ")") +
                        "\nThis new PCAPdroid-originated result does not prove the captured app’s TLS behavior.";
            }
            String text = result;
            mHandler.post(() -> { mProbeRunning = false; mActiveResult.setText(text); });
        }, "phantom-tls-test").start();
    }

    private void confirmHttpTest() {
        if (mConn == null || mProbeRunning) return;
        String host = observedHostname();
        if (host.isEmpty() || (mConn.dst_port != 80 && mConn.dst_port != 443)) {
            mActiveResult.setText("HTTP metadata check requires an observed hostname and destination port 80 or 443. No request was sent.");
            return;
        }
        String scheme = mConn.dst_port == 443 ? "https" : "http";
        String endpoint = scheme + "://" + host + ":" + mConn.dst_port + "/";
        new AlertDialog.Builder(this).setTitle("Send one HTTP HEAD request?")
                .setMessage("Send one HEAD request to " + endpoint + " with a 3 second timeout, no redirects, and no request body. The server may still log the request. This is generated by PCAPdroid and may not represent the captured app. Continue?")
                .setNegativeButton(android.R.string.cancel, null)
                .setPositiveButton("Send HEAD", (d, w) -> runHttpTest(endpoint)).show();
    }

    private void runHttpTest(String endpoint) {
        mProbeRunning = true;
        mActiveResult.setText("Sending one bounded HEAD request…");
        new Thread(() -> {
            long start = SystemClock.elapsedRealtime();
            String result;
            HttpURLConnection connection = null;
            try {
                connection = (HttpURLConnection) new URL(endpoint).openConnection();
                connection.setRequestMethod("HEAD"); connection.setConnectTimeout(3000); connection.setReadTimeout(3000);
                connection.setInstanceFollowRedirects(false); connection.setUseCaches(false);
                int code = connection.getResponseCode();
                result = "Active HTTP HEAD test to " + endpoint + " returned " + code + " in " +
                        (SystemClock.elapsedRealtime() - start) + " ms\nContent-Type: " + connection.getContentType() +
                        "\nRedirects were not followed. This PCAPdroid-originated metadata is distinct from captured app traffic.";
            } catch (Exception e) {
                result = "Active HTTP HEAD test to " + endpoint + " failed after " +
                        (SystemClock.elapsedRealtime() - start) + " ms: " + e.getClass().getSimpleName();
            } finally { if (connection != null) connection.disconnect(); }
            String text = result;
            mHandler.post(() -> { mProbeRunning = false; mActiveResult.setText(text); });
        }, "phantom-http-test").start();
    }

    private void shareReport() {
        String report = "PHANTOM connection investigation\n\n" + mEvidence.getText() +
                "\n\nFINDINGS\n" + mFindings.getText() +
                (mIntelligence.getText().length() == 0 ? "" : "\n\nEXTERNAL INTELLIGENCE\n" + mIntelligence.getText()) +
                (mActiveResult.getText().length() == 0 ? "" : "\n\nACTIVE TEST RESULT\n" + mActiveResult.getText());
        Intent send = new Intent(Intent.ACTION_SEND);
        send.setType("text/plain");
        send.putExtra(Intent.EXTRA_TEXT, report);
        startActivity(Intent.createChooser(send, getString(R.string.investigation_share_report)));
    }

    private void fetchRdap(String ip) {
        mLookupRunning = true;
        mIntelligence.setText(R.string.investigation_rdap_loading);
        new Thread(() -> {
            String result;
            long now = System.currentTimeMillis();
            String key = "result_" + ip;
            var prefs = getSharedPreferences(CACHE, MODE_PRIVATE);
            String cached = prefs.getString(key, null);
            long savedAt = prefs.getLong(key + "_time", 0);
            if (cached != null && now >= savedAt && now - savedAt < CACHE_TTL_MS) {
                result = cached + "\nCache: reused (maximum age 24 hours)";
            } else {
                HttpURLConnection connection = null;
                try {
                    URL url = new URL("https://rdap.org/ip/" + ip);
                    connection = (HttpURLConnection) url.openConnection();
                    connection.setConnectTimeout(5000);
                    connection.setReadTimeout(5000);
                    connection.setInstanceFollowRedirects(false);
                    connection.setRequestMethod("GET");
                    connection.setRequestProperty("Accept", "application/rdap+json, application/json");
                    int status = connection.getResponseCode();
                    if (status >= 300 && status < 400) {
                        String location = connection.getHeaderField("Location");
                        URL redirect = location == null ? null : new URL(url, location);
                        if (redirect == null || !"https".equalsIgnoreCase(redirect.getProtocol()))
                            throw new IllegalStateException("RDAP redirect was not HTTPS");
                        connection.disconnect();
                        connection = (HttpURLConnection) redirect.openConnection();
                        connection.setConnectTimeout(5000);
                        connection.setReadTimeout(5000);
                        connection.setInstanceFollowRedirects(false);
                        connection.setRequestProperty("Accept", "application/rdap+json, application/json");
                        status = connection.getResponseCode();
                    }
                    if (status < 200 || status >= 300) throw new IllegalStateException("HTTP " + status);
                    String json = readBounded(connection.getInputStream());
                    result = RdapResultParser.parse(ip, json, connection.getURL().toString(), Utils.formatEpochMillis(this, now));
                    prefs.edit().putString(key, result).putLong(key + "_time", now).apply();
                } catch (Exception e) {
                    result = "RDAP lookup failed for " + ip + ": " + e.getClass().getSimpleName() +
                            (e.getMessage() == null ? "" : " (" + e.getMessage() + ")") +
                            "\nNo packet data was sent. The request contained only the selected destination IP.";
                } finally {
                    if (connection != null) connection.disconnect();
                }
            }
            String finalResult = result;
            mHandler.post(() -> { mLookupRunning = false; showIntelligenceResult(finalResult); });
        }, "phantom-rdap").start();
    }

    private void showIntelligenceResult(String result) {
        SpannableString text = new SpannableString(result);
        String prefix = "Source: https://";
        int start = result.lastIndexOf(prefix);
        if (start >= 0) {
            int urlStart = start + "Source: ".length();
            int end = result.indexOf('\n', urlStart);
            if (end < 0) end = result.length();
            String source = result.substring(urlStart, end).trim();
            if (source.startsWith("https://")) {
                text.setSpan(new ClickableSpan() {
                    @Override public void onClick(@NonNull View widget) {
                        Intent intent = new Intent(Intent.ACTION_VIEW, Uri.parse(source));
                        Utils.startActivity(ConnectionInvestigationActivity.this, intent);
                    }
                    @Override public void updateDrawState(@NonNull TextPaint ds) {
                        super.updateDrawState(ds);
                        ds.setUnderlineText(true);
                    }
                }, urlStart, urlStart + source.length(), Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
            }
        }
        mIntelligence.setText(text);
    }

    private static String readBounded(InputStream stream) throws Exception {
        try (InputStream in = stream; ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            byte[] buf = new byte[4096];
            int n;
            while ((n = in.read(buf)) != -1) {
                if (out.size() + n > MAX_RDAP_BYTES) throw new IllegalStateException("RDAP response exceeds 256 KiB");
                out.write(buf, 0, n);
            }
            return out.toString(java.nio.charset.StandardCharsets.UTF_8.name());
        }
    }

    @Override public void connectionsChanges(int count) { mHandler.post(this::refresh); }
    @Override public void connectionsAdded(int start, ConnectionDescriptor[] conns) { mHandler.post(this::refresh); }
    @Override public void connectionsRemoved(int start, ConnectionDescriptor[] conns) { mHandler.post(this::refresh); }
    @Override public void connectionsUpdated(int[] positions) {
        if (mConn == null) return;
        ConnectionsRegister reg = CaptureService.getConnsRegister();
        if (reg == null) return;
        for (int pos : positions) {
            ConnectionDescriptor updated = reg.getConn(pos);
            if (updated != null && updated.incr_id == mConnId) {
                mHandler.post(this::refresh);
                break;
            }
        }
    }
}
