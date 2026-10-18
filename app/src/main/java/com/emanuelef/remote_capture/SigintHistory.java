/*
 * This file is part of PCAPdroid.
 *
 * PCAPdroid is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */
package com.emanuelef.remote_capture;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;

import androidx.annotation.NonNull;

import com.emanuelef.remote_capture.model.ConnectionDescriptor;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/** Private, metadata-only history used to identify changes between capture sessions. */
public final class SigintHistory extends SQLiteOpenHelper {
    private static final String DB_NAME = "sigint_history.db";
    private static final int DB_VERSION = 2;

    public SigintHistory(@NonNull Context context) {
        super(context.getApplicationContext(), DB_NAME, null, DB_VERSION);
    }

    @Override public void onCreate(SQLiteDatabase db) {
        db.execSQL("CREATE TABLE sessions (id INTEGER PRIMARY KEY, started INTEGER NOT NULL)");
        db.execSQL("CREATE TABLE observations (session_id INTEGER NOT NULL, key TEXT NOT NULL, " +
                "app TEXT NOT NULL, domain TEXT NOT NULL, ip TEXT NOT NULL, asn TEXT NOT NULL, " +
                "PRIMARY KEY(session_id,key))");
        db.execSQL("CREATE INDEX observations_key ON observations(key)");
        createFlowEvidence(db);
    }

    @Override public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {
        if(oldVersion < 2)
            createFlowEvidence(db);
    }

    private static void createFlowEvidence(SQLiteDatabase db) {
        db.execSQL("CREATE TABLE flow_evidence (session_id INTEGER NOT NULL, connection_id INTEGER NOT NULL, " +
                "uid INTEGER NOT NULL, src_ip TEXT NOT NULL, src_port INTEGER NOT NULL, dst_ip TEXT NOT NULL, " +
                "dst_port INTEGER NOT NULL, ip_proto INTEGER NOT NULL, l7_proto TEXT NOT NULL, domain TEXT NOT NULL, " +
                "first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL, sent_bytes INTEGER NOT NULL, " +
                "rcvd_bytes INTEGER NOT NULL, sent_packets INTEGER NOT NULL, rcvd_packets INTEGER NOT NULL, " +
                "blocked_packets INTEGER NOT NULL, is_blocked INTEGER NOT NULL, status INTEGER NOT NULL, " +
                "error INTEGER NOT NULL, tcp_flags INTEGER NOT NULL, info TEXT NOT NULL, " +
                "protocol_details TEXT NOT NULL, country TEXT NOT NULL, asn INTEGER NOT NULL, " +
                "PRIMARY KEY(session_id,connection_id))");
        db.execSQL("CREATE INDEX flow_evidence_endpoint ON flow_evidence(uid,dst_ip,dst_port)");
        db.execSQL("CREATE INDEX flow_evidence_domain ON flow_evidence(uid,domain)");
    }

    /** Records one session at most once and returns metadata keys that were absent previously. */
    public synchronized @NonNull List<String> record(long sessionId,
                                                       @NonNull List<ConnectionDescriptor> connections) {
        List<String> changes = new ArrayList<>();
        if(sessionId <= 0) return changes;

        SQLiteDatabase db = getWritableDatabase();
        db.beginTransaction();
        try {
            Cursor already = db.rawQuery("SELECT 1 FROM sessions WHERE id=?", new String[]{Long.toString(sessionId)});
            boolean recorded = already.moveToFirst();
            already.close();

            Set<String> previous = new HashSet<>();
            Cursor old = db.rawQuery("SELECT DISTINCT key FROM observations WHERE session_id=" +
                    "(SELECT id FROM sessions WHERE id<>? ORDER BY started DESC LIMIT 1)",
                    new String[]{Long.toString(sessionId)});
            while(old.moveToNext()) previous.add(old.getString(0));
            old.close();

            if(!recorded)
                db.insert("sessions", null, values("id", sessionId, "started", System.currentTimeMillis()));
            Set<String> added = new HashSet<>();
            Cursor current = db.rawQuery("SELECT key FROM observations WHERE session_id=?", new String[]{Long.toString(sessionId)});
            while(current.moveToNext()) added.add(current.getString(0));
            current.close();
            for(ConnectionDescriptor conn: connections) {
                if(conn == null) continue;
                String domain = normalize(conn.info);
                String ip = conn.dst_ip == null ? "" : conn.dst_ip;
                String app = Integer.toString(conn.uid);
                String asn = conn.asn == null ? "" : Long.toString(conn.asn.number);
                String key = app + "|" + domain + "|" + ip + "|" + asn;
                if(!conn.is_blocked && added.add(key)) {
                    ContentValues row = new ContentValues();
                    row.put("session_id", sessionId);
                    row.put("key", key);
                    row.put("app", app);
                    row.put("domain", domain);
                    row.put("ip", ip);
                    row.put("asn", asn);
                    db.insert("observations", null, row);
                    if(!previous.contains(key)) changes.add((domain.isEmpty() ? ip : domain + " → " + ip) + " (UID " + app + ")");
                }

                ContentValues flow = new ContentValues();
                flow.put("session_id", sessionId);
                flow.put("connection_id", conn.incr_id);
                flow.put("uid", conn.uid);
                flow.put("src_ip", safe(conn.src_ip));
                flow.put("src_port", conn.src_port);
                flow.put("dst_ip", ip);
                flow.put("dst_port", conn.dst_port);
                flow.put("ip_proto", conn.ipproto);
                flow.put("l7_proto", safe(conn.l7proto));
                flow.put("domain", domain);
                flow.put("first_seen", conn.first_seen);
                flow.put("last_seen", conn.last_seen);
                flow.put("sent_bytes", conn.sent_bytes);
                flow.put("rcvd_bytes", conn.rcvd_bytes);
                flow.put("sent_packets", conn.sent_pkts);
                flow.put("rcvd_packets", conn.rcvd_pkts);
                flow.put("blocked_packets", conn.blocked_pkts);
                flow.put("is_blocked", conn.is_blocked ? 1 : 0);
                flow.put("status", conn.status);
                flow.put("error", conn.error);
                flow.put("tcp_flags", (conn.getSentTcpFlags() << 8) | conn.getRcvdTcpFlags());
                flow.put("info", safe(conn.info));
                flow.put("protocol_details", safe(conn.protocol_details));
                flow.put("country", safe(conn.country));
                flow.put("asn", conn.asn == null ? 0 : conn.asn.number);
                db.insertWithOnConflict("flow_evidence", null, flow, SQLiteDatabase.CONFLICT_REPLACE);
            }
            db.execSQL("DELETE FROM flow_evidence WHERE session_id=? AND connection_id NOT IN " +
                    "(SELECT connection_id FROM flow_evidence WHERE session_id=? ORDER BY last_seen DESC LIMIT 10000)",
                    new Object[]{sessionId, sessionId});
            db.execSQL("DELETE FROM observations WHERE session_id NOT IN (SELECT id FROM sessions ORDER BY started DESC LIMIT 10)");
            db.execSQL("DELETE FROM flow_evidence WHERE session_id NOT IN (SELECT id FROM sessions ORDER BY started DESC LIMIT 10)");
            db.execSQL("DELETE FROM sessions WHERE id NOT IN (SELECT id FROM sessions ORDER BY started DESC LIMIT 10)");
            db.setTransactionSuccessful();
        } finally {
            db.endTransaction();
        }
        return changes;
    }

    public synchronized @NonNull List<FlowEvidence> getPreviousSessionFlows(long currentSessionId) {
        SQLiteDatabase db = getReadableDatabase();
        Cursor cursor = db.rawQuery("SELECT s.id,s.started,f.connection_id,f.uid,f.src_ip,f.src_port,f.dst_ip,f.dst_port," +
                "f.ip_proto,f.l7_proto,f.domain,f.first_seen,f.last_seen,f.sent_bytes,f.rcvd_bytes," +
                "f.sent_packets,f.rcvd_packets,f.blocked_packets,f.is_blocked,f.info,f.protocol_details," +
                "f.country,f.asn,f.status,f.error,f.tcp_flags FROM flow_evidence f JOIN sessions s ON f.session_id=s.id " +
                "WHERE s.id IN (SELECT id FROM sessions WHERE id<>? ORDER BY started DESC LIMIT 9) " +
                "ORDER BY s.started DESC,f.last_seen DESC LIMIT 10000", new String[]{Long.toString(currentSessionId)});
        List<FlowEvidence> result = new ArrayList<>();
        try {
            while(cursor.moveToNext()) result.add(new FlowEvidence(cursor));
        } finally {
            cursor.close();
        }
        return result;
    }

    private static String safe(String value) { return value == null ? "" : value; }

    public static final class FlowEvidence {
        public final long sessionId, sessionStarted;
        public final int connectionId, uid, srcPort, dstPort, ipProto, sentPackets, receivedPackets, blockedPackets;
        public final int status, error, tcpFlags;
        public final boolean blocked;
        public final String srcIp, dstIp, l7Proto, domain, info, protocolDetails, country;
        public final long firstSeen, lastSeen, sentBytes, receivedBytes, asn;

        private FlowEvidence(Cursor c) {
            sessionId = c.getLong(0); sessionStarted = c.getLong(1);
            connectionId = c.getInt(2); uid = c.getInt(3); srcIp = c.getString(4); srcPort = c.getInt(5);
            dstIp = c.getString(6); dstPort = c.getInt(7); ipProto = c.getInt(8); l7Proto = c.getString(9);
            domain = c.getString(10); firstSeen = c.getLong(11); lastSeen = c.getLong(12);
            sentBytes = c.getLong(13); receivedBytes = c.getLong(14); sentPackets = c.getInt(15);
            receivedPackets = c.getInt(16); blockedPackets = c.getInt(17); blocked = c.getInt(18) != 0;
            info = c.getString(19); protocolDetails = c.getString(20); country = c.getString(21); asn = c.getLong(22);
            status = c.getInt(23); error = c.getInt(24); tcpFlags = c.getInt(25);
        }
    }

    private static String normalize(String value) {
        if(value == null) return "";
        value = value.trim().toLowerCase(java.util.Locale.ROOT);
        return value.contains(" ") ? "" : value;
    }

    private static ContentValues values(String k1, long v1, String k2, long v2) {
        ContentValues out = new ContentValues();
        out.put(k1, v1);
        out.put(k2, v2);
        return out;
    }
}
