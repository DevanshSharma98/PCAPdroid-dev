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
    private static final int DB_VERSION = 1;

    public SigintHistory(@NonNull Context context) {
        super(context.getApplicationContext(), DB_NAME, null, DB_VERSION);
    }

    @Override public void onCreate(SQLiteDatabase db) {
        db.execSQL("CREATE TABLE sessions (id INTEGER PRIMARY KEY, started INTEGER NOT NULL)");
        db.execSQL("CREATE TABLE observations (session_id INTEGER NOT NULL, key TEXT NOT NULL, " +
                "app TEXT NOT NULL, domain TEXT NOT NULL, ip TEXT NOT NULL, asn TEXT NOT NULL, " +
                "PRIMARY KEY(session_id,key))");
        db.execSQL("CREATE INDEX observations_key ON observations(key)");
    }

    @Override public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {}

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
            Cursor old = db.rawQuery("SELECT DISTINCT key FROM observations WHERE session_id=(SELECT id FROM sessions ORDER BY started DESC LIMIT 1)", null);
            while(old.moveToNext()) previous.add(old.getString(0));
            old.close();

            if(!recorded)
                db.insert("sessions", null, values("id", sessionId, "started", System.currentTimeMillis()));
            Set<String> added = new HashSet<>();
            Cursor current = db.rawQuery("SELECT key FROM observations WHERE session_id=?", new String[]{Long.toString(sessionId)});
            while(current.moveToNext()) added.add(current.getString(0));
            current.close();
            for(ConnectionDescriptor conn: connections) {
                if(conn == null || conn.is_blocked) continue;
                String domain = normalize(conn.info);
                String ip = conn.dst_ip == null ? "" : conn.dst_ip;
                String app = Integer.toString(conn.uid);
                String asn = conn.asn == null ? "" : Long.toString(conn.asn.number);
                String key = app + "|" + domain + "|" + ip + "|" + asn;
                if(!added.add(key)) continue;
                ContentValues row = new ContentValues();
                row.put("session_id", sessionId);
                row.put("key", key);
                row.put("app", app);
                row.put("domain", domain);
                row.put("ip", ip);
                row.put("asn", asn);
                if(added.add(key)) {
                    db.insert("observations", null, row);
                    if(!previous.contains(key)) changes.add((domain.isEmpty() ? ip : domain + " → " + ip) + " (UID " + app + ")");
                }
            }
            db.execSQL("DELETE FROM observations WHERE session_id NOT IN (SELECT id FROM sessions ORDER BY started DESC LIMIT 10)");
            db.execSQL("DELETE FROM sessions WHERE id NOT IN (SELECT id FROM sessions ORDER BY started DESC LIMIT 10)");
            db.setTransactionSuccessful();
        } finally {
            db.endTransaction();
        }
        return changes;
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
