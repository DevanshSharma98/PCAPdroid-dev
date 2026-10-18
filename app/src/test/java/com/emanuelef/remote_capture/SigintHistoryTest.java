package com.emanuelef.remote_capture;

import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;

import androidx.test.core.app.ApplicationProvider;

import com.emanuelef.remote_capture.model.ConnectionDescriptor;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;

import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

@RunWith(RobolectricTestRunner.class)
public class SigintHistoryTest {
    @Test public void recordsObservationsOnceAndComparesToPreviousSession() {
        Context context = ApplicationProvider.getApplicationContext();
        context.deleteDatabase("sigint_history.db");
        ConnectionDescriptor first = connection("ads.example");
        SigintHistory history = new SigintHistory(context);
        assertEquals(1, history.record(100, List.of(first)).size());
        history.close();

        history = new SigintHistory(context);
        assertEquals(0, history.record(200, List.of(connection("ads.example"))).size());
        assertEquals(1, history.record(200, List.of(connection("new.example"))).size());
        history.close();
    }

    @Test public void upgradesV1HistoryWithoutDiscardingObservedRows() {
        Context context = ApplicationProvider.getApplicationContext();
        context.deleteDatabase("sigint_history.db");
        SQLiteDatabase old = context.openOrCreateDatabase("sigint_history.db", Context.MODE_PRIVATE, null);
        old.execSQL("CREATE TABLE sessions (id INTEGER PRIMARY KEY, started INTEGER NOT NULL)");
        old.execSQL("CREATE TABLE observations (session_id INTEGER NOT NULL, key TEXT NOT NULL, app TEXT NOT NULL, " +
                "domain TEXT NOT NULL, ip TEXT NOT NULL, asn TEXT NOT NULL, PRIMARY KEY(session_id,key))");
        old.execSQL("CREATE INDEX observations_key ON observations(key)");
        old.execSQL("INSERT INTO sessions(id,started) VALUES(11,100)");
        old.execSQL("INSERT INTO observations(session_id,key,app,domain,ip,asn) VALUES(11,'k','9','example.test','203.0.113.7','64500')");
        old.setVersion(1);
        old.close();

        SigintHistory upgraded = new SigintHistory(context);
        SQLiteDatabase db = upgraded.getWritableDatabase();
        Cursor preserved = db.rawQuery("SELECT COUNT(*) FROM observations WHERE session_id=11 AND domain='example.test'", null);
        preserved.moveToFirst();
        assertEquals(1, preserved.getInt(0));
        preserved.close();
        Cursor schema = db.rawQuery("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='flow_evidence'", null);
        schema.moveToFirst();
        assertEquals(1, schema.getInt(0));
        schema.close();
        upgraded.close();
    }

    @Test public void retainsNinePriorSessionsForComparison() {
        Context context = ApplicationProvider.getApplicationContext();
        context.deleteDatabase("sigint_history.db");
        SigintHistory history = new SigintHistory(context);
        for(int i = 1; i <= 11; i++)
            history.record(i * 100L, List.of(connection("api.example.test")));
        List<SigintHistory.FlowEvidence> previous = history.getPreviousSessionFlows(1100);
        assertEquals(9, previous.size());
        for(SigintHistory.FlowEvidence flow: previous) assertFalse(flow.sessionId == 1100);
        history.close();
    }

    private static ConnectionDescriptor connection(String domain) {
        ConnectionDescriptor connection = new ConnectionDescriptor(1, 4, 6, "192.0.2.2", "203.0.113.7",
                "", 40000, 443, 40000, 12345, 0, false, 1000);
        connection.info = domain;
        connection.l7proto = "TLS";
        return connection;
    }
}
