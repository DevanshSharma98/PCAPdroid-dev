package com.emanuelef.remote_capture;

import com.emanuelef.remote_capture.model.ConnectionDescriptor;

import org.junit.Test;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;

public class ConnectionAnomalyAnalyzerTest {
    @Test public void reportsPeriodicPatternAsObservationAndNamesUnknowns() {
        List<ConnectionDescriptor> current = new ArrayList<>();
        for (int i = 0; i < 4; i++)
            current.add(connection(i + 1, 1_000_000L + i * 60_000L, 0));

        List<ConnectionAnomalyAnalyzer.Finding> findings = ConnectionAnomalyAnalyzer.analyze(
                current.get(3), current, Collections.emptyList());
        String rendered = render(findings);
        assertTrue(rendered.contains("stable median interval"));
        assertTrue(rendered.contains("PLAUSIBLE EXPLANATIONS"));
        assertTrue(rendered.contains("does not prove beaconing or surveillance"));
    }

    @Test public void describesLargeUploadWithoutCallingItExfiltration() {
        ConnectionDescriptor connection = connection(7, 1_000_000L, 0);
        connection.sent_bytes = 800 * 1024;
        connection.rcvd_bytes = 20 * 1024;

        String rendered = render(ConnectionAnomalyAnalyzer.analyze(connection,
                List.of(connection), Collections.emptyList()));
        assertTrue(rendered.contains("Captured outbound bytes"));
        assertTrue(rendered.contains("backup"));
        assertTrue(rendered.contains("does not reveal payload contents"));
        assertFalse(rendered.toLowerCase().contains("exfiltrated"));
    }

    private static String render(List<ConnectionAnomalyAnalyzer.Finding> findings) {
        StringBuilder out = new StringBuilder();
        for (ConnectionAnomalyAnalyzer.Finding finding: findings) out.append(finding.render()).append('\n');
        return out.toString();
    }

    private static ConnectionDescriptor connection(int id, long when, int error) {
        ConnectionDescriptor connection = new ConnectionDescriptor(id, 4, 6, "192.0.2.4", "203.0.113.10",
                "", 40000 + id, 443, 40000 + id, 10001, 0, false, when);
        connection.info = "api.example.test";
        connection.l7proto = "TLS";
        connection.error = error;
        return connection;
    }
}
