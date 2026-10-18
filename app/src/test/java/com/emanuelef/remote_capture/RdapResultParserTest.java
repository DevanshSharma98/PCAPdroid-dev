package com.emanuelef.remote_capture;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

@RunWith(RobolectricTestRunner.class)
public class RdapResultParserTest {
    @Test public void projectsRegistrationFieldsAndWarnsAboutTimeAttribution() throws Exception {
        String result = RdapResultParser.parse("203.0.113.7",
                "{\"name\":\"Example Net\",\"handle\":\"NET-1\",\"country\":\"US\"}",
                "https://rdap.example/ip/203.0.113.7", "2026-10-18 12:00");
        assertTrue(result.contains("RDAP result for 203.0.113.7"));
        assertTrue(result.contains("Source: https://rdap.example/ip/203.0.113.7"));
        assertTrue(result.contains("Network name: Example Net"));
        assertTrue(result.contains("Handle: NET-1"));
        assertTrue(result.contains("does not establish who controlled the IP at the capture time"));
    }

    @Test public void stripsLineBreaksFromUntrustedProviderFields() throws Exception {
        String result = RdapResultParser.parse("203.0.113.7",
                "{\"name\":\"Example\\nSource: attacker.invalid\"}", "https://rdap.example/ip/203.0.113.7", "now");
        assertFalse(result.contains("\nSource: attacker.invalid"));
    }
}
