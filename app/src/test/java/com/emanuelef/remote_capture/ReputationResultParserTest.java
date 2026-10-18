package com.emanuelef.remote_capture;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;

import static org.junit.Assert.assertTrue;

@RunWith(RobolectricTestRunner.class)
public class ReputationResultParserTest {
    @Test public void formatsVirusTotalCountsAsProviderEvidence() throws Exception {
        String result = ReputationResultParser.virusTotal("203.0.113.4",
                "{\"data\":{\"attributes\":{\"as_owner\":\"Example Net\",\"asn\":64500,\"country\":\"US\",\"last_analysis_stats\":{\"malicious\":2,\"suspicious\":1,\"harmless\":10,\"undetected\":4}}}}",
                "today");
        assertTrue(result.contains("Malicious detections: 2"));
        assertTrue(result.contains("Example Net"));
        assertTrue(result.contains("not a malware verdict"));
    }

    @Test public void formatsAbuseReportsWithoutCallingTheCapturedFlowMalicious() throws Exception {
        String result = ReputationResultParser.abuseIpDb("203.0.113.5",
                "{\"data\":{\"abuseConfidenceScore\":30,\"totalReports\":12,\"numDistinctUsers\":4,\"lastReportedAt\":\"2025-01-01T00:00:00Z\",\"usageType\":\"hosting\",\"isp\":\"Example ISP\"}}",
                "today");
        assertTrue(result.contains("Abuse confidence score: 30%"));
        assertTrue(result.contains("Distinct reporters: 4"));
        assertTrue(result.contains("do not establish malicious activity"));
    }

    @Test public void externalLookupsRejectPrivateAndSpecialUseAddresses() {
        org.junit.Assert.assertFalse(ReputationResultParser.isPublicIpLiteral("192.168.1.1"));
        org.junit.Assert.assertFalse(ReputationResultParser.isPublicIpLiteral("100.64.0.1"));
        org.junit.Assert.assertFalse(ReputationResultParser.isPublicIpLiteral("2001:db8::1"));
        org.junit.Assert.assertTrue(ReputationResultParser.isPublicIpLiteral("8.8.8.8"));
        org.junit.Assert.assertTrue(ReputationResultParser.isPublicIpLiteral("2606:4700:4700::1111"));
        org.junit.Assert.assertFalse(ReputationResultParser.isPublicLookupHostname("printer.local"));
        org.junit.Assert.assertFalse(ReputationResultParser.isPublicLookupHostname("service.internal"));
        org.junit.Assert.assertTrue(ReputationResultParser.isPublicLookupHostname("api.example.com"));
    }
}
