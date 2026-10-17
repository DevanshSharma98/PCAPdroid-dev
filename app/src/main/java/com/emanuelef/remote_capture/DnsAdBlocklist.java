/*
 * Downloads and normalizes domain threat feeds for the local DNS filter.
 * The downloaded file is stored as one domain per line for the native blacklist loader.
 */
package com.emanuelef.remote_capture;

import android.content.Context;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

public final class DnsAdBlocklist {
    public static final String FILE_NAME = "dns_adblock_domains.txt";
    private static final String TAG = "DnsAdBlocklist";
    private static final String LIST_URL = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts";
    private static final String PHISHING_URL = "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-ACTIVE.txt";
    private static final int MIN_DOMAINS = 1000;
    private static final int MAX_DOMAINS = 600000;
    private static final long MAX_FEED_CHARS = 20L * 1024 * 1024;

    private DnsAdBlocklist() {}

    public static boolean isDownloaded(Context context) {
        File file = new File(context.getFilesDir(), FILE_NAME);
        return file.isFile() && file.length() > 0;
    }

    /** Download and combine active domain lists. Returns the unique domain count, or -1 on failure. */
    public static int update(Context context) {
        File dir = context.getFilesDir();
        File temp = new File(dir, FILE_NAME + ".tmp");
        File dest = new File(dir, FILE_NAME);
        File backup = new File(dir, FILE_NAME + ".bak");
        Set<String> domains = new HashSet<>();

        try {
            try (BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(
                    new java.io.FileOutputStream(temp), StandardCharsets.UTF_8))) {
                int hostsCount = downloadFeed(LIST_URL, true, writer, domains);
                if (hostsCount < MIN_DOMAINS)
                    throw new IllegalStateException("Hosts feed contained too few domains: " + hostsCount);

                int phishingCount = downloadFeed(PHISHING_URL, false, writer, domains);
                if (phishingCount < MIN_DOMAINS)
                    throw new IllegalStateException("Phishing feed contained too few domains: " + phishingCount);
            }

            if (domains.size() < MIN_DOMAINS)
                throw new IllegalStateException("Combined feeds contained too few unique domains: " + domains.size());

            if (backup.exists() && !backup.delete())
                throw new IllegalStateException("Could not remove old DNS blocklist backup");
            if (dest.exists() && !dest.renameTo(backup))
                throw new IllegalStateException("Could not preserve the existing DNS blocklist");
            if (!temp.renameTo(dest)) {
                if (backup.exists())
                    //noinspection ResultOfMethodCallIgnored
                    backup.renameTo(dest);
                throw new IllegalStateException("Could not install the downloaded DNS blocklist");
            }
            //noinspection ResultOfMethodCallIgnored
            backup.delete();
            Log.i(TAG, "Updated local DNS blocklist with " + domains.size() + " unique domains");
            return domains.size();
        } catch (Exception e) {
            Log.w(TAG, "DNS ad-block list update failed: " + e.getMessage());
            //noinspection ResultOfMethodCallIgnored
            temp.delete();
            return -1;
        }
    }

    private static int downloadFeed(String url, boolean hostsFormat, BufferedWriter writer,
                                    Set<String> domains) throws Exception {
        HttpURLConnection connection = null;
        int validCount = 0;
        long charsRead = 0;
        try {
            connection = (HttpURLConnection) new URL(url).openConnection();
            connection.setConnectTimeout(15000);
            connection.setReadTimeout(30000);
            connection.setInstanceFollowRedirects(true);
            connection.setRequestProperty("User-Agent", "PCAPdroid-DNS-Filter");

            try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                    connection.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    charsRead += line.length() + 1L;
                    if (charsRead > MAX_FEED_CHARS)
                        throw new IllegalStateException("Domain feed exceeded the configured size limit");

                    String trimmed = line.trim();
                    if (trimmed.isEmpty() || trimmed.startsWith("#"))
                        continue;

                    String[] fields = trimmed.split("\\s+");
                    int firstDomain = 0;
                    if (hostsFormat) {
                        if (fields.length < 2 || !isHostsAddress(fields[0]))
                            continue;
                        firstDomain = 1;
                    } else if (fields.length != 1) {
                        continue;
                    }

                    for (int i = firstDomain; i < fields.length; i++) {
                        String domain = fields[i].toLowerCase(Locale.ROOT);
                        if (!isDomain(domain))
                            continue;
                        validCount++;
                        if (domains.add(domain)) {
                            if (domains.size() > MAX_DOMAINS)
                                throw new IllegalStateException("Combined domain feeds exceeded the configured limit");
                            writer.write(domain);
                            writer.newLine();
                        }
                    }
                }
            }
        } finally {
            if (connection != null)
                connection.disconnect();
        }
        Log.i(TAG, "Loaded " + validCount + " valid entries from " + url);
        return validCount;
    }

    private static boolean isHostsAddress(String value) {
        return "0.0.0.0".equals(value) || "127.0.0.1".equals(value)
                || "::".equals(value) || "::1".equals(value);
    }

    private static boolean isDomain(String domain) {
        if (domain.length() < 3 || domain.length() > 253 || domain.startsWith(".") || domain.endsWith("."))
            return false;
        if ("localhost".equals(domain) || "local".equals(domain) || "broadcasthost".equals(domain))
            return false;

        for (String label : domain.split("\\.", -1)) {
            if (label.isEmpty() || label.length() > 63 || label.startsWith("-") || label.endsWith("-"))
                return false;
            for (int i = 0; i < label.length(); i++) {
                char c = label.charAt(i);
                if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || (c == '-')))
                    return false;
            }
        }
        return true;
    }
}
