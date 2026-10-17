/*
 * This file is part of PCAPdroid.
 *
 * PCAPdroid is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

package com.emanuelef.remote_capture.activities;

import android.os.Bundle;
import android.widget.Button;
import android.widget.TextView;

import com.emanuelef.remote_capture.AppsResolver;
import com.emanuelef.remote_capture.CaptureService;
import com.emanuelef.remote_capture.ConnectionsRegister;
import com.emanuelef.remote_capture.R;
import com.emanuelef.remote_capture.SigintAnalyzer;
import com.emanuelef.remote_capture.model.ConnectionDescriptor;

import java.util.ArrayList;
import java.util.List;

/** Passive, evidence-based network behavior review for the current capture. */
public class SigintHuntActivity extends BaseActivity {
    private static final String PREFS = "sigint_hunt";
    private static final String KEY_BASELINE = "network_baseline";
    private TextView mNetworkSnapshot;
    private TextView mBaselineStatus;
    private TextView mFindings;
    private String mCurrentSnapshot;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setTitle(R.string.sigint_hunt);
        displayBackAction();
        setContentView(R.layout.activity_sigint_hunt);

        mNetworkSnapshot = findViewById(R.id.network_snapshot);
        mBaselineStatus = findViewById(R.id.network_baseline_status);
        mFindings = findViewById(R.id.sigint_findings);
        Button setBaseline = findViewById(R.id.set_network_baseline);
        findViewById(R.id.refresh_sigint_report).setOnClickListener(v -> refreshReport());
        setBaseline.setOnClickListener(v -> {
            if(mCurrentSnapshot != null && !mCurrentSnapshot.startsWith("Capture is not") &&
                    !mCurrentSnapshot.startsWith("Upstream network details")) {
                getSharedPreferences(PREFS, MODE_PRIVATE).edit().putString(KEY_BASELINE, mCurrentSnapshot).apply();
                mBaselineStatus.setText(R.string.sigint_baseline_saved);
            } else
                mBaselineStatus.setText(R.string.sigint_baseline_unavailable);
        });

        refreshReport();
    }

    private void refreshReport() {
        mCurrentSnapshot = CaptureService.getSigintNetworkSnapshot();
        mNetworkSnapshot.setText(mCurrentSnapshot);

        String baseline = getSharedPreferences(PREFS, MODE_PRIVATE).getString(KEY_BASELINE, null);
        if(baseline == null)
            mBaselineStatus.setText(R.string.sigint_no_baseline);
        else if(baseline.equals(mCurrentSnapshot))
            mBaselineStatus.setText(R.string.sigint_baseline_matches);
        else
            mBaselineStatus.setText(R.string.sigint_baseline_changed);

        ConnectionsRegister register = CaptureService.getConnsRegister();
        if(register == null) {
            mFindings.setText(R.string.sigint_capture_required);
            return;
        }

        List<ConnectionDescriptor> connections = new ArrayList<>();
        for(int i = 0; i < register.getConnCount(); i++) {
            ConnectionDescriptor conn = register.getConn(i);
            if(conn != null)
                connections.add(conn);
        }

        List<String> findings = SigintAnalyzer.analyze(connections, new AppsResolver(this));
        StringBuilder report = new StringBuilder();
        report.append(getString(R.string.sigint_connection_count, connections.size())).append("\n\n");
        for(String finding: findings)
            report.append("• ").append(finding).append("\n\n");
        mFindings.setText(report.toString().trim());
    }
}
