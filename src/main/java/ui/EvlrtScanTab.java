package ui;

import burp.api.montoya.MontoyaApi;
import coverage.CoverageTracker;
import engine.ScanEngine;
import engine.ScanFinding;
import handler.TrafficFilter;
import template.TemplateLoader;

import java.util.Set;

import javax.swing.*;
import java.awt.*;

/**
 * Main plugin tab added to Burp Suite.
 * Sub-tabs: Coverage Map | Findings | Templates
 */
public class EvlrtScanTab {

    private final JPanel component;
    private final CoverageTab coverageTab;
    private final FindingsTab findingsTab;
    private final TemplatesTab templatesTab;

    public EvlrtScanTab(CoverageTracker tracker, ScanEngine scanEngine,
            TemplateLoader templateLoader, TrafficFilter filter, MontoyaApi api) {
        this.coverageTab = new CoverageTab(tracker, filter, scanEngine, api);
        this.findingsTab = new FindingsTab(scanEngine, api);
        this.templatesTab = new TemplatesTab(templateLoader);

        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("🗺 Coverage Map", coverageTab);
        tabs.addTab("🎯 Findings", findingsTab);
        tabs.addTab("📋 Templates", templatesTab);

        // Wire findings listener: push new findings to the Findings tab as they appear
        Set<ScanFinding> alreadyPushed = java.util.concurrent.ConcurrentHashMap.newKeySet();
        scanEngine.addGlobalProgressListener(job -> {
            for (ScanFinding f : job.getFindings()) {
                if (alreadyPushed.add(f)) {
                    findingsTab.addFinding(f);
                }
            }
        });

        this.component = new JPanel(new BorderLayout());
        this.component.add(tabs, BorderLayout.CENTER);
    }

    public String caption() {
        return "🔫 EvlrtScan";
    }

    public Component uiComponent() {
        return component;
    }

    public FindingsTab getFindingsTab() {
        return findingsTab;
    }

    public CoverageTab getCoverageTab() {
        return coverageTab;
    }

    public TemplatesTab getTemplatesTab() {
        return templatesTab;
    }
}
