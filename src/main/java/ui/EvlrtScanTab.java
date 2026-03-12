package ui;

import coverage.CoverageTracker;
import engine.ScanEngine;
import engine.ScanJob;
import handler.TrafficFilter;
import template.TemplateLoader;

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
            TemplateLoader templateLoader, TrafficFilter filter) {
        this.coverageTab = new CoverageTab(tracker, filter);
        this.findingsTab = new FindingsTab(scanEngine);
        this.templatesTab = new TemplatesTab(templateLoader);

        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("🗺 Coverage Map", coverageTab);
        tabs.addTab("🎯 Findings", findingsTab);
        tabs.addTab("📋 Templates", templatesTab);

        // Wire findings listener: when a job completes with findings, push to Findings
        // tab
        scanEngine.addGlobalProgressListener(job -> {
            if (job.getStatus() == ScanJob.JobStatus.COMPLETED && !job.getFindings().isEmpty()) {
                job.getFindings().forEach(findingsTab::addFinding);
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
