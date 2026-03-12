import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import coverage.CoverageTracker;
import engine.ScanEngine;
import handler.ContextMenuProvider;
import handler.ProxyTrafficListener;
import handler.TrafficFilter;

import template.TemplateLoader;
import ui.EvlrtScanTab;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;

/**
 * EvlrtScan — Burp Suite Scanning Plugin
 * Entry point implementing BurpExtension.
 */
public class Extension implements BurpExtension {

  private ScanEngine scanEngine;

  @Override
  public void initialize(MontoyaApi api) {
    api.extension().setName("🔫 EvlrtScan");

    // ---- Settings from Burp Persistence ----
    var persist = api.persistence().extensionData();

    // Templates directory: ~/.evlrtscan/yamls/
    String templatesDirPath = persist.getString("evlrtscan.templatesDir");
    if (templatesDirPath == null || templatesDirPath.isBlank()) {
      templatesDirPath = System.getProperty("user.home") + File.separator
          + ".evlrtscan" + File.separator + "yamls";
      persist.setString("evlrtscan.templatesDir", templatesDirPath);
    }

    int threadCount = persist.getInteger("evlrtscan.threads") != null
        ? persist.getInteger("evlrtscan.threads")
        : 5;

    double maxRps = persist.getString("evlrtscan.maxRps") != null
        ? Double.parseDouble(persist.getString("evlrtscan.maxRps"))
        : 10.0;

    // ---- Ensure templates directory exists ----
    try {
      Files.createDirectories(Paths.get(templatesDirPath));
    } catch (Exception e) {
      api.logging().logToError("Could not create templates directory: " + e.getMessage());
    }

    // ---- Core Components ----
    CoverageTracker coverageTracker = new CoverageTracker(api);
    scanEngine = new ScanEngine(api, threadCount, maxRps);
    TemplateLoader templateLoader = new TemplateLoader(templatesDirPath);
    TrafficFilter filter = new TrafficFilter(api);

    // Initial load from disk
    templateLoader.reload();

    // ---- Start Engine ----
    scanEngine.start();

    // Wire coverage map update when jobs complete
    scanEngine.addGlobalProgressListener(job -> {
      if (job.getStatus() == engine.ScanJob.JobStatus.COMPLETED) {
        coverageTracker.recordJobCompletion(job);
      }
    });

    // ---- Register UI ----
    EvlrtScanTab mainTab = new EvlrtScanTab(coverageTracker, scanEngine, templateLoader, filter);
    api.userInterface().registerSuiteTab(mainTab.caption(), mainTab.uiComponent());

    // ---- Register Proxy Listener ----
    api.proxy().registerRequestHandler(new ProxyTrafficListener(coverageTracker, filter));

    // ---- Register Context Menu ----
    api.userInterface().registerContextMenuItemsProvider(
        new ContextMenuProvider(api, scanEngine, templateLoader));

    // ---- Unload Handler ----
    api.extension().registerUnloadingHandler(() -> {
      scanEngine.shutdown();
      api.logging().logToOutput("EvlrtScan unloaded cleanly.");
    });

    api.logging().logToOutput("🔫 EvlrtScan loaded. Templates dir: " + templatesDirPath
        + " (" + templateLoader.loadAll().size() + " templates)");
  }
}