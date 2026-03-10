package handler;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import engine.InsertionPointParser;
import engine.ScanEngine;
import template.TemplateLoader;
import ui.ScanConfigDialog;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

/**
 * Adds "🔫 EvlrtScan — Scan..." to right-click context menu in:
 * Repeater, Proxy History, and SiteMap.
 */
public class ContextMenuProvider implements ContextMenuItemsProvider {
    private final MontoyaApi api;
    private final ScanEngine scanEngine;
    private final TemplateLoader templateLoader;
    private final InsertionPointParser parser = new InsertionPointParser();

    public ContextMenuProvider(MontoyaApi api, ScanEngine scanEngine, TemplateLoader templateLoader) {
        this.api = api;
        this.scanEngine = scanEngine;
        this.templateLoader = templateLoader;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> items = new ArrayList<>();

        // Only show when there is a selected HTTP request
        var msgOpt = event.messageEditorRequestResponse();
        var selItems = event.selectedRequestResponses();

        HttpRequest request = null;
        if (msgOpt.isPresent()) {
            request = msgOpt.get().requestResponse().request();
        } else if (!selItems.isEmpty()) {
            request = selItems.get(0).request();
        }

        if (request == null)
            return items;

        final HttpRequest finalRequest = request;

        JMenuItem scanItem = new JMenuItem("🔫 EvlrtScan — Scan...");
        scanItem.addActionListener(e -> {
            SwingUtilities.invokeLater(() -> {
                var templates = templateLoader.loadAll();
                var points = parser.parse(finalRequest);
                Window parent = api.userInterface().swingUtils().suiteFrame();
                ScanConfigDialog dialog = new ScanConfigDialog(parent, finalRequest,
                        templates, points, scanEngine);
                dialog.setVisible(true);
            });
        });
        items.add(scanItem);

        return items;
    }
}
