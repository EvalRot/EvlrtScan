package template.detection.rules;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import template.detection.DetectionRule;

import java.util.List;

/**
 * Fires when a specific response header contains any of the specified values.
 */
public class HeaderContainsRule implements DetectionRule {
    private final String headerName;
    private final List<String> values;

    public HeaderContainsRule(String headerName, List<String> values) {
        this.headerName = headerName.toLowerCase();
        this.values = values;
    }

    @Override
    public boolean matches(HttpRequestResponse baseline, HttpRequestResponse actual, String payload) {
        if (actual == null || !actual.hasResponse())
            return false;
        HttpResponse response = actual.response();
        return response.headers().stream()
                .filter(h -> h.name().toLowerCase().equals(headerName))
                .anyMatch(h -> values.stream().anyMatch(v -> h.value().contains(v)));
    }
}
