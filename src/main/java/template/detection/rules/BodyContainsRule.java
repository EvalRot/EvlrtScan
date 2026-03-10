package template.detection.rules;

import burp.api.montoya.http.message.HttpRequestResponse;
import template.detection.DetectionRule;
import java.util.List;

/** Checks if the response body contains any of the specified strings. */
public class BodyContainsRule implements DetectionRule {
    private final List<String> values;
    private final boolean caseSensitive;

    public BodyContainsRule(List<String> values, Boolean caseSensitive) {
        this.values = values;
        this.caseSensitive = caseSensitive != null && caseSensitive;
    }

    @Override
    public boolean matches(HttpRequestResponse baseline, HttpRequestResponse actual, String payload) {
        if (actual == null || !actual.hasResponse())
            return false;
        String body = actual.response().bodyToString();
        if (!caseSensitive)
            body = body.toLowerCase();
        for (String v : values) {
            String check = caseSensitive ? v : v.toLowerCase();
            if (body.contains(check))
                return true;
        }
        return false;
    }
}
