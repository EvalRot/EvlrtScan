package template.detection.rules;

import burp.api.montoya.http.message.HttpRequestResponse;
import template.detection.DetectionRule;
import java.util.regex.Pattern;

/** Fires when the response body matches a regular expression. */
public class BodyRegexRule implements DetectionRule {
    private final Pattern pattern;

    public BodyRegexRule(String regex) {
        this.pattern = Pattern.compile(regex, Pattern.DOTALL | Pattern.CASE_INSENSITIVE);
    }

    @Override
    public boolean matches(HttpRequestResponse baseline, HttpRequestResponse actual, String payload) {
        if (actual == null || !actual.hasResponse())
            return false;
        return pattern.matcher(actual.response().bodyToString()).find();
    }
}
