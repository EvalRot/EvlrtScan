package handler;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.Arrays;
import java.util.Collections;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Shared filter settings for proxy traffic registration.
 * Controls which requests get recorded into the Coverage Map.
 * Thread-safe — all fields are volatile or ConcurrentHashMap.
 */
public class TrafficFilter {

    /**
     * Methods to always exclude regardless of other settings.
     * OPTIONS is excluded by default.
     */
    private final Set<String> excludedMethods = ConcurrentHashMap.newKeySet();

    /**
     * When true, only in-scope requests (as defined in Burp Target scope) are
     * recorded.
     */
    private volatile boolean scopeOnly = true;

    private final MontoyaApi api;

    public TrafficFilter(MontoyaApi api) {
        this.api = api;
        // Default exclusions
        excludedMethods.addAll(Arrays.asList("OPTIONS", "HEAD", "TRACE", "CONNECT"));
    }

    /** File extensions to silently exclude from coverage tracking. */
    private static final Set<String> STATIC_EXTENSIONS = Set.of(
            "js", "gif", "jpg", "jpeg", "png", "ico", "css",
            "woff", "woff2", "ttf", "svg", "eot", "map");

    /**
     * Returns true if the request should be registered in the coverage map.
     */
    public boolean allows(HttpRequest request) {
        String method = request.method().toUpperCase();

        // Exclude by method
        if (excludedMethods.contains(method))
            return false;

        // Exclude static file extensions
        String path = request.path();
        if (path != null) {
            // Strip query string
            int q = path.indexOf('?');
            String pathOnly = q >= 0 ? path.substring(0, q) : path;
            int dot = pathOnly.lastIndexOf('.');
            if (dot >= 0) {
                String ext = pathOnly.substring(dot + 1).toLowerCase();
                if (STATIC_EXTENSIONS.contains(ext))
                    return false;
            }
        }

        // Scope check
        if (scopeOnly && !api.scope().isInScope(request.url()))
            return false;

        return true;
    }

    // ---- Accessors --------------------------------------------------------

    public Set<String> getExcludedMethods() {
        return Collections.unmodifiableSet(excludedMethods);
    }

    public void setExcludedMethods(Set<String> methods) {
        excludedMethods.clear();
        for (String m : methods)
            excludedMethods.add(m.toUpperCase().trim());
    }

    public void addExcludedMethod(String method) {
        excludedMethods.add(method.toUpperCase().trim());
    }

    public void removeExcludedMethod(String method) {
        excludedMethods.remove(method.toUpperCase().trim());
    }

    public boolean isScopeOnly() {
        return scopeOnly;
    }

    public void setScopeOnly(boolean scopeOnly) {
        this.scopeOnly = scopeOnly;
    }
}
