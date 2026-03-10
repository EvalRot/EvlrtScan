package handler;

import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.ProxyRequestHandler;
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction;
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction;
import coverage.CoverageTracker;

/**
 * Listens to all traffic through Burp Proxy and registers endpoints in the
 * Coverage Map. Applies TrafficFilter before recording.
 * Only observes — never intercepts or modifies requests.
 */
public class ProxyTrafficListener implements ProxyRequestHandler {
    private final CoverageTracker tracker;
    private final TrafficFilter filter;

    public ProxyTrafficListener(CoverageTracker tracker, TrafficFilter filter) {
        this.tracker = tracker;
        this.filter = filter;
    }

    @Override
    public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest interceptedRequest) {
        register(interceptedRequest);
        return ProxyRequestReceivedAction.continueWith(interceptedRequest);
    }

    @Override
    public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest interceptedRequest) {
        return ProxyRequestToBeSentAction.continueWith(interceptedRequest);
    }

    private void register(InterceptedRequest req) {
        try {
            if (!filter.allows(req))
                return;

            String host = req.httpService().host();
            String method = req.method();
            String path = req.path();
            tracker.register(host, method, path, "proxy");
        } catch (Exception e) {
            // Never let listener errors bubble into Burp proxy
        }
    }
}
