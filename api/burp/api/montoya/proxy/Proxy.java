package burp.api.montoya.proxy;

import java.util.List;

/** Stub - proxy access. */
public interface Proxy {
    List<ProxyWebSocketMessage> webSocketHistory();
}
