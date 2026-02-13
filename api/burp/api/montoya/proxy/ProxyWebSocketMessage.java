package burp.api.montoya.proxy;

import burp.api.montoya.ui.contextmenu.WebSocketMessage;
import java.time.ZonedDateTime;

/** Stub - WebSocket message from proxy history (has timestamp). */
public interface ProxyWebSocketMessage extends WebSocketMessage {
    ZonedDateTime time();
    int id();
}
