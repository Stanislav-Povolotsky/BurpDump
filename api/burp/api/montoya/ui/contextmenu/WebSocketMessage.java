package burp.api.montoya.ui.contextmenu;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.websocket.Direction;

/** Stub - represents a single WebSocket message selected in the UI. */
public interface WebSocketMessage {
    Direction direction();
    ByteArray payload();
    HttpRequest upgradeRequest();
}
