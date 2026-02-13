package burp.api.montoya.ui.contextmenu;

import java.util.List;

/** Stub - fired when context menu is opened in WebSocket History. */
public interface WebSocketContextMenuEvent {
    List<WebSocketMessage> selectedWebSocketMessages();
}
