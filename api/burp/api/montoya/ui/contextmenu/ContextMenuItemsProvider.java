package burp.api.montoya.ui.contextmenu;

import java.awt.Component;
import java.util.Collections;
import java.util.List;

/**
 * Stub - Montoya context menu provider.
 * Three overloads exist in the real API; we only need the HTTP and WebSocket ones.
 * The HTTP overload returns empty by default so the legacy IContextMenuFactory
 * remains the sole provider for HTTP context menus (no duplicates).
 */
public interface ContextMenuItemsProvider {

    default List<Component> provideMenuItems(ContextMenuEvent event) {
        return Collections.emptyList();
    }

    default List<Component> provideMenuItems(WebSocketContextMenuEvent event) {
        return Collections.emptyList();
    }
}
