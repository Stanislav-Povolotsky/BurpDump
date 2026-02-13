package burp.api.montoya;

import burp.api.montoya.proxy.Proxy;
import burp.api.montoya.ui.UserInterface;

/** Montoya API root (stub - only methods used by BurpDump). */
public interface MontoyaApi {
    Proxy proxy();
    UserInterface userInterface();
}
