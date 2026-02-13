package burp;

public interface IBurpExtenderCallbacks {
    void setExtensionName(String name);
    IExtensionHelpers getHelpers();
    void registerContextMenuFactory(IContextMenuFactory factory);
    void registerProxyListener(IProxyListener listener);
    void registerHttpListener(IHttpListener listener);
    void printOutput(String output);
    void printError(String error);
    IHttpRequestResponse[] getProxyHistory();
    IHttpRequestResponse[] getSiteMap(String urlPrefix);
    void saveExtensionSetting(String name, String value);
    String loadExtensionSetting(String name);
}
