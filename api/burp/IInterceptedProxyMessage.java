package burp;

public interface IInterceptedProxyMessage {
    IHttpRequestResponse getMessageInfo();
    int getMessageReference();
}
