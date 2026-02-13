package burp;

public interface IExtensionHelpers {
    IRequestInfo analyzeRequest(IHttpRequestResponse request);
    IRequestInfo analyzeRequest(byte[] request);
    IResponseInfo analyzeResponse(byte[] response);
    byte[] urlDecode(byte[] data);
}
