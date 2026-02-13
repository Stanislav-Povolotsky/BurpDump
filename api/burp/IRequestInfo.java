package burp;

import java.net.URL;
import java.util.List;

public interface IRequestInfo {
    URL getUrl();
    List<String> getHeaders();
    int getBodyOffset();
    byte getContentType();
}
