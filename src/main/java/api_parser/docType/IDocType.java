package api_parser.docType;

import api_parser.model.RequestHeader;
import api_parser.model.RequestSource;
import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;


public interface IDocType {

    // Callbacks ayarlama fonksiyonu
    void setCallbacks(IBurpExtenderCallbacks callbacks);


    // API dokümantasyonunu oluşturma fonksiyonu
    String generate(List<RequestSource> requestSources,String docName);


    JsonObject processAuthHeader(String authValue);

    // Callbacks'i alma fonksiyonu
    IBurpExtenderCallbacks getCallbacks();

    // HTTP Request'in metodunu dönen fonksiyon
    default String getRequestMethod(IHttpRequestResponse req) {
        if (req == null || this.getCallbacks() == null) {
            throw new IllegalArgumentException("Request or Callbacks cannot be null");
        }

        return this.getCallbacks().getHelpers().analyzeRequest(req).getMethod();
    }

    // HTTP Request URL'ini dönen fonksiyon
    default String getRequestUrl(IHttpRequestResponse req) {
        if (req == null || this.getCallbacks() == null) {
            throw new IllegalArgumentException("Request or Callbacks cannot be null");
        }

        return this.getCallbacks().getHelpers().analyzeRequest(req).getUrl().toString();
    }

    default String getRequestPath(IHttpRequestResponse req) {
        if (req == null || this.getCallbacks() == null) {
            throw new IllegalArgumentException("Request or Callbacks cannot be null");
        }

        return this.getCallbacks().getHelpers().analyzeRequest(req).getUrl().getPath();
    }

    // HTTP Request body bilgisini dönen fonksiyon
    default String getRequestBody(IHttpRequestResponse req) {
        if (req == null || this.getCallbacks() == null) {
            throw new IllegalArgumentException("Request or Callbacks cannot be null");
        }

        byte[] requestBytes = req.getRequest();
        int bodyOffset = this.getCallbacks().getHelpers().analyzeRequest(req).getBodyOffset();
        byte[] bodyBytes = new byte[requestBytes.length - bodyOffset];
        System.arraycopy(requestBytes, bodyOffset, bodyBytes, 0, bodyBytes.length);

        return new String(bodyBytes, StandardCharsets.UTF_8);
    }

    // URL parçalama ve işleme fonksiyonu
    default JsonObject getRequestUrlObject(String rawUrl) {
        JsonObject url = new JsonObject();
        String[] urlParts = rawUrl.replace("http://", "").replace("https://", "").split("/");
        JsonArray host = new JsonArray();
        for (String part : urlParts[0].split("\\.")) {
            host.add(part);
        }
        url.add("host", host);
        if (urlParts.length > 1) {
            JsonArray path = new JsonArray();
            for (String part : urlParts[1].split("/")) {
                path.add(part);
            }
            url.add("path", path);
        }
        url.addProperty("raw", rawUrl);
        return url;
    }

    // Request header ve body işlemleri
    default JsonObject getRequestHeadersBody(IHttpRequestResponse req) {
        JsonObject requestDetails = new JsonObject();
        requestDetails.addProperty("method", getRequestMethod(req));
        requestDetails.add("url", getRequestUrlObject(getRequestUrl(req)));

        JsonArray headers = new JsonArray();
        // Yeni header bilgilerini al
        getRequestHeaders(req).forEach(header -> {
            JsonObject headerObj = new JsonObject();
            headerObj.addProperty("key", header.getKey());
            headerObj.addProperty("value", header.getValue());
            headers.add(headerObj);
        });
        requestDetails.add("header", headers);

        JsonObject body = new JsonObject();
        body.addProperty("mode", "raw");
        body.addProperty("raw", getRequestBody(req));
        requestDetails.add("body", body);

        return requestDetails;
    }

    default List<RequestHeader> getRequestHeaders(IHttpRequestResponse req) {
        if (req == null || this.getCallbacks() == null) {
            throw new IllegalArgumentException("Request or Callbacks cannot be null");
        }

        List<RequestHeader> headersList = new ArrayList<>();
        List<String> headers = this.getCallbacks().getHelpers().analyzeRequest(req).getHeaders();

        // İstenmeyen header bilgilerini filtrele (content-length, connection)
        for (String header : headers) {
            if (!header.toLowerCase().contains("content-length") && !header.toLowerCase().contains("connection")) {
                String[] headerParts = header.split(":", 2);
                if (headerParts.length == 2) {
                    headersList.add(new RequestHeader(headerParts[0].trim(), headerParts[1].trim()));
                }
            }
        }

        return headersList;
    }
}