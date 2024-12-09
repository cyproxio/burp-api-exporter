package api_parser.docType;

import api_parser.model.AuthContainer;
import api_parser.model.RequestHeader;
import api_parser.model.RequestSource;
import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.List;
import java.util.stream.Collectors;


public class PostmanDocType implements IDocType {
    private IBurpExtenderCallbacks callbacks;
    private PrintWriter stdout;

    public void setStdout(PrintWriter stdout) {
        this.stdout = stdout;
    }

    @Override
    public void setCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
    }

    @Override
    public IBurpExtenderCallbacks getCallbacks() {
        return this.callbacks;
    }

    @Override
    public String generate(List<RequestSource> requestSources,String docName) {
        JsonObject postmanCollection = new JsonObject();

        // "info" kısmı
        JsonObject info = new JsonObject();
        info.addProperty("name", docName);
        info.addProperty("schema", "https://schema.getpostman.com/json/collection/v2.1.0/collection.json");
        postmanCollection.add("info", info);

        JsonArray items = new JsonArray();

        // Koleksiyon seviyesinde auth'u ayarlamak için değişken
        AuthContainer authContainer = new AuthContainer();


        requestSources.stream()
                .collect(Collectors.groupingBy(RequestSource::getFolderName))
                .forEach((folderName, requests) -> {
                    JsonObject folder = new JsonObject();
                    folder.addProperty("name", folderName);

                    JsonArray folderItems = new JsonArray();

                    for (RequestSource requestSource : requests) {
                        JsonObject requestItem = new JsonObject();
                        requestItem.addProperty("name", requestSource.getReqName());

                        JsonObject request = new JsonObject();
                        request.addProperty("method", getRequestMethod(requestSource.getReq()));
                        request.add("url", getRequestUrlForPostman(requestSource.getReq()));

                        JsonObject auth = null;
                        JsonArray headers = new JsonArray();

                        for (RequestHeader header : getRequestHeaders(requestSource.getReq())) {
                            if (header.getKey().equalsIgnoreCase("Authorization")) {
                                auth = processAuthHeader(header.getValue());

                                // Eğer koleksiyon auth'u henüz ayarlanmamışsa, burada ayarla
                                if (authContainer.auth == null) {
                                    authContainer.auth = auth;
                                }
                            } else if (!header.getKey().equalsIgnoreCase("Content-Length") && !header.getKey().equalsIgnoreCase("Connection")) {
                                JsonObject headerObj = new JsonObject();
                                headerObj.addProperty("key", header.getKey());
                                headerObj.addProperty("value", header.getValue());
                                headers.add(headerObj);
                            }
                        }

                        request.add("header", headers);

                        if (auth == null) {
                            JsonObject noAuth = new JsonObject();
                            noAuth.addProperty("type","noauth");
                            request.add("auth", noAuth);

                        }

                        JsonObject body = new JsonObject();
                        body.addProperty("mode", "raw");
                        body.addProperty("raw", getRequestBody(requestSource.getReq()));
                        request.add("body", body);

                        requestItem.add("request", request);
                        folderItems.add(requestItem);
                    }

                    folder.add("item", folderItems);
                    items.add(folder);
                });

        // Eğer koleksiyon auth'u ayarlandıysa, koleksiyona ekle
        if (authContainer.auth != null) {
            postmanCollection.add("auth", authContainer.auth);
        }

        postmanCollection.add("item", items);

        return postmanCollection.toString();
    }

    // HTTP Request URL'ini JSON formatında dönen fonksiyon
    public JsonObject getRequestUrlForPostman(IHttpRequestResponse req) {

        try {
            JsonObject url = new JsonObject();

            // URL'yi Burp Helper üzerinden alıyoruz
            String rawUrl = this.getCallbacks().getHelpers().analyzeRequest(req).getUrl().toString();
            url.addProperty("raw", rawUrl);

            // URL'yi parçalayarak host ve path bilgilerini ekliyoruz
            JsonArray host = new JsonArray();
            String[] urlParts = rawUrl.replace("http://", "").replace("https://", "").split("/");
            String[] hostParts = urlParts[0].split(":");
            for (String part : hostParts[0].split("\\.")) {
                host.add(part);  // Host bilgisini parçalayarak ekliyoruz
            }
            url.add("host", host);

            // Eğer path bilgisi varsa, path'ı JSON dizisine ekliyoruz
            URL parsedUrl = new URL(rawUrl);

            JsonArray path = new JsonArray();
            String[] pathParts = parsedUrl.getPath().split("/");
            for (String part : pathParts) {
                if (!part.isEmpty()) {
                    path.add(part);  // Path bilgisini ekliyoruz
                }
            }
            url.add("path", path);
            return url;

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public JsonObject processAuthHeader(String authValue) {
        JsonObject auth = new JsonObject();

        if (authValue == null || authValue.isEmpty()) {
            return auth; // Eğer header yoksa boş bir auth döner
        }

        // Bearer Auth
        if (authValue.toLowerCase().startsWith("bearer ")) {
            auth.addProperty("type", "bearer");
            JsonArray bearer = new JsonArray();
            JsonObject token = new JsonObject();
            token.addProperty("key", "token");
            token.addProperty("value", authValue.substring(7).trim());
            token.addProperty("type", "string");
            bearer.add(token);
            auth.add("bearer", bearer);
        }
        // Basic Auth
        else if (authValue.toLowerCase().startsWith("basic ")) {
            auth.addProperty("type", "basic");
            String base64Credentials = authValue.substring(6).trim();
            String decoded = new String(java.util.Base64.getDecoder().decode(base64Credentials));
            String[] credentials = decoded.split(":");
            if (credentials.length == 2) {
                auth.addProperty("username", credentials[0]);
                auth.addProperty("password", credentials[1]);
            } else {
                throw new IllegalArgumentException("Invalid Basic Auth credentials format.");
            }
        }
        // Diğer durumlar
        else {
            String[] parts = authValue.trim().split("\\s+", 2); // Boşluğa göre iki parçaya ayırır
            if (parts.length == 2) {
                auth.addProperty("type", parts[0]); // İlk kısım 'type' olarak işlenir
                auth.addProperty("value", parts[1]); // İkinci kısım 'value' olarak işlenir
            } else {
                auth.addProperty("type", "unknown"); // Tek parça varsa 'type' olarak işlenir
                auth.addProperty("value", parts[0]);
            }
        }

        return auth;
    }

}