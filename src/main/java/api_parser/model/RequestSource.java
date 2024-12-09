package api_parser.model;

import burp.IHttpRequestResponse;

public class RequestSource {

    private IHttpRequestResponse req;
    private String reqName;
    private String folderName;

    public RequestSource(IHttpRequestResponse req, String reqName, String folderName) {
        super();
        this.req = req;
        this.reqName = reqName;
        this.folderName = folderName;
    }

    public IHttpRequestResponse getReq() {
        return req;
    }
    public void setReq(IHttpRequestResponse req) {
        this.req = req;
    }
    public String getReqName() {
        return reqName;
    }
    public void setReqName(String reqName) {
        this.reqName = reqName;
    }
    public String getFolderName() {
        return folderName;
    }
    public void setFolderName(String folderName) {
        this.folderName = folderName;
    }

    // Yeni eklenen getResponse metodu
    public byte[] getResponse() {
        if (req != null) {
            return req.getResponse();
        }
        return null; // Response yoksa null döner
    }

    // HTTP metodunu döndüren getMethod metodu
    public String getMethod() {
        if (req != null && req.getRequest() != null) {
            // HTTP request metodunu analiz et
            return req.getRequest().toString().split(" ")[0];
        }
        return null; // Eğer req null ise veya metod alınamazsa null döner
    }
}
