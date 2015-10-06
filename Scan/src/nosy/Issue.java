package nosy;

import burp.BurpExtender;

public class Issue {
    
    public final int id;
    public final String request;
    public final String response;
    
    public Issue(int id, String request, String response) {
        this.id = id;
        this.request = request;
        this.response = response;
        
    }
    
    public byte[] requestBytes() {
        return BurpExtender.getBurpCallbacks().getHelpers().stringToBytes(request);
    }
    
    public String request() {
        return request;
    }
    
    public byte[] responseBytes() {
        return BurpExtender.getBurpCallbacks().getHelpers().stringToBytes(response);
    }
}
