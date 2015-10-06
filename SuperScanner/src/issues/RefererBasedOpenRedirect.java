package issues;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IScanIssue;
import burp.IScannerInsertionPoint;
import helper.HttpMessage;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import log.Logger;

public class RefererBasedOpenRedirect implements IScanIssue {

    private IBurpExtenderCallbacks callbacks;
    private final IHttpService httpService;
    private URL url;
    private IHttpRequestResponse[] httpMessages;
    private String name;
    private String detail;

    private static final String STR_PAYLOAD = "example.com";
    private static final byte[] PAYLOAD = STR_PAYLOAD.getBytes();

    public RefererBasedOpenRedirect(IHttpRequestResponse message, List<int[]> requestMarkers, List<int[]> responseMarkers,
            byte insertionPointType, String insertionPointName) {
        callbacks = BurpExtender.getBurpCallbacks();

        this.name = RefererBasedOpenRedirect.name();
        this.httpService = message.getHttpService();
        this.url = callbacks.getHelpers().analyzeRequest(message).getUrl();

        this.httpMessages = new IHttpRequestResponse[]{callbacks.applyMarkers(message, requestMarkers, responseMarkers)};
        
        switch(insertionPointType) {
            case IScannerInsertionPoint.INS_PARAM_NAME_URL:
                detail = "The name of an arbitrarily supplied URL parameter may be used to perform an HTTP redirect. ";
                detail += "The payload <b>" + STR_PAYLOAD + "</b> was submitted in the name of an arbitrarily supplied URL parameter and it was found in the response. ";
                break;
            default:
                detail = "The value of <b>" + insertionPointName + "</b> may be used to perform an HTTP redirect. ";
                detail += "The payload <b>" + STR_PAYLOAD + "</b> was submitted in the " + insertionPointName + " and it was found in the response. ";
        }
        
        detail += "This may trick the user into visiting following URL: <b>" + STR_PAYLOAD + "</b><br><br>";
    }

    public static String name() {
        return "Open redirection";
    }

    public static RefererBasedOpenRedirect detect(IHttpRequestResponse message, IScannerInsertionPoint insertionPoint) throws UnsupportedEncodingException {
        List<byte[]> payloads = Arrays.asList(PAYLOAD, (message.getHttpService().getHost() + "." + STR_PAYLOAD).getBytes());
        IExtensionHelpers helper = BurpExtender.getBurpCallbacks().getHelpers();
        
        for (byte[] payload : payloads) {
            byte[] checkRequest = insertionPoint.buildRequest(payload);
            IHttpRequestResponse requestResponse = BurpExtender.getBurpCallbacks().makeHttpRequest(message.getHttpService(), checkRequest);
            
            if (helper.analyzeResponse(requestResponse.getResponse()).getStatusCode() != HttpURLConnection.HTTP_MOVED_TEMP
                    && helper.analyzeResponse(requestResponse.getResponse()).getStatusCode() != HttpURLConnection.HTTP_MOVED_PERM) {

                String payloadStr = helper.bytesToString(payload);
                List<int[]> responseMarkers = new ArrayList<>();
                try {
                    responseMarkers = HttpMessage.getMatches(helper.bytesToString(requestResponse.getResponse()), "<a.+?href=[\"']?((\\w+:)?\\/\\/)?[^\\/]*?" + payloadStr + ".*?>");
                } catch (Exception e) {
                    Logger log = new Logger();
                    log.err("Exception at detect()", e);
                    log.err("inputs: " + helper.bytesToString(requestResponse.getResponse()));
                    log.err("inputs: " + "<a.+?href=[\"']?((\\w+:)?\\/\\/)?[^\\/]*?" + payloadStr + ".*?>");
                }

                if (responseMarkers.size() > 0) {
                    List<int[]> requestMarkers = new ArrayList<>(1);
                    requestMarkers.add(insertionPoint.getPayloadOffsets(payload));

                    return new RefererBasedOpenRedirect(requestResponse, requestMarkers, responseMarkers,
                            insertionPoint.getInsertionPointType(),
                            insertionPoint.getInsertionPointName());
                }
            }
        }
            
        return null;
    }

    @Override
    public URL getUrl() {
        return url;
    }

    @Override
    public String getIssueName() {
        return name;
    }

    @Override
    public int getIssueType() {
        return 4;
    }

    @Override
    public String getSeverity() {
        return "High";
    }

    @Override
    public String getConfidence() {
        return "Certain";
    }

    @Override
    public String getIssueBackground() {
        return null;
    }

    @Override
    public String getRemediationBackground() {
        return null;
    }

    @Override
    public String getIssueDetail() {
        return detail;
    }

    @Override
    public String getRemediationDetail() {
        return null;
    }

    @Override
    public IHttpRequestResponse[] getHttpMessages() {
        return httpMessages;
    }

    @Override
    public IHttpService getHttpService() {
        return httpService;
    }
}
