package issues;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IScanIssue;
import helper.HttpMessage;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;


public class VerboseError implements IScanIssue {
        

    private static final String STACKTRACE = "(?:\\w|\\.|\\/)+?\\.(?:php|pl)(?::\\d+|(?:\\(\\d+\\)))";
    
    private static final String AT_POSITION= "at\\sposition\\s[0-9]+";
            
    private static final List<byte[]> needles = Arrays.asList("Undefined index: ".getBytes(),
                                                                "ERROR DB: Duplicate entry".getBytes(),
                                                                "Unable to insert a record into".getBytes(),
                                                                "<b>Fatal error</b>:".getBytes(),
                                                                "<b>Source Error:</b>".getBytes(),
                                                                "<b>Stack Trace:</b>".getBytes());


    private final IHttpService httpService;
    private final URL url;
    private final IHttpRequestResponse[] httpMessages;
    private final String name;
    private String detail;

    public VerboseError(IHttpRequestResponse message, List<int[]> matches) {
        IBurpExtenderCallbacks callbacks = BurpExtender.getBurpCallbacks();

        this.name = "Verbose errors enabled";
        this.httpService = message.getHttpService();
        this.url = callbacks.getHelpers().analyzeRequest(message).getUrl();
       
        HttpMessage.orderMarkers(matches);
        this.httpMessages = new IHttpRequestResponse[]{callbacks.applyMarkers(message, null, matches)};

        detail = "The response contains the following patterns:<br><ul>";
        for(String marker : HttpMessage.parseMarkers(message.getResponse(), matches)) {
            detail += "<li>" + marker + "</li>";
        }
        detail += "</ul>";
    }

    public static List<int[]> detect(IHttpRequestResponse message) {
        IExtensionHelpers helper = BurpExtender.getBurpCallbacks().getHelpers();
        List<int[]> matches = new ArrayList<>();
        for(byte[] needle : needles) {
            matches.addAll(HttpMessage.getMatches(message.getResponse(), needle, helper));
        }
        
        matches.addAll(HttpMessage.getMatches(helper.bytesToString(message.getResponse()), STACKTRACE));
        matches.addAll(HttpMessage.getMatches(helper.bytesToString(message.getResponse()), AT_POSITION));
        
        return matches;
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
        return 87; // from OwnDB
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
