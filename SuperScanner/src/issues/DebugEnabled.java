/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package issues;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IScanIssue;
import helper.HttpMessage;
import java.net.URL;
import java.util.List;
import log.Logger;

/**
 *
 * @author tmendo
 */
public class DebugEnabled implements IScanIssue {

    // php debug
    // example: array(6) {
    private static final String PHP_DEBUG = "array";


    private final IHttpService httpService;
    private URL url;
    private IHttpRequestResponse[] httpMessages;
    private String name;
    private String detail;

    public DebugEnabled(IHttpRequestResponse message, List<int[]> matches) {
        IBurpExtenderCallbacks callbacks = BurpExtender.getBurpCallbacks();

        this.name = "Debug enabled";
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
        
        try {
            return HttpMessage.getMatches(helper.bytesToString(message.getResponse()), PHP_DEBUG);
        }
        catch (Exception e) {
            Logger log = new Logger();
            log.err("Exception at detect()", e);
            log.err("inputs: " + helper.bytesToString(message.getResponse()));
            log.err("inputs: " + PHP_DEBUG);
            return null;
        }        
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
        return 89; 
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
