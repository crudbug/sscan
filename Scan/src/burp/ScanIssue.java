package burp;

import java.net.URL;


public class ScanIssue implements IScanIssue {
    private final URL url;
    private final String name;
    private final int issueType;
    private final String severity;
    private final String confidence;
    private final String issueBackground;
    private final String remediationBackground;
    private final String issueDetail;
    private final String remediationDetail;
    private final IHttpRequestResponse[] httpMessages;
    private final IHttpService httpService;

    public ScanIssue(IScanIssue issue, String details) {
        url = issue.getUrl();
        name = issue.getIssueName();
        issueType = issue.getIssueType();
        severity = issue.getSeverity();
        confidence = issue.getConfidence();
        issueBackground = issue.getIssueBackground();
        remediationBackground = issue.getRemediationBackground();
        issueDetail = details;
        remediationDetail = issue.getRemediationDetail();
        httpMessages = issue.getHttpMessages();
        httpService = issue.getHttpService();
    }
    
    public ScanIssue(IScanIssue issue, IHttpRequestResponse[] httpMessages, String details) {
        url = issue.getUrl();
        name = issue.getIssueName();
        issueType = issue.getIssueType();
        severity = issue.getSeverity();
        confidence = issue.getConfidence();
        issueBackground = issue.getIssueBackground();
        remediationBackground = issue.getRemediationBackground();
        issueDetail = details;
        remediationDetail = issue.getRemediationDetail();
        this.httpMessages = httpMessages;
        httpService = issue.getHttpService();
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
        return issueType;
    }

    @Override
    public String getSeverity() {
        return severity;
    }

    @Override
    public String getConfidence() {
        return confidence;
    }

    @Override
    public String getIssueBackground() {
        return issueBackground;
    }

    @Override
    public String getRemediationBackground() {
        return remediationBackground;
    }

    @Override
    public String getIssueDetail() {
        return issueDetail;
    }

    @Override
    public String getRemediationDetail() {
        return remediationDetail;
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
