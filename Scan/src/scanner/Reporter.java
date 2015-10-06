package scanner;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.ICookie;
import burp.IHttpRequestResponse;
import burp.IHttpRequestResponseWithMarkers;
import burp.IHttpService;
import burp.IRequestInfo;
import burp.IResponseInfo;
import burp.IScanIssue;
import burp.ScanIssue;
import helper.HttpMessage;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import log.Logger;
import nosy.Issue;
import nosy.Nosy;
import nosy.Severity;
import nosy.Vulnerability;


public class Reporter {

    private final IBurpExtenderCallbacks iburp;

    // this structure enables deleting while iterating
    List<IScanIssue> issueList = new LinkedList<>();

    // Nosy representation
    private Nosy nosy;
    
    // log facility
    private final Logger log;
    
    private int originalIssues = 0;
    private int reportedIssues = 0;
    private int errorCount = 0;

    // useful for stat reporting
    private final List<URL> targets;
    
    public Reporter(List<URL> targets) {
        this.targets = targets;
        this.iburp = BurpExtender.getBurpCallbacks();
        this.log= Logger.getInstance();
        for(URL t : targets) {
            issueList.addAll(Arrays.asList(iburp.getScanIssues(t.toString())));
        }
        originalIssues = issueList.size();
    }

    public void analyze() {
        log.log("Original vulnerabilities");
        stats();
        
        cleanIssues();
        reportedIssues = issueList.size();
    }

    public boolean sendStats(Date startTime, Date endTime, long reqCnt, int reason) throws MalformedURLException, IOException {
        return nosy.sendStats(targets.get(0).getHost(), startTime, endTime,
                            reqCnt, totalCount(), reportedCount(), errorCount(),
                            reason);
    }
    
    
    public void sendIssues() {
        nosy = new Nosy(issueList);
        errorCount = nosy.sendIssues();
    }

    private void stats() {
        HashMap<String, Integer> stats = new HashMap<>();

        for (IScanIssue scanIssue : issueList) {
            String key = scanIssue.getIssueName();

            if (stats.containsKey(key)) {
                stats.put(key, stats.get(key) + 1);
            } else {
                stats.put(key, 1);
            }
        }

        for (String vulnName : stats.keySet()) {
            log.log("\t" + stats.get(vulnName) + " " + vulnName);
        }
    }


    private void cleanIssues() {
        removeFalsePositives();
        log.log("After removing FPs (from manual selection)");
        stats();
        removeIrrelevant();
        log.log("After removing irrelevant");
        stats();
        removeDuplicates();
        log.log("After removing duplicates");
        stats();
        merge();
        log.log("After merging");
        stats();
        validateXSS();
        log.log("After XSS cleaning");
        stats();
        validateSessionTokenInURL();
        log.log("After Session Token cleaning");
        stats();
        validateCrossdomainXml();
        log.log("After crossdomain.xml cleaning");
        stats();
        validateCookies();
        log.log("After cookie cleaning");
        stats();
        validateSQLi();
        log.log("After SQLi validation");
        stats();
        validateSourceCodeDisclosure();
        log.log("After Source Code Disclosure validation");
        stats();
        validatePasswordSentUsingGET();
        log.log("After validating User Voice GET passwords");
        stats();
        validateDirectoryListing();
        log.log("After validating directory listing");
        stats();
    }

    

    private void removeFalsePositives() {
        for (Iterator<IScanIssue> it = issueList.iterator(); it.hasNext(); ) {
            if (it.next().getSeverity().equals(Severity.FP)) {
                it.remove();
            }
        }        
        
    }
    

    private void removeIrrelevant() {

        for (Iterator<IScanIssue> it = issueList.iterator(); it.hasNext(); ) {
            if ( ! Vulnerability.isRelevant(it.next().getIssueType())) {
                it.remove();
            }
        }        
    }


    private void merge() {
      
    }


    private void mergeByID(int vulnerability, boolean extendedMarkers) {
        List<IScanIssue> toMergeIssues = new LinkedList<>();

        // gather them
        for (IScanIssue issue : issueList) {
             if (issue.getIssueType() == vulnerability) {
                 toMergeIssues.add(issue);
             }
        }

        merge(toMergeIssues, extendedMarkers);
    }


   
    private void merge(List<IScanIssue> toMergeIssues, boolean extendedMarkers) {
        List<IScanIssue> toDelete = new LinkedList<>();

        // merge only if there is more than one
        if (toMergeIssues.size() > 1 ) {
            String details = toMergeIssues.size() + " instances of this issue were identified, at the following locations:<br><br><ul>";
            
            for (IScanIssue issue : toMergeIssues) {
                toDelete.add(issue);
                String path = iburp.getHelpers().analyzeRequest(issue.getHttpMessages()[0]).getUrl().getPath();
                IHttpRequestResponse message = issue.getHttpMessages()[0];
                
                details += "<li>" + path;
                
                if (message instanceof IHttpRequestResponseWithMarkers) {
                    List<String> markers;
                    if (extendedMarkers) {
                        markers = HttpMessage.getExtendedResponseMarkers((IHttpRequestResponseWithMarkers) message);
                    }
                    else {
                        markers = HttpMessage.getResponseMarkers((IHttpRequestResponseWithMarkers) message);
                    }
                    
                    if (markers.size() > 0) {
                        details += "<ul>";
                        for(String marker : markers) {
                            details += "<li>" + marker + "</li>";
                        }
                        details += "</ul>";
                    }                    
                }                
                details += "</li>";
            }
            details += "</ul>";
            
            // creation must be the last step
            IScanIssue merger = new ScanIssue(toMergeIssues.get(0), details);
            iburp.addScanIssue(merger);
            issueList.add(merger);
        }

        issueList.removeAll(toDelete);
    }

    private void validateSessionTokenInURL() {
        List<IScanIssue> toDelete = new LinkedList<>();
        for (IScanIssue issue : issueList) {
            if (issue.getIssueType() == Vulnerability.SESSION_URL) {
                IHttpRequestResponse message = issue.getHttpMessages()[0];

                if (message instanceof IHttpRequestResponseWithMarkers) {
                    boolean found = false;
                    for(String marker : HttpMessage.getResponseMarkers((IHttpRequestResponseWithMarkers) message)) {
                        if (marker.matches("session")) {
                            found = true;
                            break;
                        }
                    }

                    if (!found) {
                        toDelete.add(issue);
                    }
                }
            }
        }
        issueList.removeAll(toDelete);
    }


    private void validatePasswordSentUsingGET() {
        List<IScanIssue> toDelete = new LinkedList<>();
        
        for (IScanIssue issue : issueList) {
            if (issue.getIssueType() == Vulnerability.GET_PASSWORD && issue.getHttpMessages()[0] instanceof IHttpRequestResponseWithMarkers) {
                IHttpRequestResponse message = issue.getHttpMessages()[0];
                List<String> markers = HttpMessage.getResponseMarkers((IHttpRequestResponseWithMarkers) message);
             
                for (String marker: markers) {
                    if (marker.startsWith("<input class=\"uvFieldPassword\" type=\"password\" name=\"password\"")) {
                        log.trace("UserVoice GET password FP found");
                        toDelete.add(issue);
                        continue;
                    }
                }
                
            }
        }
        
        issueList.removeAll(toDelete);
    }

    
    private void validateXSS() {
        List<IScanIssue> toDelete = new LinkedList<>();
        
        for (IScanIssue issue : issueList) {
            
        }
        issueList.removeAll(toDelete);
        

    }
    
  
    private void merge404XSS() {
        // gather 404
        List<IScanIssue> toMergeIssues = new LinkedList<>();
        List<IScanIssue> toDelete = new LinkedList<>();

        // gather them
        for (IScanIssue issue : issueList) {
            if (issue.getIssueType() == Vulnerability.XSS_REFLECTED) {
                if (iburp.getHelpers().analyzeResponse(issue.getHttpMessages()[0].getResponse()).getStatusCode() == HttpURLConnection.HTTP_NOT_FOUND) {
                    toMergeIssues.add(issue);
                }
            }
        }        
                
        ArrayList<String> parameters = new ArrayList<>();
        for (IScanIssue issue : toMergeIssues) {
            String parameter = helper.ScanIssue.getParameter(issue);
            if (parameter.startsWith("REST URL") && parameters.contains(parameter)) {
                toDelete.add(issue);
                log.trace("FP XSS 404 REST URL");
            }
            else {
                parameters.add(parameter);
            }
        }
        
        issueList.removeAll(toDelete);
    }
         
    
    private void validateSourceCodeDisclosure() {
        List<IScanIssue> toDelete = new LinkedList<>();
        
        for (IScanIssue issue : issueList) {
            // 1- ignores ASP source code disclosure if just a single word,
            // for instance, <%=Title%>
            if (issue.getIssueType() == Vulnerability.CODE_DISCLOSURE &&
                    issue.getConfidence().equals("Tentative")) {
                IHttpRequestResponse message = issue.getHttpMessages()[0];
                
                if (message instanceof IHttpRequestResponseWithMarkers) {
                    List<String> markers = HttpMessage.getResponseMarkers((IHttpRequestResponseWithMarkers) message);
                    int matched = 0;
                    for (String marker: markers) {
                        if (word.matcher(marker).matches()) {
                            matched++;
                        }
                    }
                    if (matched == markers.size()) {
                        log.trace("FP");
                        toDelete.add(issue);
                    }                    
                }                
            }
        }
        
        issueList.removeAll(toDelete);
    }
    
    

    private void validateSQLi() {
        List<IScanIssue> toDelete = new LinkedList<>();
        Pattern oracleFPPattern = Pattern.compile("(\\d+)", Pattern.CASE_INSENSITIVE);

        for (IScanIssue issue : issueList) {
            if (issue.getIssueType() == Vulnerability.SQL_INJECTION) {
                IHttpRequestResponse[] messages = issue.getHttpMessages();
                IHttpRequestResponse message = messages[0];

                if (message instanceof IHttpRequestResponseWithMarkers) {
                    List<String> markers = HttpMessage.getResponseMarkers((IHttpRequestResponseWithMarkers) message);

                    int oracleFPCount = 0;
                    for (String marker: markers) {
                        if (oracleFPPattern.matcher(marker).find()) {
                            oracleFPCount++;
                        }
                    }

                    if (oracleFPCount == markers.size()) {
                        log.trace("FP SQLi (oracle error)");
                        toDelete.add(issue);
                        continue;
                    }
                }

                if (messages.length == 2) {
                    if (issue.getConfidence().equals("Tentative") &&
                            (iburp.getHelpers().analyzeResponse(messages[1].getResponse()).getStatusCode() == HttpURLConnection.HTTP_UNAVAILABLE ||
                            iburp.getHelpers().analyzeResponse(messages[0].getResponse()).getStatusCode() == HttpURLConnection.HTTP_UNAVAILABLE)) {
                        log.trace("FP SQLi: one of the responses was 503");
                        toDelete.add(issue);
                        continue;
                    }
                }

                IRequestInfo info = iburp.getHelpers().analyzeRequest(message);
                String file = "";
                try {
                    file = info.getUrl().getFile();
                }
                catch (java.lang.UnsupportedOperationException e) {
                    log.err("Failed to get URL", e);
                    log.err("Request " + iburp.getHelpers().bytesToString(message.getRequest()));
                }                
                if (file.equals("MAINTAINERS.txt") || file.equals("CHANGELOG.txt") || file.equals("INSTALL.pqsql.txt") || file.equals("INSTALL.txt")) {
                    log.trace("FP SQLi: default instalation files " + file);
                    toDelete.add(issue);
                    continue;
                }
                
              
                 if (message instanceof IHttpRequestResponseWithMarkers) {
                    List<String> markers = HttpMessage.getResponseMarkerLine((IHttpRequestResponseWithMarkers) message, iburp);
                    for (String marker: markers) {
                        if (marker.contains(postgresqlStr)) {
                            toDelete.add(issue);
                            break;
                        }
                    }
                 }
                
            }
        }
        issueList.removeAll(toDelete);
    }
  
  

    public int totalCount() {
        return originalIssues;
    }

    public int reportedCount() {
        return reportedIssues;
    }

    public int errorCount() {
        return errorCount;
    }

    



    private void validateDirectoryListing() {
        List<IScanIssue> toDelete = new LinkedList<>();
        
    }
    

    private void validateCrossdomainXml() {
        List<IScanIssue> toDelete = new LinkedList<>();
        Pattern pattern = Pattern.compile("\\*\"\\/>");

        boolean safeDomains = true;
        
        for (IScanIssue issue : issueList) {
            if (issue.getIssueType() == Vulnerability.X_DOMAIN_FLASH) {
                IHttpRequestResponse message = issue.getHttpMessages()[0];

                if (message instanceof IHttpRequestResponseWithMarkers) {
                    List<String> markers = HttpMessage.getResponseMarkers((IHttpRequestResponseWithMarkers) message);

                    for (String marker : markers) {
                        Matcher matcher = pattern.matcher(marker);
                        if (matcher.find()) {
                            safeDomains = false;
                            break;
                        }
                    }

                    if (safeDomains) {
                        toDelete.add(issue);
                    }
                }
            }
        }
        issueList.removeAll(toDelete);
    }
    

    private void validateCookies() {
        List<IScanIssue> toDelete = new LinkedList<>();
        
        for (IScanIssue issue : issueList) {
            if (issue.getIssueType() == Vulnerability.HTTPONLY || issue.getIssueType() == Vulnerability.SECURE) {
                List<ICookie> cookies = helper.ScanIssue.getVulnerableCookies(issue, iburp);
                log.trace("Got " + cookies.size() + " cookies");
                boolean relevantCookie = false;
                               
                for (ICookie cookie : cookies) {
                   
                    if (cookie.getValue().toLowerCase().startsWith("delete")) {
                        log.trace("Cookie " + cookie.getName() + " has value " + cookie.getValue());
                        continue; 
                    }
                }

                if (!relevantCookie) {
                    toDelete.add(issue);
                }
            }
        }
        issueList.removeAll(toDelete);
    }
}

// TODO SSL 