package nosy;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IHttpRequestResponseWithMarkers;
import burp.IRequestInfo;
import burp.IScanIssue;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import helper.HttpMessage;
import helper.ScanIssue;
import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.nio.charset.Charset;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import javax.net.ssl.HttpsURLConnection;
import log.Logger;


public class Nosy {

    private static final String NOSY_URL = "https://localhost";
    private static final String URL_BASE = NOSY_URL + "/api/";
    private static final String SCAN_WS = NOSY_URL + "/scan/";
    private static final String AUTH_TOKEN = "XXX";
    private final Logger log;
    
    public static final int EXIT_SUCCESS = 10;
    public static final int EXIT_TIME_LIMIT = 20;
    public static final int EXIT_QUEUE = 40;
    public static final int EXIT_UNKNOWN = 50;
    public static final int EXIT_BLOCKED = 60;
    public static final HashMap<Integer, String> SCAN_STATUS;
    static {
        SCAN_STATUS = new HashMap<>();
        SCAN_STATUS.put(EXIT_SUCCESS, "Successful");
        SCAN_STATUS.put(EXIT_QUEUE, "Scan queue too big");
        SCAN_STATUS.put(EXIT_UNKNOWN, "Unknown exception");
    }
    
    // respect Nosy API date format
    private final SimpleDateFormat formatter = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm");

    private List<IScanIssue> issueList = null;
    private final IBurpExtenderCallbacks iburp;
    
    // indicates an error reading info from Nosy
    private boolean readError = false;

    public Nosy() {
        this.log = Logger.getInstance();
        this.iburp = BurpExtender.getBurpCallbacks();
    }

    public Nosy(List<IScanIssue> issueList) {
        this.issueList = issueList;
        this.log = Logger.getInstance();
        this.iburp = BurpExtender.getBurpCallbacks();
    }
   

    private String preparePostData(IScanIssue issue) throws UnsupportedEncodingException {

        IHttpRequestResponse[] requests = issue.getHttpMessages();
        // TODO multiple requests? Maybe I should choose the last one
        if (requests.length > 1) {
            log.warn("Got multiple requests while preparing this issue " + issue.toString());
        }

        IRequestInfo requestInfo = iburp.getHelpers().analyzeRequest(requests[0]);

        JsonObject jsonObject = new JsonObject();
        jsonObject.addProperty("method", requestInfo.getMethod());
        jsonObject.addProperty("host", issue.getUrl().getHost());
        jsonObject.addProperty("url", issue.getUrl().toString());
        jsonObject.addProperty("severity", Severity.fromBurp(issue.getSeverity()));
        jsonObject.addProperty("confidence", issue.getConfidence());
        jsonObject.addProperty("vulnerability", issue.getIssueType());
        jsonObject.addProperty("full_payload", new String(requests[0].getRequest(), "UTF-8"));
        jsonObject.addProperty("response", new String(requests[0].getResponse(), "UTF-8"));
        jsonObject.addProperty("parameter", ScanIssue.getParameter(issue));

        // join markers with details
        String details = issue.getIssueDetail();
        if (issue.getIssueType() == Vulnerability.CODE_DISCLOSURE) {
                if (requests[0] instanceof IHttpRequestResponseWithMarkers) {
                    details += "<br><ul>";
                    for(String marker : HttpMessage.getResponseMarkers((IHttpRequestResponseWithMarkers) requests[0])) {
                        details += "<li>"+marker+"</li>";
                    }
                    details += "</ul>";
                }
        }
        jsonObject.addProperty("information", details);

        return new Gson().toJson(jsonObject);
    }


    public int sendIssues() {
            int errorCount = 0;

           for (IScanIssue scanIssue : issueList) {
               try {
                   if (sendIssue(scanIssue)) {
                       errorCount++;
                   }
               }
               catch (java.security.InvalidAlgorithmParameterException ex) {
                   log.err("Failed to verify certificate. Likely because keystore does not exist." ,ex);
                   errorCount++;
               }
               catch (Exception ex) {
                   log.err("Could not send issue " + scanIssue.getIssueName(), ex);
                   errorCount++;
               }
           }

           return errorCount;
    }

    
    private String sendReadRequest(URL url) throws IOException {
        String response = "";
        
        HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
        conn.setConnectTimeout(2000);
        conn.setDoOutput(true);
        conn.setRequestProperty("Accept", "application/json");
        conn.setRequestMethod("GET");
                
        readError = false;
        InputStream connIn = null;
        int code = conn.getResponseCode();
        if (code != HttpsURLConnection.HTTP_OK) {
            log.err("Got HTTP " + conn.getResponseCode() + " from " + url.toString());
            connIn = conn.getErrorStream();
            readError = true;
        }
        else {
            connIn = conn.getInputStream();
        }
            
        try (BufferedReader buffer = new BufferedReader(new InputStreamReader(connIn))) {
            String tmp;
            while ((tmp = buffer.readLine()) != null) {
                response += tmp;
            }
        }

        if (readError) {
            log.trace("Tried to read: " + url.toString());
            log.warn("nosy response " + response);
        }

        return response;
    }
    
    
    private boolean sendIssue(IScanIssue issue) throws Exception {
        return sendRequest(new URL(URL_BASE), "POST", preparePostData(issue));
    }

    private boolean sendRequest(URL url, String method, String data) throws IOException {
        HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
        conn.setConnectTimeout(2000);
        conn.setDoOutput(true);
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setRequestProperty("Accept", "application/json");
        conn.setRequestProperty("Authorization", "Token " + AUTH_TOKEN);
        conn.setRequestMethod(method);
        if (method.equals("POST")) {
            conn.setDoInput(true);
            try (DataOutputStream wr = new DataOutputStream(conn.getOutputStream())) {
                byte[] dataBytes = data.getBytes(Charset.forName("UTF-8"));
                wr.write(dataBytes, 0, dataBytes.length);
                wr.flush();
            }
        }        

         // execute HTTPS request
        boolean error = false;
        InputStream connIn = null;
        int code = conn.getResponseCode();
        if (code != HttpsURLConnection.HTTP_CREATED && code != HttpsURLConnection.HTTP_OK) {
            log.err("Got HTTP " + conn.getResponseCode() + " from " + url.toString());
            connIn = conn.getErrorStream();
            error = true;
        }

        if (error) {
            String response = "";
            try (BufferedReader buffer = new BufferedReader(new InputStreamReader(connIn))) {
                String tmp;
                while ((tmp = buffer.readLine()) != null) {
                    response += tmp;
                }
            }
            
            if (error) {
                log.trace("Tried to send: " + data);
                log.warn("nosy response " + response);
            }
        }

        return error;
    }
    
    
    
    public boolean sendStats(String host, Date startTime, Date endTime, long reqCnt, int issueCnt, int reportedCnt, int errorCnt, int reason) throws IOException {
        JsonObject jsonObject = new JsonObject();
        jsonObject.addProperty("host", host);
        jsonObject.addProperty("start", formatter.format(startTime));
        jsonObject.addProperty("end", formatter.format(endTime));
        jsonObject.addProperty("request_count", reqCnt);
        jsonObject.addProperty("total_issue_count", issueCnt);
        jsonObject.addProperty("reported_issue_count", reportedCnt);
        jsonObject.addProperty("errored_issue_count", errorCnt);
        jsonObject.addProperty("status", Integer.toString(reason));
        jsonObject.addProperty("status_msg", SCAN_STATUS.get(reason));
        
        String request = new Gson().toJson(jsonObject);

        return sendRequest(new URL(SCAN_WS), "POST", request);
    }
}