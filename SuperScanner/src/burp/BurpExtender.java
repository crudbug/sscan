package burp;

import java.util.ArrayList;
import java.util.List;
import log.Logger;
import issues.DebugEnabled;
import issues.VerboseError;
import issues.RefererBasedOpenRedirect;
import java.io.UnsupportedEncodingException;

public class BurpExtender implements IBurpExtender, IScannerCheck {

    // burp API callback object
    private static IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helper;

    // log facility
    private static Logger log;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        BurpExtender.callbacks = callbacks;
        this.helper = BurpExtender.callbacks.getHelpers();
        this.log = new Logger(BurpExtender.callbacks);

        BurpExtender.callbacks.setExtensionName("Scanner");

        BurpExtender.callbacks.registerScannerCheck(this);
    }

    public static IBurpExtenderCallbacks getBurpCallbacks() {
        return callbacks;
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        List<IScanIssue> issues = new ArrayList<>(1);
        VerboseError issue1 = detectVerboseErrors(baseRequestResponse);
        if (issue1 != null) {
            log.log("adding issue " + issue1.getIssueName());
            issues.add(issue1);
        }

        DebugEnabled issue2 = detectDebugEnabled(baseRequestResponse);
        if (issue2 != null) {
            log.log("adding issue " + issue2.getIssueName());
            issues.add(issue2);
        }

        return issues;
    }

    private VerboseError detectVerboseErrors(IHttpRequestResponse message) {
        List<int[]> matches = VerboseError.detect(message);

        if (matches.size() > 0) {
            try {
                VerboseError issue = new VerboseError(message, matches);
                return issue;
            } catch (Exception ex) {
                log.err("Could not create vulnerability", ex);
                log.err(helper.bytesToString(message.getResponse()));
                return null;
            }
        } else {
            return null;
        }
    }

    private DebugEnabled detectDebugEnabled(IHttpRequestResponse message) {
        List<int[]> matches = DebugEnabled.detect(message);

        if (matches.size() > 0) {
            try {
                DebugEnabled issue = new DebugEnabled(message, matches);
                log.log("create object for " + issue.getIssueName() + " type: " + issue.getIssueType());
                return issue;
            } catch (Exception ex) {
                log.err("Could not create vulnerability", ex);
                log.err(helper.bytesToString(message.getResponse()));
                return null;
            }
        } else {
            return null;
        }
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        try {
            List<IScanIssue> issues = new ArrayList<>(1);
           
            RefererBasedOpenRedirect issue = RefererBasedOpenRedirect.detect(baseRequestResponse, insertionPoint);
            if (issue != null) {
                issues.add(issue);
            }
            
            return issues;
        } catch (UnsupportedEncodingException ex) {
            log.err("Failed to search for custom issues", ex);
            return null;
        }
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        if (newIssue.getIssueName().equals(RefererBasedOpenRedirect.name())) {
            if (existingIssue.getUrl().equals(newIssue.getUrl()) && 
                    existingIssue.getIssueDetail().equals(newIssue.getIssueDetail())) {
                return -1;
            }
            else { 
                return 0;
            }
        }
        else {
            return 0;
        }
    }


}
