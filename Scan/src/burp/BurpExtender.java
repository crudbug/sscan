package burp;

import scanner.Configuration;
import log.Logger;
import log.MessageLogger;
import scanner.PerformanceMonitor;
import scanner.Reporter;
import scanner.ScanMonitor;
import scanner.SpiderMonitor;
import scanner.ThreadExceptionHandler;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.ListIterator;
import java.util.logging.Level;
import net.sourceforge.argparse4j.ArgumentParsers;
import net.sourceforge.argparse4j.inf.ArgumentParser;
import net.sourceforge.argparse4j.inf.ArgumentParserException;
import net.sourceforge.argparse4j.inf.Namespace;
import nosy.Nosy;


public class BurpExtender implements IBurpExtender, IExtensionStateListener, IHttpListener {

    private static BurpExtender thisObject;
      
    // burp API callback objects
    private static IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helper;

    // logger facilities
    private static Logger log = null;
    private MessageLogger spiderLog;
    private MessageLogger scannerLog;

    // indicates Skynet exit procedure was executed or not
    private boolean exited = false;

    // scanner queue. Needs to be thread safe because of scan monitor
    public List<IScanQueueItem> scanQueue = Collections.synchronizedList(new ArrayList<IScanQueueItem>());

    // Monitors
    private PerformanceMonitor perfMon;
    public SpiderMonitor spiderMonitor;
    private ScanMonitor scanMonitor;

    // burp configuration
    private Configuration conf;

    // Path to the state file with the base config passed as cmd argument
    public String baseConfigPath;

    // File object of the state file read from baseConfigPath
    public File baseConfigFile;

    // Do not send requests to the target, either spider or scanner
    public boolean dontscan = false;
    
    // Basic auth credentials
    public String basicAuthUser = null;
    public String basicAuthPass = null;

    // defines what Spider & Scanner can request
    private RequestValidator requestRules = null;


    // statistic stuff
    private long requests = 0;
    private Date startTime;
    Reporter report;
        
    public String targetFQDN;

    public ArrayList<URL> targets = new ArrayList<>();
    
   
    public String target;
    // working directory
    public String workingDir;
    // sleep to allow configuration
    public boolean sleep;
    // nosy host id used to query Nosy DB to prevent duplicates
    public int hostId;

    
    public static BurpExtender getInstance() {
        return thisObject;
    }
    

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        BurpExtender.callbacks = callbacks;
        thisObject = this;

        this.helper = BurpExtender.callbacks.getHelpers();
        BurpExtender.callbacks.registerExtensionStateListener(this);
        BurpExtender.callbacks.registerHttpListener(this);

        parseArguments();

        // sleep to allow the initial manual state saving
        if (sleep) {
            try {
                Thread.sleep(2 * 60 * 1000);
            } catch (InterruptedException ex) {
                java.util.logging.Logger.getLogger(BurpExtender.class.getName()).log(Level.SEVERE, null, ex);
            }
        }

        // start log
        try {
            log = new Logger(BurpExtender.callbacks);
            log.enableIndependentLogging(workingDir, "skynet", false);
            log.enableTrace();
            spiderLog = new MessageLogger(workingDir + "/spider.log", "spider");
            scannerLog = new MessageLogger(workingDir + "/scanner.log", "scanner");
        } catch (FileNotFoundException ex) {
            handleTerminalException(ex);
        }
    
        startSkynet();
    }

  
    private void parseArguments() {
        String[] args = callbacks.getCommandLineArguments();
        
        ArgumentParser parser = ArgumentParsers.newArgumentParser("Skynet");
        parser.addArgument("-t", "--target").required(true)
                .dest("target")
                .help("Specify an URL, IP or FQDN to spider and scan");
        parser.addArgument("-w", "--working-dir").required(true)
                .dest("workingDir")
                .help("Specify the directory for the temporary files");
        parser.addArgument("-c", "--conf").required(true)
                .dest("conf")
                .help("Path to the state file with the base configuration");
        parser.addArgument("-H", "--hostid").required(false)
                .type(Integer.class)
                .dest("hostId")
                .help("Nosy host id: used to prevent repeated issues");
        parser.addArgument("-d").required(false)
                .type(Boolean.class)
                .setDefault(false)
                .dest("dontscan")
                .help("Do not send any request to the target. Useful to debug a stored state");
        parser.addArgument("-b").required(false)
                .type(String.class)
                .dest("basicAuth")
                .help("Basic auth pair: username:password");

        Namespace ns = null;
        try {
            ns = parser.parseArgs(args);
        } catch (ArgumentParserException e) {
            parser.handleError(e);
            System.exit(1);
        }

        // make the arguments ready to use
        dontscan = ns.get("dontscan");
        hostId = ns.get("hostId"); // TODO 
        
        // TODO 
        String basicAuth = ns.get("basicAuth");
        if (basicAuth != null) {
            basicAuthUser = basicAuth.split(":")[0];
            basicAuthPass = basicAuth.split(":")[1];
        }

        target = ns.get("target");
        try {
            // workaround for burps spider bug
            target += target.endsWith("/") ? "" : "/";
            
            if (!target.startsWith("http://") && !target.startsWith("https://")) {
                // unspecified scheme: scan both
                targets.add(new URL("http://" + target));
                targets.add(new URL("https://" + target));
            }
            else {
                targets.add(new URL(target));
            }
            targetFQDN = targets.get(0).getHost();
            
        } catch (MalformedURLException e) {
            handleTerminalException(e);
        }

        workingDir = ns.get("workingDir");
        try {
            File workingDirF = new File(workingDir);

            if (!workingDirF.isDirectory()) {
                log.err(workingDir + " is not a directory");
                System.exit(1);
            }
            if (!workingDirF.canWrite()) {
                log.err(workingDir + " is not writable");
                System.exit(1);
            }
            if (!workingDir.endsWith("/")) {
                workingDir += "/";
            }
        }
        catch (Exception e) {
            handleTerminalException(e);
        }

        baseConfigPath = ns.get("conf");
        try {
            baseConfigFile = new File(baseConfigPath).getCanonicalFile();

            if (!baseConfigFile.isFile()) {
                log.err(baseConfigPath + " is not a file");
                System.exit(1);
            }
            if (!baseConfigFile.canRead()) {
                log.err(baseConfigPath + " is not readable");
                System.exit(1);
            }
        }
        catch (Exception e) {
            handleTerminalException(e);
        }
    }

    private boolean loadBaseState() {
        try {
            callbacks.saveExtensionSetting("skynet_started", "yes");
            log.log("loading config " + baseConfigPath + " ...");
            callbacks.restoreState(baseConfigFile);
            log.log("loading done.");
            callbacks.saveExtensionSetting("skynet_started", "no");
            return true;
        } catch (Exception e) {
            log.err("Failed to setup the state", e);
            return false;
        }
    }



    /**
     * This is where everything starts.
     */
    private void startSkynet() {
        try {
            startTime = new Date();

            log.log("target FQDN is " + targetFQDN);
            if (targets.size() == 1) {
                log.log("target scheme specified");
            }
            else {
                log.log("target scheme unspecified: using both");
            }
            
            if (dontscan) {
                log.warn("not running spider or scanner");
            }
            else {
                log.log("saving config...");
                conf = new Configuration();
                log.log("done.");

                setScope();
                setBasicAuth();
                //conf.dumpConfig();
                
                log.log("starting request validator...");
                requestRules = new RequestValidator();
                log.log("done.");
                
                log.log("starting performance monitor...");
                perfMon = new PerformanceMonitor(conf);
                log.log("done.");

                log.log("starting spider monitor...");
                spiderMonitor = new SpiderMonitor(new Date());
                Thread spiderT = new Thread(spiderMonitor);
                spiderT.setUncaughtExceptionHandler(new ThreadExceptionHandler());
                spiderT.start();
                log.log("done.");                

                log.log("starting spidering...");
                for(URL t : targets) {
                    callbacks.sendToSpider(t);
                }

                // wait for the spider & scanner
                log.trace("entering the joins...");
                spiderT.join();
                log.trace("after spider join");
                scanT.join();
                log.trace("after scan join");
                log.log("Spider & Scanner are done.");
            }

            stopSkynet(Nosy.EXIT_SUCCESS);
        } 
        catch (Exception e) {
            handleTerminalException(e);
        }
    }

    private void stopMonitors() {
        if (!dontscan) {
            spiderMonitor.stop();
            scanMonitor.stop();
        }
    }
    
    public void stopSkynet(int reason) {
        
        log.log("stopSkynet called with " + reason);
        log.log("stopSkynet exited is " + exited);
        
        log.log("stopSkynet exiting");
        stopMonitors();
        log.log("stopSkynet after stoppingMonitors");
        try {
            save();
        } 
        catch (java.lang.UnsupportedOperationException e) {
            log.err("Error while exiting", e);
            reason = Nosy.EXIT_UNKNOWN;
            log.err("Exit reason updated");
        }
        log.log("stopSkynet after saving");
        reportStats(reason);
        log.log("stopSkynet after reporting");
        callbacks.exitSuite(false);
        log.log("stopSkynet after exiting");
    }
    
    private void save() {
        log.log("Starting exit procedure: handling results");
        report = new Reporter(targets());
        report.analyze();
        if (!dontscan) {
            report.sendIssues();
        }
        

        // save state
        log.trace("Working directory " + workingDir);
        File stateFile = new File(workingDir + "/" + new Date().toString().replaceAll("[\\s:]", "_") + ".burp");
        try {
            log.log("saving state...");
            log.trace("saving " + stateFile.toString());
            callbacks.saveState(stateFile);
            log.log("done.");
        } catch (Exception e) {
            log.err("Failed to save state.", e);
        }
    }
    
    private void reportStats(int reason) {
        Date stopTime = new Date();
        long runTime = stopTime.getTime() - startTime.getTime();
        
        if (!dontscan) {
            try {
                boolean statsError = report.sendStats(startTime, stopTime, requests, reason);
                if (statsError) {
                    log.err("Failed to report stats to Nosy");
                }
            } catch (MalformedURLException ex) {
                log.err("Failed to report stats to Nosy");
                log.err("Failed to parse the target URL", ex);
            } catch (IOException ex) {
                log.err("Failed to report stats to Nosy");
                log.err("Failed to send stats", ex);
            }
        }
    }

  
    private void handleTerminalException(Exception e) {
        // TODO ensure this logs
        java.util.logging.Logger.getLogger(BurpExtender.class.getName()).log(Level.SEVERE, "Error: ", e);
        callbacks.exitSuite(false);
    }


    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse message) {
        IRequestInfo reqInfo = helper.analyzeRequest(message);

        if (messageIsRequest) {
            setUserAgent(message);
            requests++;            
        }

        // process spider request/response
        if (toolFlag == IBurpExtenderCallbacks.TOOL_SPIDER) {
            if (messageIsRequest) {
                // TODO missing method test for spider
                requestRules.spiderable(message);
                log.trace("spidering... " + reqInfo.getUrl() + " with " + reqInfo.getMethod());
            } 
            else {
                spiderLog.log(message);
                

                
                try {
                    IResponseInfo resInfo = helper.analyzeResponse(message.getResponse());

                    log.trace("Response status code: " + resInfo.getStatusCode());
                    // got a spider response. Let's scan it
                    if (resInfo.getStatusCode() != HttpURLConnection.HTTP_NOT_FOUND) {
                        scanUrl(message);
                    }
                } catch (Exception e) {
                    log.err("Spider exception!", e);
                }
            }
        }
        else if (toolFlag == IBurpExtenderCallbacks.TOOL_SCANNER && !messageIsRequest) {
            scannerLog.log(message);
        }

    }

    public void scanUrl(IHttpRequestResponse messageInfo) {
        try {
            IHttpService service = messageInfo.getHttpService();
            IRequestInfo reqInfo = helper.analyzeRequest(messageInfo);
            log.trace("Will try to scan " + reqInfo.getUrl());

            // is this request using TLS?
            boolean useTLS = service.getProtocol().equals("https");
            callbacks.doPassiveScan(service.getHost(), service.getPort(), useTLS, messageInfo.getRequest(), messageInfo.getResponse());

           if (requestRules.scannable(messageInfo)) {               
                IScanQueueItem scanItem = callbacks.doActiveScan(service.getHost(), service.getPort(), useTLS, messageInfo.getRequest());
                scanQueue.add(scanItem);
           }            
        }
        catch (Exception e) {
            log.err("Scanner exception!" , e);
        }
    }

    public byte[] processProxyMessage(int messageReference, boolean messageIsRequest, java.lang.String remoteHost, int remotePort, boolean serviceIsHttps, java.lang.String httpMethod, java.lang.String url, java.lang.String resourceType, java.lang.String statusCode, java.lang.String responseContentType, byte[] message, int[] action) {

        return message;
    }

    @Override
    public void extensionUnloaded() {
      
    }

    
    public List<URL> targets() {
        return targets;
    }

    public static IBurpExtenderCallbacks getBurpCallbacks() {
        return callbacks;
    }


    public String toolName(int tool) {
        if (tool == IBurpExtenderCallbacks.TOOL_SPIDER) {
            return "spider";
        }
        else if (tool == IBurpExtenderCallbacks.TOOL_SCANNER) {
            return "scanner";
        }
        else {
            return "new tool " + tool;
        }
    }
    
    private String version() {
        
        String[] version = callbacks.getBurpVersion();
        return version[1] + "." + version[2];
    }
    
    private void setBasicAuth() {
        if (basicAuthUser != null && basicAuthPass != null &&
                !basicAuthUser.isEmpty() && !basicAuthPass.isEmpty()) {
            log.log("setting basic auth as specified");
            conf.setBasicAuth(targetFQDN, basicAuthUser, basicAuthPass);
        }
    }
   
    private void setScope() {
        // add to system wide scope (spider, scanner, etc)
        for(URL t : this.targets) {
            log.log("adding " + t.toString() + " to scope...");
            callbacks.includeInScope(t);
        }   
    }
}
