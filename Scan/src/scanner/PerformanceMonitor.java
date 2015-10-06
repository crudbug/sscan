
package scanner;

import burp.BurpExtender;
import burp.IHttpRequestResponse;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import log.Logger;
import nosy.Nosy;


public class PerformanceMonitor {

    // max ms before
    private static final int HARD_LIMIT_RESPONSE = 5000;
    
    // seconds before giving up waiting on this request
    private static final int TIMEOUT = 10;

    // request being measured
    private IHttpRequestResponse request;

    // moment the request is sent.
    private long requestTime;

    // are we waiting for a response?
    private boolean waitingForResponse = false;

    // logger facility
    private final Logger logger;

    // throttling?
    private boolean throttling = false;


    // spider and scanner step throttle increase in miliseconds
    private static final int THROTTLE_STEP = 200;

    // calculated baseline response time
    private int baseResponseTime = 0;

    // the number of values used to calculate the baseline
    private int baseValueCount = 0;

    // have we determined the baseline response time?
    private boolean haveBaseline = false;

    // burp configuration
    private final Configuration conf;


    public PerformanceMonitor(Configuration conf) {
        this.logger= Logger.getInstance();
        this.conf = conf;
    }



    public void markRequest(IHttpRequestResponse msgInfo) {
        this.request = msgInfo;
        this.requestTime = new Date().getTime();
        this.waitingForResponse = true;
    }


    public void markResponse(IHttpRequestResponse msgInfo) {

        if (!waitingForResponse) {
            return;
        }

        try {
            long responseTime = new Date().getTime() - requestTime;

            if (Arrays.equals(request.getRequest(), msgInfo.getRequest())) {
                waitingForResponse = false;

                // compare against the baseline
                if (haveBaseline) {
                    if (responseTime >= HARD_LIMIT_RESPONSE) {
                        logger.err("Response time over hard limit : " + responseTime);
                        BurpExtender.getInstance().stopSkynet(Nosy.EXIT_TIME_LIMIT);
                    }           
                }
                else {
                    addToBaseline(responseTime);
                }
            }
            else if (responseTime >= TIMEOUT * 1000) {
                logger.log("Response timeout: " + responseTime + "ms");
            }
        }
        catch (Exception e) {
            logger.err("PerformanceMonitor failed to compared request and response", e);
        }
    }



    /**
     * Helper function to calculate the baseline
     */
    private void addToBaseline(long responseTime) {
         baseResponseTime += responseTime;
         baseValueCount++;

         // got all values
         if (baseValueCount == BASELINE_SIZE) {
            baseResponseTime = baseResponseTime / BASELINE_SIZE;
            haveBaseline = true;
            logger.log("Baseline response time is: " + baseResponseTime + "ms");
         }
    }    
}
