package scanner;

import log.Logger;
import java.util.Date;


public class SpiderMonitor implements Runnable {

    // idle seconds time before considering spider done
    public int idleTimeout = 60;


    // log facility
   private final Logger log;

    // last spider request
    private final Date lastRequest;
    
    // stuff to handle thread stopping
    private volatile boolean stop = false;

    public SpiderMonitor(Date lastRequest) {
        this.log= Logger.getInstance();
        this.lastRequest = lastRequest;
    }

    public boolean running() {
        return !stop;
    }

    public void stop() {
        stop = true;
    }

    @Override
    public void run() {
        int timeout = 1000*idleTimeout;

        Date currentTime = new Date();
        log.log("Spider started at " + currentTime);

        while (!stop && lastRequest.getTime() + timeout > currentTime.getTime())
        {
            log.trace("Spider monitor is waiting...");
            currentTime = new Date();
            try {
                Thread.sleep(timeout);
            } catch (InterruptedException ex) {
                log.err("SpiderMonitor sleep was interrupted! Reason: " + ex.getMessage());
            }
        }
        
        stop(); // update status (may have exited because of timeout)
        log.log("Spidering complete at " + lastRequest);
    }
}
