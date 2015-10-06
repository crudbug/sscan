package scanner;

import burp.BurpExtender;
import log.Logger;
import burp.IScanQueueItem;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import nosy.Nosy;


public class ScanMonitor implements Runnable {

    // TODO 
    private static final String TOO_MANY_ERRORS = "abandoned - too many errors (";
    private static final String WAITING_CANCEL = "waiting to cancel";
    private static final String CANCELLED = "cancelled";

    // seconds the thread waits before checking the queue again
    private static final int THREAD_WAIT = 10;
    
    // max seconds without progress
    private static final int SCAN_WAIT = 100;
    private int queueSize = 0;
    private Date lastQueueChange;
    private int reqs = 0;
    private int previousItemRequests = 0;
    
    // log facility
    private final Logger log;

    // scanner queue
    private final List<IScanQueueItem> scanQueue;


    private int scannedItems;       // scanned items
    private int errorItems;         // items with error
    private int canceledItems;      // canceled items

    // stuff to handle thread stopping
    private volatile boolean stop = false;

    public ScanMonitor(List<burp.IScanQueueItem> scanQueue) {
        this.log= Logger.getInstance();

        this.scanQueue = scanQueue;
        this.scannedItems = 0;
        this.errorItems = 0;
        this.canceledItems = 0;
        this.lastQueueChange = new Date();
    }

    public void stop() {
        stop = true;
        log.trace("scanMonitor was asked to stop");
    }

    @Override
    public void run() {
        // go immediately to sleep: we might not have anything on queue upon start
        while(!stop) {
            try {
                Thread.sleep(THREAD_WAIT * 1000);
            }
            catch (InterruptedException ex) {
                log.err("ScanMonitor sleep was interrupted! Reason: " + ex.getMessage());
            }

            // list of items completed, to remove
            ArrayList<IScanQueueItem> completeItems = new ArrayList<>();

            for(IScanQueueItem scanItem : scanQueue) {

                if (scanItem.getPercentageComplete() == 100) {
                    log.trace("removing a complete scanItem");
                    completeItems.add(scanItem);
                }
                else if (scanItem.getStatus().startsWith(TOO_MANY_ERRORS)) {
                    log.trace("Scan item removed due to: " + scanItem.getStatus() + ". Error count: " + scanItem.getNumErrors());
                    completeItems.add(scanItem);
                    errorItems++;
                }
                else if (scanItem.getStatus().equals(WAITING_CANCEL) ||
                        scanItem.getStatus().equals(CANCELLED)) {
                    log.trace("Scan item removed due to: " + scanItem.getStatus());
                    completeItems.add(scanItem);
                    canceledItems++;
                }
                else {
                    itemRequests = scanItem.getNumRequests();
                    log.trace("Scan item status is " + scanItem.getStatus() +
                            " - Errors: " + scanItem.getNumErrors() + " Requests: "  + scanItem.getNumRequests() +
                            " Insertion: " + scanItem.getNumInsertionPoints());
                }
            }
            
            // remove them
            scannedItems += completeItems.size();
            scanQueue.removeAll(completeItems);

            // report the current queue status
            if (scanQueue.size() > 0) {
                log.log(scanQueue.size() + " remaining objects in the scan queue");
                
                if (scanQueue.size() > Configuration.SCANNER_MAX_QUEUE) {
                    log.warn("Scan queue size is too big");
                    log.warn("Preparing to exit");
                    BurpExtender.getInstance().stopSkynet(Nosy.EXIT_QUEUE);
                    stop = true;
                }
            }
            else if (BurpExtender.getInstance().spiderMonitor. spider.isAlive()) {
                log.log("Scanner queue is empty. Waiting for the spider"); 
            }
            else if (!BurpExtender.getInstance().spiderMonitor.running()){
                log.log("Scanning completed at " + new Date() + ". " + scannedItems + " items were scanned");
                if (errorItems > 0 || canceledItems > 0) {
                    log.log(errorItems + " items with too many errors and " + canceledItems + " were canceled.");
                }
                stop = true;
            }
            else {
                log.warn("Scan queue is empty, but Spider is running");
            }
           
        }
                
        log.log("Scanning complete");
    }
}
