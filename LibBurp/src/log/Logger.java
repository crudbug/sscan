/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package log;

import burp.IBurpExtenderCallbacks;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.PrintStream;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 *
 * @author tmendo
 */
public class Logger {

    // Singleton
    private static Logger instance = null;

    private final SimpleDateFormat formatter;
    private static final String dateFormat = "dd-MM-yyyy HH:mm:ss:SSS";

    // output streams
    private PrintStream err = null;
    private PrintStream out = null;
    
    // split out and err log
    private boolean splitErrorLog = false;

    /**
     * configurations
     */

    // trace prints a lot more stuff
    private boolean trace = false;
    
    /**
     * Functions and constructors
     * @param callbacks
     */
    public Logger(IBurpExtenderCallbacks callbacks) {
        err = new PrintStream(callbacks.getStderr());
        out = new PrintStream(callbacks.getStdout());
        formatter = new SimpleDateFormat(dateFormat);
        splitErrorLog = false;
        instance = this;
    }

    public Logger() {
        err = new PrintStream(System.err);
        out = new PrintStream(System.out);
        formatter = new SimpleDateFormat(dateFormat);
        splitErrorLog = false;
        instance = this;
    }

    public static synchronized Logger getInstance() {
        if (instance == null) {
            instance = new Logger();
        }
        return instance;
    }

    public void enableIndependentLogging(String logDir, String filePrefix, boolean splitErrorLog) throws FileNotFoundException {
        if (err != null) {
            err.close();
        }
        if (out != null) {
            out.close();
        }

        this.splitErrorLog = splitErrorLog;
        
        if(this.splitErrorLog) {
            err = new PrintStream(new FileOutputStream(logDir + "/" + filePrefix + "-error.log", true));
        }
        out = new PrintStream(new FileOutputStream(logDir + "/" + filePrefix + ".log", true));
    }

    public void enableTrace() {
        this.trace = true;
    }

    // public accessors
    public void err(String msg) {
        if (splitErrorLog) {
            err.println(formatter.format(new Date()) + " - ERROR: " + msg);
        }
        else {
            out.println(formatter.format(new Date()) + " - ERROR: " + msg);
        }
    }

    public void err(Exception e) {
        if (splitErrorLog) { 
            e.printStackTrace(err);
        }
        else {
            e.printStackTrace(out);
        }             
    }

    public void err(String msg, Exception e) {
        err(msg);
        err(e);
    }

    public void warn(String msg) {
        log("WARNING: " + msg);
    }

    public void warn(String msg, Exception e) {
        log("WARNING: " + msg);
        e.printStackTrace(out);
    }

    public void trace(String msg) {
        if (this.trace) {
            log("TRACE: " + msg);
        }
    }

    public void log(String msg) {
        out.println(formatter.format(new Date()) + " - " + msg);
    }
}
