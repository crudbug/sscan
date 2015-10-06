package log;

import burp.IHttpRequestResponse;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.PrintStream;
import java.io.UnsupportedEncodingException;
import java.text.SimpleDateFormat;
import java.util.Date;



public class MessageLogger {

    private final PrintStream out;
    private final SimpleDateFormat formatter;
    private final String tool;

    public MessageLogger(String path, String tool) throws FileNotFoundException {
        this.tool = tool;
        out = new PrintStream(new FileOutputStream(path, true));
        formatter = new SimpleDateFormat("dd-MMM-yyyy HH:mm:ss:SSS");
    }

    public void log(IHttpRequestResponse message) {
        out.println(formatter.format(new Date()) + " - " + tool);

        try {            
            out.println(new String(message.getRequest(), "UTF-8"));
        } catch (UnsupportedEncodingException ex) {
            out.println("Error: could not log the request: " + ex.getMessage());
        }

        try {
            out.println(new String(message.getResponse(), "UTF-8") + "\n");
        } catch (UnsupportedEncodingException ex) {
            out.println("Error: could not log the response: " + ex.getMessage());
        }
    }
}
