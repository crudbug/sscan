package nosy;

import log.Logger;
import java.util.Hashtable;


public class Severity {
    
    
    public static String FP = "False positive";    

    private static Hashtable<String, String> getMap() {
        Hashtable<String, String> severities = new Hashtable<String, String>();
        severities.put("High", "20S");
        severities.put("Medium", "10P");
        severities.put("Low", "00O");
        severities.put("Information", "00O");

        return severities;
    }

    // TODO do this in the Nosy
    public static String fromBurp(String burp) {

        String out = getMap().get(burp);
        if (out == null) {
            Logger log = Logger.getInstance();
            log.warn("got an invalid severity: " + burp);
            return null;
        } else {
            return out;
        }
    }
}

