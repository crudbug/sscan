package scanner;

import log.Logger;
import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;


public class Configuration {
  
    public static String COLLABORATOR = "burpcollaborator.net";
    public static String USERAGENT = "UA/2.0";
    // max number of itens in the scan queue
    public static int SCANNER_MAX_QUEUE = 100;

        
    // burp config after loading everything
    private final Map<String,String> baseConfig;

    // log facility
    private final Logger log;

    // burp API callback object
    private final IBurpExtenderCallbacks callbacks;

    public Configuration() {
        this.callbacks = BurpExtender.getBurpCallbacks();
        this.log = Logger.getInstance();
        log.trace("loaded configuration log instance");
        this.baseConfig = callbacks.saveConfig();
        log.trace("after saveConfig");
    }

    public void dumpConfig() {
        log.trace("Dumping config...\n");

        Iterator it = callbacks.saveConfig().entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry pairs = (Map.Entry)it.next();
            log.trace(pairs.getKey() + " = " + pairs.getValue());
        }

        log.trace("\ndone.");
    }


    public String getSetting(String settingName) {
        return (String) callbacks.saveConfig().get(settingName);
    }

   
}
