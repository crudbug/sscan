package burp;

import burp.db.Tab;
import log.Logger;

// TODO

public class BurpExtender implements IBurpExtender {

    // burp API callback object
    private static IBurpExtenderCallbacks callbacks;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        BurpExtender.callbacks.setExtensionName("DB");

        // start log
        Logger log = new Logger(BurpExtender.callbacks);        
        log.enableTrace();

        // tab
        Tab issueTab = Tab.getInstance();
        issueTab.addMenuTab();
              
        // add right click menu
        this.callbacks.registerContextMenuFactory((IContextMenuFactory) issueTab);
    }

    public static IBurpExtenderCallbacks getBurpCallbacks() {
        return callbacks;
    }
}
