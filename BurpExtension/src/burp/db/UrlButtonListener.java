/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package burp.db;

import static burp.db.Tab.log;
import java.awt.Desktop;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.net.URI;

/**
 *
 * @author tmendo
 */
public class UrlButtonListener implements ActionListener {

    private String url = null;

    public UrlButtonListener() {        
    }

    public void setUrl(String url) {
        this.url = url;
    }
    
    public void actionPerformed(ActionEvent e) {
        try {
            Desktop.getDesktop().browse(new URI(url));
        } catch (Exception ex) {
            log.err("Could not open browser to view " + url, ex);
        }
    }

}
