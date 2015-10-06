/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package burp.db;

import com.google.gson.JsonParser;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 *
 * @author tmendo
 */
public class IssueDuplicateException extends Exception {

    private String error;

    public IssueDuplicateException(String err) {
        super(err);        
        this.error = err;
    }

}
