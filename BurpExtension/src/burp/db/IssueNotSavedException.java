/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package burp.db;

/**
 *
 * @author tmendo
 */
public class IssueNotSavedException extends Exception {

    private String error;

    public IssueNotSavedException(String err) {
        super(err);
        this.error = err;
    }

}
