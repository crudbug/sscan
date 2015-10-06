/*
 * This class exists only to easy the gson deserialization
 */


package burp.db.api;

import burp.db.Audit;


/**
 *
 * @author tmendo
 */
public class AuditList {
    public int count;
    public Audit[] results;
}
