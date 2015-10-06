/*
 * This class exists only to easy the gson deserialization
 */


package burp.db.api;

import burp.db.Source;

/**
 *
 * @author tmendo
 */
public class SourceList {

    public int count;
    public Source[] results;
}
