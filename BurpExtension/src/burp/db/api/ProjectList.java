/*
 * This class exists only to easy the gson deserialization
 */

package burp.db.api;

import burp.db.Project;

/**
 *
 * @author tmendo
 */
public class ProjectList {

    public int count;
    public Project[] results;
}
