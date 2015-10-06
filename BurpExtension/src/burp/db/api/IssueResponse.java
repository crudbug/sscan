/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package burp.db.api;

import com.google.gson.JsonParser;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 *
 * @author tmendo
 */
public class IssueResponse {

    private final String response;
    private int issue_id;
    private boolean ok = false;
    private String error;
    

    public IssueResponse(String response) {
        this.response = response;

        Pattern pattern = Pattern.compile("^\\{\"id\":\\s(\\d+),");
        Matcher matcher = pattern.matcher(response);

        if (matcher.find()) {
            issue_id = Integer.parseInt(matcher.group(1));
            ok = true;
        }
        else {
            getError();
        }
     }

    public int issueID() {
        return issue_id;
    }

    public boolean ok() {
        return ok;
    }
    
    /**
     * parses {"non_field_errors": ["Possible duplicate [7912L]"]}
     * @return 
     */
    public boolean duplicate() {
        String errorDetail = new JsonParser().parse(response).getAsJsonObject().get("non_field_errors").getAsJsonArray().get(0).getAsString();

        return Pattern.compile("Possible\\sduplicate\\s\\[\\d+L\\]").matcher(errorDetail).matches();
    }
    
    public String duplicateError() {
        return new JsonParser().parse(response).getAsJsonObject().get("non_field_errors").getAsJsonArray().get(0).getAsString();
    }

    private void getError() {
        Pattern pattern = Pattern.compile("^\\{\"(.+?)\":(.+)");
        Matcher matcher = pattern.matcher(response);
        
        if (matcher.find()) {
            error = matcher.group(1) + " : " + matcher.group(2);
        }
    }

    public String error() {
        return error;
    }
}
