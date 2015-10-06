/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package burp.db;

import burp.BurpExtender;
import helper.HttpMessage;
import burp.IRequestInfo;
import com.google.gson.Gson;
import com.google.gson.JsonObject;

import java.net.URL;


public class Issue {

    // Issue fields required by the DB
    public int id = -1;
    private final String method;
    private String url;
    private final String severity;
    private final int project;
    private int audit = -1;
    private final int vulnerability;
    private final int source;
    private final String information;
    private final String private_information;
    private final String payload;
    private final String full_payload;
    private final String parameter;
    private final String response;
    private final String created_by;


    /**
     * @param request
     * @param response
     * @param reqInfo
     * @param severity
     * @param source
     * @param project
     * @param audit
     * @param vulnerability
     * @param info
     * @param parameter
     * @param privateInfo
     * @throws Exception 
     */
    public Issue(byte[] request, byte[] response,
            IRequestInfo reqInfo, Severity severity, Source source, Project project, Audit audit,
            Vulnerability vulnerability, String info, String parameter, String privateInfo) throws Exception {

        // method
        this.method = HttpMessage.getMethod(request);

        // url
        URL u = reqInfo.getUrl();
        this.url = u.getProtocol() + "://" + u.getHost();
        if (u.getPort() != 80 && u.getPort() != 443 && u.getPort() != -1) {
            this.url += ":" + u.getPort();
        }
        this.url += u.getPath();
        // log.trace("message url " + this.url);

        // from menu
        this.severity = severity.id;
        this.project = project.id;
        if (audit != null) {
            this.audit = audit.id;
        }
        this.vulnerability = vulnerability.id;
        this.source = source.id;
        this.information = info;
        this.private_information = privateInfo;

        // full payload
        this.full_payload = new String(request);

        // full response
        this.response = new String(response, "UTF-8");

        // payload
        // remove the headers and leave the rest
        this.payload = new String(request).replaceFirst("(?s).+?\\r?\\n\\r?\\n", "");

        // parameter
        this.parameter = parameter;
        
        // human that reported the vulnerability
        this.created_by = BurpExtender.getBurpCallbacks().loadExtensionSetting("reporterName");
    }

    public String toJson() {
        if (audit != -1) {
            return new Gson().toJson(this);
        }
        else {
            JsonObject asJsonObject = new Gson().toJsonTree(this).getAsJsonObject();
            asJsonObject.remove("audit");
            return asJsonObject.toString();
        }
    }

    /**
     * Returns true if this issue was already created if its has a valid ID, it was created
     *
     * @return
     */
    public boolean created() {
        return id != -1;
    }
}
