/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package burp.db;

import burp.db.api.AuditList;
import burp.db.api.IssueResponse;
import burp.db.api.ProjectList;
import burp.db.api.SourceList;
import burp.db.api.VulnerabilityCategoryList;
import burp.db.api.VulnerabilityList;
import com.google.gson.Gson;
import java.io.*;
import java.net.URL;
import java.net.URLEncoder;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.HttpsURLConnection;
import javax.xml.bind.DatatypeConverter;
import log.Logger;
import pt.sapo.securitylib.crypto.Crypto;

/**
 *
 * @author tmendo
 */
public class DB {

    private static final String DB_URL = "https://localhost/";
    private static final String URL_BASE = DB_URL + "api/";
    private static final String DB_ISSUE = DB_URL + "issue/";
    private static final Logger log = Logger.getInstance();
    private Source[] sources;
    private Vulnerability[] vulnerabilities;
    private Project[] projects;
    private Severity[] severities;
    private VulnerabilityCategory[] vulnCategories;
    private Audit[] audits;

    public String urlForIssue(int issue) {
        return DB_ISSUE + Integer.toString(issue);
    }


    /**
     * returns the audit from the specified index position
     *
     * @param index
     * @return
     */
    public Audit auditByIndex(Number index) {
        int i = index.intValue();
        if (i >= 0 && i < audits.length) {
            return audits[i];
        } else {
            return null;
        }
    }

    /**
     * returns the vulnerability from the specified index position
     *
     * @param index
     * @return
     */
    public VulnerabilityCategory vulnerabilityCategoryByIndex(Number index) {
        int i = index.intValue();
        if (i >= 0 && i < vulnCategories.length) {
            return vulnCategories[i];
        } else {
            return null;
        }
    }

    /**
     * returns the source from the specificed index position
     *
     * @param index
     * @return
     */
    public Source sourceByIndex(Number index) {
        int i = index.intValue();
        if (i >= 0 && i < sources.length) {
            return sources[i];
        } else {
            return null;
        }
    }

    /**
     * returns the project from the specified index position
     *
     * @param index
     * @return
     */
    public Project projectByIndex(Number index) {
        int i = index.intValue();
        if (i >= 0 && i < projects.length) {
            return projects[i];
        } else {
            return null;
        }
    }
    
    public Project projectByName(String name) {
        for (int i = 0; i < projects.length; i++) {
                if (projects[i].name.equals(name)) {
                    return projects[i];
                }
        }
        
        return null;
    }

    /**
     * returns the vulnerability from the specified index position
     *
     * @param index
     * @return
     */
    public Vulnerability vulnerabilityByIndex(Number index) {
        int i = index.intValue();
        if (i >= 0 && i < vulnerabilities.length) {
            return vulnerabilities[i];
        } else {
            return null;
        }
    }

    /**
     * returns the severity from the specified index position
     *
     * @param index
     * @return
     */
    public Severity severityByIndex(Number index) {
        int i = index.intValue();
        if (i >= 0 && i < severities.length) {
            return severities[i];
        } else {
            return null;
        }
    }

    public String[] getCategories() throws IOException {
        try {
            String response = sendRequest(URL_BASE + "vulnerabilitycategory/?page_size=10000");

            VulnerabilityCategoryList categoryList = new Gson().fromJson(response, VulnerabilityCategoryList.class);
            vulnCategories = categoryList.results;
            
            String[] names = new String[categoryList.count];
            for (int i = 0; i < categoryList.count; i++) {
                names[i] = vulnCategories[i].name;
            }

            return names;
        } catch (IOException ex) {
            log.err("Could not get categories");
            throw ex;
        } catch (com.google.gson.JsonSyntaxException ex) {
            log.err("db API returned something unexpected");
            log.err(ex);
            throw ex;
        }
    }

    public String[] getSeverities() throws IOException {
        try {
            String response = sendRequest(URL_BASE + "severity/");

            log.log(response);
            severities = new Gson().fromJson(response, Severity[].class);
            
            String[] names = new String[severities.length];
            for (int i = 0; i < severities.length; i++) {
                names[i] = severities[i].name;
            }

            return names;
        } catch (IOException ex) {
            log.err("Could not get severities");
            throw ex;
        } catch (com.google.gson.JsonSyntaxException ex) {
            log.err("db API returned something unexpected");
            log.err(ex);
            throw ex;            
        }
    }

   
    public String[] getProjects() throws IOException {
        try {
            // page_size=10000 forces the API to return all projects
            String response = sendRequest(URL_BASE + "project/?page_size=10000");

            ProjectList project_list = new Gson().fromJson(response, ProjectList.class);
            // this is the one used to map the UI choosen index to the right project ID
            projects = project_list.results;

            String[] names = new String[project_list.count];
            for (int i = 0; i < project_list.count; i++) {
                names[i] = projects[i].name;
            }

            return names;
        } catch (IOException ex) {
            log.err("Could not get projects");
            throw ex;
        } catch (com.google.gson.JsonSyntaxException ex) {
            log.err("db API returned something unexpected");
            log.err(ex);
            throw ex;
        }
    }

    /**
     * returns the vulnerabilities from the category index
     *
     * @param categoryIndex
     * @return
     */
    public String[] getVulnerabilities(Number categoryIndex) throws IOException {
        return getVulnerabilities(vulnerabilityCategoryByIndex(categoryIndex).id);
    }

    public String[] getVulnerabilities() throws IOException {
        return getVulnerabilities(-1);
    }

    public String[] getVulnerabilities(int categoryId) throws IOException {
        try {
            String response;
            if (categoryId == -1) {
                response = sendRequest(URL_BASE + "vulnerability/");
            } else {
                log.log("Fetching vulnerabilities for category " + categoryId);
                response = sendRequest(URL_BASE + "vulnerability/?vulnerability_category=" + categoryId);
            }

            VulnerabilityList vuln_list = new Gson().fromJson(response, VulnerabilityList.class);
            vulnerabilities = vuln_list.results;
            String[] names = new String[vulnerabilities.length];
            for (int i = 0; i < vulnerabilities.length; i++) {
                names[i] = vulnerabilities[i].name;
            }

            return names;
        } catch (IOException ex) {
            log.err("Could not get vulnerabilities");
            throw ex;
        } catch (com.google.gson.JsonSyntaxException ex) {
            log.err("db API returned something unexpected");
            log.err(ex);
            throw ex;
        }
    }

       public List<String> getAudits(int projectId) throws IOException {
        try {
            String response;
            log.log("Fetching audits for project " + projectId);
            response = sendRequest(URL_BASE + "audit/?project=" + projectId);
  
            AuditList audit_list = new Gson().fromJson(response, AuditList.class);
            audits = audit_list.results;
            List<String> dates = new ArrayList<String>();
            for (int i = 0; i < audits.length; i++) {
                dates.add(audits[i].start_date);
            }

            return dates;
        } catch (IOException ex) {
            log.err("Could not get audits");
            throw ex;
        } catch (com.google.gson.JsonSyntaxException ex) {
            log.err("db API returned something unexpected");
            log.err(ex);
            throw ex;
        }
    }

    public String[] getSources() throws IOException {
        try {
            // page_size=10000 forces the API to return all projects
            String response = sendRequest(URL_BASE + "issuesource/?page_size=10000");

            SourceList source_list = new Gson().fromJson(response, SourceList.class);
            sources = source_list.results;
            
            String[] names = new String[source_list.count];
            for (int i = 0; i < source_list.count; i++) {
                names[i] = sources[i].name;
            }

            return names;
        } catch (IOException ex) {
            log.err("Could not get sources");
            throw ex;
        } catch (com.google.gson.JsonSyntaxException ex) {
            log.err("db API returned something unexpected");
            log.err(ex);
            throw ex;
        }
    }

    private String sendRequest(URL url, String method, String data) throws IOException {

        // open HTTPS connection
        HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
        conn.setConnectTimeout(2000);
        conn.setDoOutput(true);
        conn.setRequestProperty("Accept", "application/json");
        conn.setRequestMethod(method);
        if (method.equals("POST")) {
            conn.setDoInput(true);
            try (DataOutputStream wr = new DataOutputStream(conn.getOutputStream())) {
                wr.writeBytes(data);
                wr.flush();
            }
        }

        // execute HTTPS request
        InputStream connIn = null;
        int code = conn.getResponseCode();
        if (code == HttpsURLConnection.HTTP_CREATED || code == HttpsURLConnection.HTTP_OK) {
            connIn = conn.getInputStream();
        } else {
            log.err("Got HTTP " + conn.getResponseCode() + " from " + url.toString());
            connIn = conn.getErrorStream();
        }
        
        StringBuffer response = new StringBuffer();
        try (BufferedReader buffer = new BufferedReader(new InputStreamReader(connIn))) {
            String tmp;
            while ((tmp = buffer.readLine()) != null) {
                response.append(tmp);
            }
        }

        return response.toString();
    }

    private String sendRequest(String urlStr) throws IOException  {
        try {
            String randomParam = UUID.randomUUID().toString().replace("-", "");

            // we might receive an URL with a query string
            URL url = new URL(urlStr);
            if (url.getQuery() == null) {
                url = new URL(urlStr+"?sdata="+randomParam+"&hmac="+DatatypeConverter.printHexBinary(this.hmac(randomParam)));
            }
            else {
                url = new URL(urlStr+"&sdata="+randomParam+"&hmac="+DatatypeConverter.printHexBinary(this.hmac(randomParam)));
            }

            log.log("URL: " + url);
            return sendRequest(url, "GET", null);
        } catch (IOException ex) {
            log.err("Communication failure: " + ex.getMessage());
            throw ex;
        } catch (GeneralSecurityException ex) {
            log.err("Error building the HMAC:");
            log.err(ex);
            return "";
        }
    }


    private String sendRequest(URL url) throws IOException {
        return sendRequest(url, "GET", null);
    }

    // sets the issue ID if everything goes well
    public void sendIssue(Issue issue) throws Exception {

        String raw_response = sendRequest(new URL(URL_BASE + "issue/"), "POST", getIssueWithHmacInJson(issue));
        log.log("db response " + raw_response);

        IssueResponse response = new IssueResponse(raw_response);
        
        if (response.ok()) {
            issue.id = response.issueID();
        }
        else if (response.duplicate()) {
            throw new IssueDuplicateException(response.duplicateError());
        }
        else {
            throw new IssueNotSavedException(response.error());
        }
    }


    private String getIssueWithHmacInJson(Issue issue) {
        try {
            String issueJson = issue.toJson();
            String postdata = "sdata=" + URLEncoder.encode(issueJson, "UTF-8") + "&hmac=" + DatatypeConverter.printHexBinary(this.hmac(issueJson));
            log.log("no encoding -> sdata=" + issueJson + "&hmac=" + DatatypeConverter.printHexBinary(this.hmac(issueJson)));
            log.log("Issue -> " + postdata);

            return postdata;
        } catch (Exception ex) {
            log.err("Error obtaining the issue with HMAC:");
            log.err(ex);
            return "";
        }
    }

    private byte[] hmac(String in) throws GeneralSecurityException {
        byte[] secret = DatatypeConverter.parseHexBinary("XX");
        return Crypto.generateAuthenticator(in.getBytes(), secret);
    }
    
 
}
