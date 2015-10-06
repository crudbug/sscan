/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package burp.db;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IHttpRequestResponseWithMarkers;
import burp.IHttpService;
import burp.IMessageEditor;
import burp.IMessageEditorController;
import burp.IRequestInfo;
import burp.IScanIssue;
import burp.ITab;
import static burp.db.Tab.log;
import ca.odell.glazedlists.EventList;
import ca.odell.glazedlists.GlazedLists;
import ca.odell.glazedlists.matchers.TextMatcherEditor;
import ca.odell.glazedlists.swing.AutoCompleteSupport;
import helper.HttpMessage;
import helper.ScanIssue;
import java.awt.Color;
import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.List;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JComboBox;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.SwingUtilities;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import log.Logger;

/**
 *
 * @author tmendo
 */
public class Tab extends javax.swing.JPanel implements ActionListener, ITab, IMessageEditorController, IContextMenuFactory  {

    // my own Singleton isntance
    private static Tab instance = null;

    // global log
    static Logger log = Logger.getInstance();

    private IExtensionHelpers helper = null;

    // db representation
    private DB db;

    // burp extender objects
    private IBurpExtenderCallbacks iburp;

     // choosen request
    private IMessageEditor requestViewer;
    private IMessageEditor responseViewer;
    private IHttpRequestResponse httpMessage;
    private IRequestInfo reqInfo;
    private IScanIssue scanIssue;

    private DefaultComboBoxModel vulnsModel;
    private DefaultComboBoxModel auditModel;
    
    private AutoCompleteSupport projectAutoComplete;
    
    private UrlButtonListener urlButtonListener;

    private static final String REQUIRED_TITLE = "Missing mandatory value";

    /**
     * Creates new form dbTab2
     */
    public Tab() {
        this.iburp = BurpExtender.getBurpCallbacks();
        this.helper = iburp.getHelpers();
        db = new DB();
        initComponents();
        fillComboBoxes();
        fillOptionTab();
    }


    public static synchronized Tab getInstance() {
        if (instance == null) {
            instance = new Tab();
        }
        return instance;
    }

    private String getInformationTextFormatted() {
        String requestText = "";
        String responseText = "";

        if (httpMessage instanceof IHttpRequestResponseWithMarkers) {

            for (String marker : HttpMessage.getRequestMarkers((IHttpRequestResponseWithMarkers) httpMessage)) {
                requestText += "\n" + marker;
            }
            requestText = requestText.length() > 0 ? "Request details:\n" + requestText : "";

            for (String marker : HttpMessage.getResponseMarkers((IHttpRequestResponseWithMarkers) httpMessage)) {
                responseText += "\n" + marker;
            }
            responseText = responseText.length() > 0 ? "Response details:\n" + responseText : "";
        }

        return requestText + responseText;
    }

    public void setIssueInfo(IScanIssue scanIssue) throws UnsupportedEncodingException {
        this.httpMessage = scanIssue.getHttpMessages()[0];
        this.scanIssue = scanIssue;
        this.parameterTextField.setText(ScanIssue.getParameter(scanIssue));
        this.informationTextArea.setText(scanIssue.getIssueDetail());
        setIssueInfoHelper();
        this.privateInformationTextArea.setText(getInformationTextFormatted());
    }


    public void setCustomIssueInfo(IHttpRequestResponse requestResponse, int[] customBounds, boolean clickedRequest) throws UnsupportedEncodingException {
        this.httpMessage = requestResponse;
        this.scanIssue = null;
        this.parameterTextField.setText("");

        String text = "Response details:\n\n";
        if (clickedRequest) {
            text = "Request details:\n\n";
        }
        text += HttpMessage.getCustomMarkers(requestResponse, customBounds, clickedRequest);
        informationTextArea.setText(text);
        setIssueInfoHelper();
    }


    public void setIssueInfo(IHttpRequestResponse requestResponse) throws UnsupportedEncodingException {
        this.httpMessage = requestResponse;
        this.scanIssue = null;
        this.parameterTextField.setText("");
        this.informationTextArea.setText(getInformationTextFormatted());
        setIssueInfoHelper();
    }


    private void setIssueInfoHelper() {
        if (httpMessage == null) {
            JOptionPane.showMessageDialog(panel, "The request could not be read", REQUIRED_TITLE, JOptionPane.WARNING_MESSAGE);
            return;
        }

        reqInfo = helper.analyzeRequest(httpMessage);

        // TODO 
        this.privateInformationTextArea.setText("");

        requestViewer.setMessage(this.httpMessage.getRequest(), true);
        if (this.httpMessage.getResponse() != null) {
            responseViewer.setMessage(this.httpMessage.getResponse(), false);
        }
        else {
            responseViewer.setMessage(new byte[0],true);
            JOptionPane.showMessageDialog(panel, "Response was not set", REQUIRED_TITLE, JOptionPane.WARNING_MESSAGE);
        }
    }

   
    public void addMenuTab() {
        // create our UI
        SwingUtilities.invokeLater(new Runnable()
        {

            @Override
            public void run()
            {                      
                issueUrlButton.setVisible(false);
                urlButtonListener = new UrlButtonListener();
                issueUrlButton.addActionListener(urlButtonListener);

                // tabs with request/response viewers
                requestViewer = iburp.createMessageEditor(Tab.this, true);
                responseViewer = iburp.createMessageEditor(Tab.this, true);
                requestResponsePane.addTab("Request", requestViewer.getComponent());
                requestResponsePane.addTab("Response", responseViewer.getComponent());

                iburp.customizeUiComponent(Tab.this);

                // add the custom tab to Burp's UI
                iburp.addSuiteTab(Tab.this);
                
                // this enables auto complete. It must be here (at the Swing Event Dispatch Thread)
                projectComboBox.setFocusable(true);
                try {
                    projectAutoComplete = AutoCompleteSupport.install(projectComboBox, GlazedLists.eventListOf(db.getProjects()));
                    projectAutoComplete.setFilterMode(TextMatcherEditor.CONTAINS);
                } catch (IOException ex) {
                    log.err(ex);
                }
            }
        });
    }

    /**
     * This method is called from within the constructor to initialize the form. WARNING: Do NOT modify this code. The content of this method is always regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jTabbedPane1 = new javax.swing.JTabbedPane();
        panel = new javax.swing.JSplitPane();
        requestResponsePane = new javax.swing.JTabbedPane();
        topPane = new javax.swing.JPanel();
        projectLabel = new javax.swing.JLabel();
        auditLabel = new javax.swing.JLabel();
        categoryLabel = new javax.swing.JLabel();
        vulnerabilityLabel = new javax.swing.JLabel();
        severityLabel = new javax.swing.JLabel();
        sourceLabel = new javax.swing.JLabel();
        projectComboBox = new javax.swing.JComboBox();
        auditComboBox = new javax.swing.JComboBox();
        categoryComboBox = new javax.swing.JComboBox();
        vulnerabilityComboBox = new javax.swing.JComboBox();
        severityComboBox = new javax.swing.JComboBox();
        sourceComboBox = new javax.swing.JComboBox();
        jScrollPane1 = new javax.swing.JScrollPane();
        privateInformationTextArea = new javax.swing.JTextArea();
        jScrollPane2 = new javax.swing.JScrollPane();
        informationTextArea = new javax.swing.JTextArea();
        informationLabel = new javax.swing.JLabel();
        privateInformationLabel = new javax.swing.JLabel();
        jButton1 = new javax.swing.JButton();
        parameterLabel = new javax.swing.JLabel();
        parameterTextField = new javax.swing.JTextField();
        feedbackLabel = new javax.swing.JLabel();
        issueUrlButton = new javax.swing.JButton();
        refreshButton = new javax.swing.JButton();
        extendedInfoButton = new javax.swing.JButton();
        jPanel1 = new javax.swing.JPanel();
        reporterName = new javax.swing.JTextField();
        jLabel1 = new javax.swing.JLabel();
        jLabel2 = new javax.swing.JLabel();

        panel.setDividerLocation(300);
        panel.setOrientation(javax.swing.JSplitPane.VERTICAL_SPLIT);

        requestResponsePane.setMaximumSize(new java.awt.Dimension(1000000, 1000000));
        panel.setBottomComponent(requestResponsePane);

        projectLabel.setText("Project");

        auditLabel.setText("Audit");

        categoryLabel.setText("Category");

        vulnerabilityLabel.setText("Vulnerability");

        severityLabel.setText("Severity");

        sourceLabel.setText("Source");

        projectComboBox.setMaximumSize(new java.awt.Dimension(400, 100));
        projectComboBox.setMinimumSize(new java.awt.Dimension(100, 27));
        projectComboBox.setPreferredSize(new java.awt.Dimension(350, 27));
        projectComboBox.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                auditChanger(evt);
            }
        });

        auditComboBox.setMaximumSize(new java.awt.Dimension(400, 32767));
        auditComboBox.setMinimumSize(new java.awt.Dimension(100, 27));
        auditComboBox.setPreferredSize(new java.awt.Dimension(350, 27));

        categoryComboBox.setMaximumSize(new java.awt.Dimension(400, 32767));
        categoryComboBox.setMinimumSize(new java.awt.Dimension(40, 27));
        categoryComboBox.setPreferredSize(new java.awt.Dimension(350, 27));
        categoryComboBox.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                vulnerabilityChanger(evt);
            }
        });

        vulnerabilityComboBox.setMaximumSize(new java.awt.Dimension(400, 32767));
        vulnerabilityComboBox.setMinimumSize(new java.awt.Dimension(40, 27));
        vulnerabilityComboBox.setPreferredSize(new java.awt.Dimension(350, 27));

        severityComboBox.setMaximumSize(new java.awt.Dimension(400, 32767));
        severityComboBox.setMinimumSize(new java.awt.Dimension(40, 27));
        severityComboBox.setPreferredSize(new java.awt.Dimension(350, 27));

        sourceComboBox.setMaximumSize(new java.awt.Dimension(400, 32767));
        sourceComboBox.setMinimumSize(new java.awt.Dimension(40, 27));
        sourceComboBox.setPreferredSize(new java.awt.Dimension(350, 27));

        privateInformationTextArea.setColumns(20);
        privateInformationTextArea.setLineWrap(true);
        privateInformationTextArea.setRows(5);
        privateInformationTextArea.setMinimumSize(new java.awt.Dimension(100, 8));
        privateInformationTextArea.setPreferredSize(new java.awt.Dimension(240, 60));
        jScrollPane1.setViewportView(privateInformationTextArea);

        informationTextArea.setColumns(20);
        informationTextArea.setLineWrap(true);
        informationTextArea.setRows(5);
        jScrollPane2.setViewportView(informationTextArea);

        informationLabel.setText("Information");

        privateInformationLabel.setText("Private Information");
        privateInformationLabel.setLocation(new java.awt.Point(-32151, -32627));

        jButton1.setText("Create Issue");
        jButton1.setHorizontalTextPosition(javax.swing.SwingConstants.CENTER);
        jButton1.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                createIssue(evt);
            }
        });
        jButton1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton1ActionPerformed(evt);
            }
        });

        parameterLabel.setText("Parameter");

        parameterTextField.setToolTipText("");
        parameterTextField.setCursor(new java.awt.Cursor(java.awt.Cursor.TEXT_CURSOR));
        parameterTextField.setMinimumSize(new java.awt.Dimension(350, 28));
        parameterTextField.setPreferredSize(new java.awt.Dimension(350, 28));
        parameterTextField.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                parameterTextFieldActionPerformed(evt);
            }
        });

        issueUrlButton.setText("url button");

        refreshButton.setText("Refresh");
        refreshButton.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                reconnect(evt);
            }
        });
        refreshButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                refreshButtonActionPerformed(evt);
            }
        });

        extendedInfoButton.setText("Extended Info");
        extendedInfoButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                getExtendedInfo(evt);
            }
        });

        javax.swing.GroupLayout topPaneLayout = new javax.swing.GroupLayout(topPane);
        topPane.setLayout(topPaneLayout);
        topPaneLayout.setHorizontalGroup(
            topPaneLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(topPaneLayout.createSequentialGroup()
                .addGap(20, 20, 20)
                .addGroup(topPaneLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(topPaneLayout.createSequentialGroup()
                        .addGroup(topPaneLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(auditLabel)
                            .addComponent(projectLabel)
                            .addComponent(categoryLabel)
                            .addComponent(vulnerabilityLabel)
                            .addComponent(severityLabel)
                            .addComponent(sourceLabel)
                            .addComponent(parameterLabel))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(topPaneLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                            .addComponent(auditComboBox, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(projectComboBox, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(categoryComboBox, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(vulnerabilityComboBox, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(severityComboBox, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(sourceComboBox, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(parameterTextField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addGap(50, 50, 50)
                        .addGroup(topPaneLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(informationLabel)
                            .addComponent(jScrollPane2, javax.swing.GroupLayout.DEFAULT_SIZE, 402, Short.MAX_VALUE)
                            .addComponent(privateInformationLabel)
                            .addComponent(jScrollPane1))
                        .addGap(10, 10, 10))
                    .addGroup(topPaneLayout.createSequentialGroup()
                        .addComponent(refreshButton)
                        .addGap(191, 191, 191)
                        .addComponent(feedbackLabel)
                        .addGap(62, 62, 62)
                        .addComponent(jButton1)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addComponent(issueUrlButton)
                        .addGap(55, 55, 55)
                        .addComponent(extendedInfoButton)
                        .addContainerGap())))
        );
        topPaneLayout.setVerticalGroup(
            topPaneLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(topPaneLayout.createSequentialGroup()
                .addGap(10, 10, 10)
                .addGroup(topPaneLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, topPaneLayout.createSequentialGroup()
                        .addGroup(topPaneLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(projectLabel)
                            .addComponent(projectComboBox, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(topPaneLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(auditLabel)
                            .addComponent(auditComboBox, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(topPaneLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(categoryLabel)
                            .addComponent(categoryComboBox, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(topPaneLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(vulnerabilityLabel)
                            .addComponent(vulnerabilityComboBox, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)))
                    .addGroup(topPaneLayout.createSequentialGroup()
                        .addComponent(informationLabel)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jScrollPane2, javax.swing.GroupLayout.DEFAULT_SIZE, 125, Short.MAX_VALUE)))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(topPaneLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(topPaneLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                        .addComponent(severityLabel)
                        .addComponent(severityComboBox, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addComponent(privateInformationLabel, javax.swing.GroupLayout.Alignment.TRAILING))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(topPaneLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING, false)
                    .addGroup(topPaneLayout.createSequentialGroup()
                        .addGroup(topPaneLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(sourceLabel)
                            .addComponent(sourceComboBox, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(topPaneLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(parameterLabel)
                            .addComponent(parameterTextField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)))
                    .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 0, Short.MAX_VALUE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(topPaneLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jButton1)
                    .addComponent(feedbackLabel)
                    .addComponent(issueUrlButton)
                    .addComponent(refreshButton)
                    .addComponent(extendedInfoButton))
                .addContainerGap())
        );

        panel.setLeftComponent(topPane);

        jTabbedPane1.addTab("Issue", panel);

        reporterName.setMinimumSize(new java.awt.Dimension(300, 28));
        reporterName.setPreferredSize(new java.awt.Dimension(300, 28));
        reporterName.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                reporterNameActionPerformed(evt);
            }
        });

        jLabel1.setText("Reporter Name");

        jLabel2.setText("Format: username");

        javax.swing.GroupLayout jPanel1Layout = new javax.swing.GroupLayout(jPanel1);
        jPanel1.setLayout(jPanel1Layout);
        jPanel1Layout.setHorizontalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addGap(30, 30, 30)
                .addComponent(jLabel1)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(reporterName, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(jLabel2)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        jPanel1Layout.setVerticalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addGap(38, 38, 38)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(reporterName, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel1)
                    .addComponent(jLabel2))
                .addContainerGap(495, Short.MAX_VALUE))
        );

        reporterName.getDocument().addDocumentListener(new DocumentListener() {
            public void changedUpdate(DocumentEvent e) {
                reporterNameChanged();
            }
            public void removeUpdate(DocumentEvent e) {
                reporterNameChanged();
            }
            public void insertUpdate(DocumentEvent e) {
                reporterNameChanged();
            }
        });

        jTabbedPane1.addTab("Options", jPanel1);

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jTabbedPane1, javax.swing.GroupLayout.Alignment.TRAILING)
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jTabbedPane1)
        );

        jTabbedPane1.getAccessibleContext().setAccessibleName("Issue");
    }// </editor-fold>//GEN-END:initComponents

    private void parameterTextFieldActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_parameterTextFieldActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_parameterTextFieldActionPerformed

    @SuppressWarnings("unchecked")
    private void auditChanger(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_auditChanger
         try {
            if (evt.getStateChange() == ItemEvent.SELECTED) {
                JComboBox projBox = (JComboBox) evt.getSource();
                // because of the auto complete we might not get an valid index
                if (projBox.getSelectedIndex() != -1) {
                    //projectByName
                    Project p = (Project) db.projectByName((String) projBox.getSelectedItem());
                    List<String> audits = db.getAudits(p.id);
                    audits.add(audits.size(), " ");  // used when we don't want an audit
                    auditModel = new DefaultComboBoxModel<>(audits.toArray());

                    auditComboBox.removeAllItems();
                    auditComboBox.setModel(auditModel);
                    auditComboBox.setSelectedIndex(-1);
                }
            }
        } catch (Exception ex) {
            log.err("failed to get audits by project", ex);
        }
    }//GEN-LAST:event_auditChanger

    @SuppressWarnings("unchecked")
    private void vulnerabilityChanger(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_vulnerabilityChanger
        try {
            if (evt.getStateChange() == ItemEvent.SELECTED) {
                JComboBox catBox = (JComboBox) evt.getSource();
                VulnerabilityCategory cat = (VulnerabilityCategory) db.vulnerabilityCategoryByIndex(catBox.getSelectedIndex());
                vulnsModel = new DefaultComboBoxModel<>(db.getVulnerabilities(cat.id));

                vulnerabilityComboBox.removeAllItems();
                vulnerabilityComboBox.setModel(vulnsModel);
            }
        } catch (Exception ex) {
            log.err("failed to get vulnerabilities by category", ex);
        }
    }//GEN-LAST:event_vulnerabilityChanger

    private void createIssue(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_createIssue
        log.log("handling submit");
        
        String reporter = iburp.loadExtensionSetting("reporterName");
        if (reporter == null || reporter.isEmpty()) {
            JOptionPane.showMessageDialog(panel, "Reporter Name is mandatory", REQUIRED_TITLE, JOptionPane.WARNING_MESSAGE);
            return;
        }

        // get user selection


        Project project = (Project) db.projectByIndex(projectComboBox.getSelectedIndex());
        Audit audit = (Audit) db.auditByIndex(auditComboBox.getSelectedIndex());

        Vulnerability vulnerability = (Vulnerability) db.vulnerabilityByIndex(vulnerabilityComboBox.getSelectedIndex());

        // verify if we have all the parameters
        if (severity == null) {
            JOptionPane.showMessageDialog(panel, "Severity is required", REQUIRED_TITLE, JOptionPane.WARNING_MESSAGE);
        }
        if (project == null) {
            JOptionPane.showMessageDialog(panel, "Project is required", REQUIRED_TITLE, JOptionPane.WARNING_MESSAGE);
        } 
        if (vulnerability == null) {
            JOptionPane.showMessageDialog(panel, "Vulnerability is required", REQUIRED_TITLE, JOptionPane.WARNING_MESSAGE);
        }
        if (source == null) {
            JOptionPane.showMessageDialog(panel, "Source is required", REQUIRED_TITLE, JOptionPane.WARNING_MESSAGE);
        }
        if (severity == null || source == null || project == null || vulnerability == null) {
            return;
        }
        
        Issue issue;
        try {
            // create the issue representation
            issue = new Issue(requestViewer.getMessage(), responseViewer.getMessage(), 
                    reqInfo, severity, source, project, audit, vulnerability,
                    informationTextArea.getText(), parameterTextField.getText(), privateInformationTextArea.getText());
         } catch (Exception ex) {
            feedbackLabel.setText("failed: missing request/response");
            feedbackLabel.setForeground(new Color(210, 39, 30));
            issueUrlButton.setVisible(false);
            log.err("failed: missing request/response: " + ex.getMessage(), ex);
            return;
        }
        
        try {
            db.sendIssue(issue);

            // if everything went well, anounce that
            feedbackLabel.setText("Issue created");
            issueUrlButton.setVisible(true);

            String url = db.urlForIssue(issue.id);
            log.log("new url " + url);
            issueUrlButton.setText(url);
            urlButtonListener.setUrl(url);
        } catch (IssueDuplicateException ex) {
            feedbackLabel.setText("failed to create the issue: " + ex.getMessage());
            feedbackLabel.setForeground(new Color(210, 39, 30));
            issueUrlButton.setVisible(false);
        } catch (Exception ex) {
            feedbackLabel.setText("failed to create the issue: " + ex.getMessage());
            feedbackLabel.setForeground(new Color(210, 39, 30));
            issueUrlButton.setVisible(false);
            log.err("failed to create issue: " + ex.getMessage(), ex);
        }
    }//GEN-LAST:event_createIssue

    private void refreshButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_refreshButtonActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_refreshButtonActionPerformed

    private void reconnect(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_reconnect
        fillComboBoxes();
    }//GEN-LAST:event_reconnect

    private void getExtendedInfo(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_getExtendedInfo
        String requestText = "";
        String responseText = "";

        try {
            if (httpMessage instanceof IHttpRequestResponseWithMarkers) {

                if (requestViewer.isMessageModified()) {
                    JOptionPane.showMessageDialog(panel, "This request has been modified.\nMarkers cannot be read.", REQUIRED_TITLE, JOptionPane.WARNING_MESSAGE);
                }
                else {
                    for (String marker : HttpMessage.getExtendedRequestMarkers((IHttpRequestResponseWithMarkers) httpMessage)) {
                        requestText += "\n" + marker;
                    }
                    requestText = requestText.length() > 0 ? "Request details:\n" + requestText : "";
                }

                if (responseViewer.isMessageModified()) {
                    JOptionPane.showMessageDialog(panel, "This response has been modified.\nMarkers cannot be read.", REQUIRED_TITLE, JOptionPane.WARNING_MESSAGE);
                }
                else {
                    for (String marker : HttpMessage.getExtendedResponseMarkers((IHttpRequestResponseWithMarkers) httpMessage)) {
                        responseText += "\n" + marker;
                    }
                    responseText = responseText.length() > 0 ? "Response details:\n" + responseText : "";
                }
                
                informationTextArea.setText(requestText + responseText);
            }
            else {
                JOptionPane.showMessageDialog(panel, "This request has no markers", REQUIRED_TITLE, JOptionPane.WARNING_MESSAGE);
            }
        } catch (Exception ex) {
            log.err(ex);
        }
    }//GEN-LAST:event_getExtendedInfo

    private void reporterNameActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_reporterNameActionPerformed
        
    }//GEN-LAST:event_reporterNameActionPerformed

    private void reporterNameChanged() {
        String text = reporterName.getText();
        if (text == null || text.isEmpty()) {
            JOptionPane.showMessageDialog(panel, "Reporter Name is mandatory", REQUIRED_TITLE, JOptionPane.WARNING_MESSAGE);
        }
        else {
            iburp.saveExtensionSetting("reporterName", text);
        }
    }
    
    private void jButton1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton1ActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_jButton1ActionPerformed

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JComboBox auditComboBox;
    private javax.swing.JLabel auditLabel;
    private javax.swing.JComboBox categoryComboBox;
    private javax.swing.JLabel categoryLabel;
    private javax.swing.JButton extendedInfoButton;
    private javax.swing.JLabel feedbackLabel;
    private javax.swing.JLabel informationLabel;
    private javax.swing.JTextArea informationTextArea;
    private javax.swing.JButton issueUrlButton;
    private javax.swing.JButton jButton1;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JTabbedPane jTabbedPane1;
    private javax.swing.JSplitPane panel;
    private javax.swing.JLabel parameterLabel;
    private javax.swing.JTextField parameterTextField;
    private javax.swing.JLabel privateInformationLabel;
    private javax.swing.JTextArea privateInformationTextArea;
    private javax.swing.JComboBox projectComboBox;
    private javax.swing.JLabel projectLabel;
    private javax.swing.JButton refreshButton;
    private javax.swing.JTextField reporterName;
    private javax.swing.JTabbedPane requestResponsePane;
    private javax.swing.JComboBox severityComboBox;
    private javax.swing.JLabel severityLabel;
    private javax.swing.JComboBox sourceComboBox;
    private javax.swing.JLabel sourceLabel;
    private javax.swing.JPanel topPane;
    private javax.swing.JComboBox vulnerabilityComboBox;
    private javax.swing.JLabel vulnerabilityLabel;
    // End of variables declaration//GEN-END:variables

    @Override
    public void actionPerformed(ActionEvent e) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public String getTabCaption()
    {
        return "DB";
    }

    @Override
    public Component getUiComponent()
    {
        return this;
    }

    @Override
    public byte[] getRequest()
    {
        return httpMessage.getRequest();
    }

    @Override
    public byte[] getResponse()
    {
        return httpMessage.getResponse();
    }

    @Override
    public IHttpService getHttpService()
    {
        return httpMessage.getHttpService();
    }
    
    private void fillOptionTab() {
        String text = iburp.loadExtensionSetting("reporterName");
        if (text == null || text.isEmpty()) {
            iburp.issueAlert("Reporter Name is empty");
        }
        else {
            reporterName.setText(text);
        }
    }

    @SuppressWarnings("unchecked")
    private void fillComboBoxes() {
        try {
            if (projectAutoComplete != null) {
                EventList itemList = projectAutoComplete.getItemList();
                itemList.clear();
            }
            
                       
            categoryComboBox.setModel(new DefaultComboBoxModel<>(db.getCategories()));
            severityComboBox.setModel(new DefaultComboBoxModel<>(db.getSeverities()));
            sourceComboBox.setModel(new DefaultComboBoxModel<>(db.getSources()));
            projectComboBox.setSelectedItem(null);
            auditComboBox.setSelectedItem(null);
            categoryComboBox.setSelectedItem(null);
            vulnerabilityComboBox.setSelectedItem(null);
            severityComboBox.setSelectedItem(null);
            sourceComboBox.setSelectedItem(null);
        } catch (IOException ex) {
            log.err(ex);
        }
    }


    @Override
    public List<JMenuItem> createMenuItems(final IContextMenuInvocation invocation) {
        JMenuItem sendToDBMenu = new JMenuItem("send to db");
        sendToDBMenu.addMouseListener(new MouseListener() {
            @Override
            public void mousePressed(MouseEvent me) {
                try {
                    menuRightClicked(invocation);
                } catch (UnsupportedEncodingException ex) {
                    JOptionPane.showMessageDialog(panel, "HTTP message has non UTF-8 chars", REQUIRED_TITLE, JOptionPane.WARNING_MESSAGE);
                }
            }

            @Override
            public void mouseClicked(MouseEvent me) {
            }

            @Override
            public void mouseReleased(MouseEvent me) {
            }

            @Override
            public void mouseEntered(MouseEvent me) {
            }

            @Override
            public void mouseExited(MouseEvent me) {
            }
        });

        List<JMenuItem> menus = new ArrayList<>();
        menus.add(sendToDBMenu);
        return menus;

    }

    private void menuRightClicked(IContextMenuInvocation invocation) throws UnsupportedEncodingException {
        IHttpRequestResponse[] messageInfo = null;
        

        if (invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_SCANNER_RESULTS) {
            IScanIssue[] issues = invocation.getSelectedIssues();
            if (issues.length > 1) {
                JOptionPane.showMessageDialog(panel, "Select only one issue", REQUIRED_TITLE, JOptionPane.WARNING_MESSAGE);
            } else {
                setIssueInfo(issues[0]);
            }
        } else { // clicked outside the scanner
            messageInfo = invocation.getSelectedMessages();

            if (messageInfo.length > 1) {
                JOptionPane.showMessageDialog(panel, "Select only one request", REQUIRED_TITLE, JOptionPane.WARNING_MESSAGE);
            } else {
                // got custom selection?
                int[] bounds = invocation.getSelectionBounds();
                if (bounds != null && bounds[0] != bounds[1]) {
                    // clicked in the request or response?
                    log.log("custom bounds");
                    switch (invocation.getInvocationContext()) {
                        case IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST:
                            setCustomIssueInfo(messageInfo[0], bounds, true);
                            break;
                        case IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE:
                            setCustomIssueInfo(messageInfo[0], bounds, false);
                            break;
                    }
                } else {
                    log.log("no custom selection");
                    setIssueInfo(messageInfo[0]);
                }
            }
        }
    }
}
