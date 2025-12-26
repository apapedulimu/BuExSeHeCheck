import burp.*;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.util.*;
import java.util.List;

public class BuExSeHeCheck implements IBurpExtender, ITab, IContextMenuFactory {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    private JPanel mainPanel;

    private IMessageEditor requestViewer;
    private IMessageEditor responseViewer;

    private JTextPane resultPane;

    private HeaderTableModel headerModel;

    // =========================
    // BURP ENTRY POINT
    // =========================
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {

        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();

        callbacks.setExtensionName("BuExSeHeCheck");

        buildUI();

        callbacks.addSuiteTab(this);
        callbacks.registerContextMenuFactory(this);

        callbacks.printOutput("BuExSeHeCheck loaded successfully");
    }

    // =========================
    // UI
    // =========================
    private void buildUI() {

        mainPanel = new JPanel(new BorderLayout());

        // ===== Security Header Table =====
        headerModel = new HeaderTableModel();
        JTable headerTable = new JTable(headerModel);
        JScrollPane headerScroll = new JScrollPane(headerTable);

        JButton addHeaderBtn = new JButton("Add Header");
        JButton removeHeaderBtn = new JButton("Remove Selected");

        addHeaderBtn.addActionListener(e -> {
            String h = JOptionPane.showInputDialog(mainPanel, "Header name:");
            if (h != null && !h.trim().isEmpty()) {
                headerModel.addHeader(h.trim());
            }
        });

        removeHeaderBtn.addActionListener(e -> {
            int row = headerTable.getSelectedRow();
            if (row >= 0) {
                headerModel.removeHeader(row);
            }
        });

        JPanel headerBtnPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        headerBtnPanel.add(addHeaderBtn);
        headerBtnPanel.add(removeHeaderBtn);

        JPanel headerPanel = new JPanel(new BorderLayout());
        headerPanel.setBorder(BorderFactory.createTitledBorder("Security Headers"));
        headerPanel.add(headerScroll, BorderLayout.CENTER);
        headerPanel.add(headerBtnPanel, BorderLayout.SOUTH);

        // ===== Request / Response =====
        requestViewer = callbacks.createMessageEditor(null, false);
        responseViewer = callbacks.createMessageEditor(null, false);

        JSplitPane messageSplit = new JSplitPane(
                JSplitPane.HORIZONTAL_SPLIT,
                wrap("Request", requestViewer.getComponent()),
                wrap("Response", responseViewer.getComponent())
        );
        messageSplit.setResizeWeight(0.5);

        // ===== Results =====
        resultPane = new JTextPane();
        resultPane.setEditable(false);
        resultPane.setContentType("text/html");
        resultPane.setFont(new Font("Monospaced", Font.PLAIN, 12));

        JScrollPane resultScroll = new JScrollPane(resultPane);

        JButton clearBtn = new JButton("Clear Results");
        clearBtn.addActionListener(e -> clearAll());

        JPanel resultPanel = new JPanel(new BorderLayout());
        resultPanel.setBorder(new EmptyBorder(5, 5, 5, 5));
        resultPanel.add(resultScroll, BorderLayout.CENTER);
        resultPanel.add(clearBtn, BorderLayout.SOUTH);

        // ===== Message + Results split =====
        JSplitPane messageResultSplit = new JSplitPane(
                JSplitPane.VERTICAL_SPLIT,
                messageSplit,
                resultPanel
        );
        messageResultSplit.setResizeWeight(0.65);

        // ===== Header + Main Content split =====
        JSplitPane headerMainSplit = new JSplitPane(
                JSplitPane.VERTICAL_SPLIT,
                headerPanel,
                messageResultSplit
        );
        headerMainSplit.setResizeWeight(0.25);
        headerMainSplit.setOneTouchExpandable(true);

        mainPanel.add(headerMainSplit, BorderLayout.CENTER);
    }

    private JPanel wrap(String title, Component c) {
        JPanel p = new JPanel(new BorderLayout());
        p.setBorder(BorderFactory.createTitledBorder(title));
        p.add(c, BorderLayout.CENTER);
        return p;
    }

    private void clearAll() {

        resultPane.setText("");
        resultPane.setCaretPosition(0);

        requestViewer.setMessage(new byte[0], true);
        responseViewer.setMessage(new byte[0], false);
    }

    // =========================
    // TAB
    // =========================
    @Override
    public String getTabCaption() {
        return "Sec Headers";
    }

    @Override
    public Component getUiComponent() {
        return mainPanel;
    }

    // =========================
    // CONTEXT MENU
    // =========================
    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {

        IHttpRequestResponse[] messages = invocation.getSelectedMessages();
        if (messages == null || messages.length == 0) {
            return null;
        }

        JMenuItem item = new JMenuItem("Send to BuExSeHeCheck");
        item.addActionListener(e -> analyze(messages[0]));

        return Collections.singletonList(item);
    }

    // =========================
    // ANALYSIS
    // =========================
    private void analyze(IHttpRequestResponse message) {

        requestViewer.setMessage(message.getRequest(), true);
        responseViewer.setMessage(message.getResponse(), false);

        IResponseInfo respInfo = helpers.analyzeResponse(message.getResponse());

        Map<String, String> respHeaders = new HashMap<>();
        for (String h : respInfo.getHeaders()) {
            int i = h.indexOf(":");
            if (i > 0) {
                respHeaders.put(h.substring(0, i).trim(), h.substring(i + 1).trim());
            }
        }

        String url = helpers.analyzeRequest(message).getUrl().toString();

        StringBuilder html = new StringBuilder();
        html.append("<html><body style='font-family:monospace;'>");
        html.append("<b>======================================================</b><br>");
        html.append("<b>BuExSeHeCheck – Security Header Checker</b><br>");
        html.append("<b>======================================================</b><br><br>");
        html.append("<b>Analyzing:</b> ").append(url).append("<br><br>");

        int present = 0, missing = 0;

        for (String header : headerModel.getHeaders()) {
            String value = respHeaders.get(header);

            if (value == null) {
                html.append("<span style='color:red;'>[!] Missing security header: ")
                        .append(header).append("</span><br>");
                missing++;
            } else {
                html.append("<span style='color:green;'>[*] Header ")
                        .append(header).append(" is present</span><br>");

                html.append("<div style='margin-left:20px;color:#999;'>");
                if (header.equalsIgnoreCase("Content-Security-Policy")) {
                    for (String part : value.split(";")) {
                        html.append(part.trim()).append("<br>");
                    }
                } else {
                    html.append(value);
                }
                html.append("</div>");
                present++;
            }
        }

        html.append("<br><b>------------------------------------------------------</b><br>");
        html.append("[+] Present: ").append(present).append("<br>");
        html.append("[-] Missing: ").append(missing).append("<br>");
        html.append("</body></html>");

        resultPane.setText(html.toString());
        resultPane.setCaretPosition(0);
    }

    // =========================
    // HEADER TABLE MODEL
    // =========================
    private static class HeaderTableModel extends AbstractTableModel {

        private final java.util.List<String> headers = new ArrayList<>(Arrays.asList(
                "X-Frame-Options",
                "X-Content-Type-Options",
                "Strict-Transport-Security",
                "Content-Security-Policy",
                "Referrer-Policy",
                "Permissions-Policy",
                "Cross-Origin-Embedder-Policy",
                "Cross-Origin-Resource-Policy",
                "Cross-Origin-Opener-Policy"
        ));

        @Override
        public int getRowCount() {
            return headers.size();
        }

        @Override
        public int getColumnCount() {
            return 1;
        }

        @Override
        public String getColumnName(int column) {
            return "Header Name";
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            return headers.get(rowIndex);
        }

        public void addHeader(String h) {
            headers.add(h);
            fireTableDataChanged();
        }

        public void removeHeader(int row) {
            headers.remove(row);
            fireTableDataChanged();
        }

        public java.util.List<String> getHeaders() {
            return headers;
        }
    }
}
