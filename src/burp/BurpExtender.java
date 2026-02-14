package burp;

import javax.swing.*;
import java.awt.*;
import java.io.*;
import java.net.URL;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributeView;
import java.nio.file.attribute.FileTime;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.List;
import java.util.zip.GZIPInputStream;
import java.util.zip.InflaterInputStream;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.proxy.ProxyWebSocketMessage;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.WebSocketContextMenuEvent;
import burp.api.montoya.ui.contextmenu.WebSocketMessage;
import burp.api.montoya.websocket.Direction;

/**
 * BurpDump - Burp Suite extension that exports selected HTTP history
 * items (and captured WebSocket frames) to the filesystem, preserving
 * the URL path structure with second-level domain grouping.
 *
 * Output layout (relative to the chosen directory):
 *   ./{group}/{host}/{path}              - response body (decompressed if needed)
 *   ./{group}/{host}/{path}.response     - response headers
 *   ./{group}/{host}/{path}.request      - request headers only
 *   ./{group}/{host}/{path}.request.data - request body (if present, decompressed)
 *
 * WebSocket frame layout:
 *   ./{group}/{host}/{path}#ws.{id}.send  - client-to-server frame
 *   ./{group}/{host}/{path}#ws.{id}.recv  - server-to-client frame
 */
public class BurpExtender implements IBurpExtender, IContextMenuFactory,
        IProxyListener, IHttpListener,
        BurpExtension, ContextMenuItemsProvider {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private MontoyaApi montoyaApi;
    private File lastExportDir;

    private String version   = "dev";
    private String buildDate = "";

    /* ================================================================== */
    /*  WebSocket frame storage                                           */
    /* ================================================================== */

    private final List<WsFrame> wsFrames =
            Collections.synchronizedList(new ArrayList<WsFrame>());
    private long lastWsSecond  = 0;
    private int  wsSubCounter  = 0;

    /** Represents a single WebSocket send / receive captured via proxy. */
    private static class WsFrame {
        final String  host;
        final int     port;
        final String  path;
        final boolean isSend;    // true = client-to-server
        final byte[]  payload;
        final long    timestampMillis;
        final long    uniqueId;  // seconds*1000 + sub-counter

        WsFrame(String host, int port, String path,
                boolean isSend, byte[] payload,
                long timestampMillis, long uniqueId) {
            this.host            = host;
            this.port            = port;
            this.path            = path;
            this.isSend          = isSend;
            this.payload         = payload;
            this.timestampMillis = timestampMillis;
            this.uniqueId        = uniqueId;
        }
    }

    /** Generate a unique, monotonically-growing ID within each second. */
    private synchronized long nextWsUniqueId(long timestampMillis) {
        long sec = timestampMillis / 1000;
        if (sec != lastWsSecond) {
            lastWsSecond = sec;
            wsSubCounter = 0;
        }
        long id = sec * 1000 + wsSubCounter;
        wsSubCounter++;
        return id;
    }

    /* ================================================================== */
    /*  Burp entry point                                                  */
    /* ================================================================== */

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers   = callbacks.getHelpers();
        loadBuildInfo();
        try {
            String saved = callbacks.loadExtensionSetting("lastExportDir");
            if (saved != null && !saved.isEmpty()) {
                File f = new File(saved);
                if (f.isDirectory()) lastExportDir = f;
            }
        } catch (Exception ignored) { }
        callbacks.setExtensionName("BurpDump v" + version);
        callbacks.registerContextMenuFactory(this);

        // Register listeners for passive WebSocket capture.
        // Both interfaces are part of the official Burp legacy API.
        try { callbacks.registerProxyListener(this); }
        catch (Throwable t) {
            callbacks.printError("Could not register proxy listener: " + t);
        }
        try { callbacks.registerHttpListener(this); }
        catch (Throwable t) {
            callbacks.printError("Could not register HTTP listener: " + t);
        }

        callbacks.printOutput("BurpDump v" + version + " loaded."
                + (buildDate.isEmpty() ? "" : "  (built " + buildDate + ")"));
    }

    private void loadBuildInfo() {
        try (InputStream is = getClass().getResourceAsStream("/burp/build-info.properties")) {
            if (is != null) {
                Properties props = new Properties();
                props.load(is);
                version   = props.getProperty("version",    version);
                buildDate = props.getProperty("build.date", buildDate);
            }
        } catch (Exception ignored) { }
    }

    /* ================================================================== */
    /*  Montoya API entry point (Burp 2023.1+)                            */
    /* ================================================================== */

    /**
     * Called by Burp when the Montoya API is available.
     * Registers a {@link ContextMenuItemsProvider} so that BurpDump
     * appears in the <b>WebSocket History</b> context menu.
     */
    @Override
    public void initialize(MontoyaApi api) {
        this.montoyaApi = api;
        try {
            api.userInterface().registerContextMenuItemsProvider(this);
        } catch (Throwable t) {
            if (callbacks != null)
                callbacks.printError("Montoya context-menu registration failed: " + t);
            return;
        }
        if (callbacks != null) {
            callbacks.printOutput("BurpDump: Montoya API initialized "
                    + "(WebSocket context menu enabled)");
        }
    }

    /* ================================================================== */
    /*  Montoya WebSocket context menu                                    */
    /* ================================================================== */

    /**
     * Invoked by Burp when the user right-clicks inside WebSocket History.
     * Provides menu items to export selected / all WebSocket messages.
     */
    @Override
    public List<Component> provideMenuItems(WebSocketContextMenuEvent event) {
        List<WebSocketMessage> selected = event.selectedWebSocketMessages();
        List<Component> items = new ArrayList<>();

        if (selected != null && !selected.isEmpty()) {
            JMenuItem mi = new JMenuItem(
                    "Export " + selected.size()
                            + " WebSocket message(s)");
            mi.addActionListener(e -> onExportMontoyaWsSelected(selected));
            items.add(mi);
        }

        if (montoyaApi != null) {
            JMenuItem allMi = new JMenuItem(
                    "Export all WebSocket history");
            allMi.addActionListener(e -> onExportMontoyaWsAll());
            items.add(allMi);
        }

        {
            JMenuItem allMi = new JMenuItem(
                    "Export all (HTTP + WebSocket)");
            allMi.addActionListener(e -> onExportEverything());
            items.add(allMi);
        }

        return items;
    }

    /* ================================================================== */
    /*  Montoya WebSocket export                                          */
    /* ================================================================== */

    /** Export WebSocket messages selected in the Montoya context menu. */
    private void onExportMontoyaWsSelected(
            final List<WebSocketMessage> messages) {

        callbacks.printOutput("onExportMontoyaWsSelected: " + messages.size()
                + " messages, showing directory chooser");
        final File baseDir = chooseExportDirectory(
                "BurpDump - WebSocket export directory");
        if (baseDir == null) {
            callbacks.printOutput("onExportMontoyaWsSelected: user cancelled directory chooser");
            return;
        }
        callbacks.printOutput("onExportMontoyaWsSelected: dir=" + baseDir);

        JFrame owner = findBurpFrame();
        final int total = messages.size();

        JDialog dialog = new JDialog(owner,
                "BurpDump - WebSocket export", false);
        dialog.setDefaultCloseOperation(JDialog.DO_NOTHING_ON_CLOSE);

        JProgressBar bar = new JProgressBar(0, total);
        bar.setStringPainted(true);
        bar.setString("0 / " + total);
        bar.setPreferredSize(new Dimension(420, 26));

        JLabel label = new JLabel("Starting WebSocket export...");
        label.setBorder(BorderFactory.createEmptyBorder(0, 0, 6, 0));
        JButton cancelBtn = new JButton("Cancel");

        JPanel panel = new JPanel(new BorderLayout(8, 8));
        panel.setBorder(BorderFactory.createEmptyBorder(12, 16, 12, 16));
        panel.add(label, BorderLayout.NORTH);
        panel.add(bar,   BorderLayout.CENTER);
        JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 0, 0));
        btnPanel.add(cancelBtn);
        panel.add(btnPanel, BorderLayout.SOUTH);

        dialog.setContentPane(panel);
        dialog.setResizable(false);
        dialog.pack();
        dialog.setLocationRelativeTo(owner);

        final List<String> errors = new ArrayList<String>();

        SwingWorker<int[], Object[]> worker = new SwingWorker<int[], Object[]>() {
            @Override
            protected int[] doInBackground() {
                callbacks.printOutput("WS worker started, processing " + messages.size() + " messages...");
                int ok = 0, fail = 0;
                for (int i = 0; i < messages.size(); i++) {
                    if (isCancelled()) break;
                    WebSocketMessage msg = messages.get(i);
                    String desc = "(ws) " + (i + 1);
                    try {
                        URL u = new URL(msg.upgradeRequest().url());
                        String s = u.getHost() + u.getPath();
                        desc = s.length() > 80 ? s.substring(0, 77) + "..." : s;
                    } catch (Throwable t) {
                        callbacks.printError("WS describe error #" + (i+1) + ": " + t);
                    }
                    publish(new Object[]{ i, desc });
                    try {
                        exportMontoyaWsMessage(msg, baseDir);
                        ok++;
                    } catch (Throwable ex) {
                        fail++;
                        String detail = desc + " - " + ex.getClass().getName()
                                + ": " + ex.getMessage();
                        errors.add(detail);
                        if (fail <= 3) callbacks.printError("WS export fail #" + fail + ": " + detail);
                    }
                }
                callbacks.printOutput("WS worker done: ok=" + ok + " fail=" + fail);
                return new int[]{ ok, fail };
            }

            @Override
            protected void process(List<Object[]> chunks) {
                Object[] last = chunks.get(chunks.size() - 1);
                int idx     = (int) last[0];
                String desc = (String) last[1];
                bar.setValue(idx + 1);
                bar.setString((idx + 1) + " / " + total);
                label.setText(desc);
            }

            @Override
            protected void done() {
                dialog.dispose();
                try {
                    if (isCancelled()) {
                        callbacks.printOutput("WS export cancelled.");
                        return;
                    }
                    int[] r = get();
                    String msg = String.format(
                            "Exported %d WebSocket message(s), %d error(s).",
                            r[0], r[1]);
                    showExportResult(owner, msg, errors);
                } catch (Exception ex) {
                    callbacks.printError("Error: " + ex);
                }
            }
        };

        cancelBtn.addActionListener(e -> worker.cancel(false));
        dialog.addWindowListener(new java.awt.event.WindowAdapter() {
            @Override
            public void windowClosing(java.awt.event.WindowEvent e) {
                worker.cancel(false);
            }
        });

        worker.execute();
        dialog.setVisible(true);
    }

    /** Export the entire Proxy WebSocket history via Montoya API. */
    private void onExportMontoyaWsAll() {
        try {
            onExportMontoyaWsAllImpl();
        } catch (Throwable ex) {
            String detail = ex.getClass().getName() + ": " + ex.getMessage();
            try { callbacks.printError("onExportMontoyaWsAll fatal: " + detail); }
            catch (Throwable ignored) { }
            JOptionPane.showMessageDialog(findBurpFrame(),
                    "Unexpected error in Export all WS:\n" + detail,
                    "BurpDump", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void onExportMontoyaWsAllImpl() {
        if (montoyaApi == null) {
            callbacks.printError("onExportMontoyaWsAll: montoyaApi is null");
            JOptionPane.showMessageDialog(findBurpFrame(),
                    "Montoya API is not available.\n"
                            + "Your Burp version may not support this feature.",
                    "BurpDump", JOptionPane.ERROR_MESSAGE);
            return;
        }
        callbacks.printOutput("onExportMontoyaWsAll: requesting webSocketHistory()");
        List<ProxyWebSocketMessage> history;
        try {
            history = montoyaApi.proxy().webSocketHistory();
        } catch (Throwable ex) {
            callbacks.printError("Cannot read WS history: " + ex);
            JOptionPane.showMessageDialog(findBurpFrame(),
                    "Could not read WebSocket History:\n" + ex
                            + "\n\nYour Burp version may not support this API.\n"
                            + "Try exporting selected messages instead.",
                    "BurpDump", JOptionPane.ERROR_MESSAGE);
            return;
        }
        callbacks.printOutput("onExportMontoyaWsAll: got " + (history == null ? "null" : history.size()) + " messages");
        if (history == null || history.isEmpty()) {
            JOptionPane.showMessageDialog(findBurpFrame(),
                    "WebSocket history is empty.", "BurpDump",
                    JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        // ProxyWebSocketMessage extends WebSocketMessage
        List<WebSocketMessage> list = new ArrayList<WebSocketMessage>();
        for (ProxyWebSocketMessage m : history) list.add(m);
        callbacks.printOutput("onExportMontoyaWsAll: launching export of " + list.size() + " messages...");
        onExportMontoyaWsSelected(list);
    }

    /** Write a single Montoya WebSocketMessage to disk via exportWsFrame. */
    private void exportMontoyaWsMessage(WebSocketMessage msg, File baseDir)
            throws Exception {
        String urlStr = msg.upgradeRequest().url();
        URL url = new URL(urlStr);

        String host = url.getHost();
        int port    = url.getPort();
        String path = url.getPath();
        if (path == null || path.isEmpty()) path = "/";

        boolean isSend = (msg.direction() == Direction.CLIENT_TO_SERVER);
        byte[] payload = msg.payload() != null
                ? msg.payload().getBytes() : new byte[0];

        long timestamp = System.currentTimeMillis();
        if (msg instanceof ProxyWebSocketMessage) {
            try {
                java.time.ZonedDateTime time =
                        ((ProxyWebSocketMessage) msg).time();
                if (time != null)
                    timestamp = time.toInstant().toEpochMilli();
            } catch (Throwable ignored) { }  // NoSuchMethodError in older Burp
        }

        long id = nextWsUniqueId(timestamp);
        WsFrame frame = new WsFrame(host, port, path,
                isSend, payload, timestamp, id);
        exportWsFrame(frame, baseDir);
    }

    /* ================================================================== */
    /*  Proxy & HTTP listeners - passive WebSocket capture                */
    /* ================================================================== */

    @Override
    public void processProxyMessage(boolean messageIsRequest,
                                    IInterceptedProxyMessage message) {
        try {
            IHttpRequestResponse msgInfo = message.getMessageInfo();
            handleMessage(messageIsRequest, msgInfo);
        } catch (Exception ignored) { }
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest,
                                   IHttpRequestResponse messageInfo) {
        try {
            handleMessage(messageIsRequest, messageInfo);
        } catch (Exception ignored) { }
    }

    /**
     * Inspect every proxy / HTTP-listener message:
     *   - if the response is "101 Switching Protocols" with "Upgrade: websocket"
     *     we log the WebSocket connection so the user sees it.
     *   - individual WebSocket frames are NOT exposed by the Burp legacy
     *     extension API; they would need the Montoya API.  The capture
     *     infrastructure is in place so that frames can be added from an
     *     alternative source if needed.
     */
    private void handleMessage(boolean messageIsRequest,
                               IHttpRequestResponse msgInfo) {
        if (messageIsRequest) return;          // only look at responses
        byte[] response = msgInfo.getResponse();
        if (response == null) return;

        IResponseInfo ri = helpers.analyzeResponse(response);
        if (ri.getStatusCode() != 101) return;

        String upgrade = findHeaderValue(ri.getHeaders(), "Upgrade");
        if (upgrade == null || !upgrade.toLowerCase().contains("websocket")) return;

        // WebSocket upgrade detected - log for the user.
        try {
            IRequestInfo reqInfo = helpers.analyzeRequest(msgInfo);
            URL url = reqInfo.getUrl();
            callbacks.printOutput("WebSocket upgrade detected: " + url);
        } catch (Exception ignored) { }
    }

    /**
     * Public helper so that external code (e.g. a Montoya-based adapter)
     * can feed captured WebSocket frames into this extension's storage.
     */
    public void addWebSocketFrame(String host, int port, String path,
                                  boolean isSend, byte[] payload,
                                  long timestampMillis) {
        long id = nextWsUniqueId(timestampMillis);
        wsFrames.add(new WsFrame(host, port, path, isSend, payload,
                timestampMillis, id));
    }

    /* ================================================================== */
    /*  Context menu                                                      */
    /* ================================================================== */

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<JMenuItem> items = new ArrayList<>();

        IHttpRequestResponse[] messages = invocation.getSelectedMessages();
        byte ctx = invocation.getInvocationContext();

        if (messages != null && messages.length > 0) {
            final IHttpRequestResponse[] selected = messages;
            final byte context = ctx;
            JMenuItem mi = new JMenuItem(
                    "Save " + messages.length + " item(s)");
            mi.addActionListener(e -> onExport(selected, context));
            items.add(mi);
        }

        // Bulk-export items — only in list-like contexts (not in
        // single-message editors/viewers such as Repeater).
        boolean bulkContext = ctx >= IContextMenuInvocation.CONTEXT_TARGET_SITE_MAP_TREE;

        // WebSocket export (if frames have been captured)
        if (bulkContext) {
            synchronized (wsFrames) {
                if (!wsFrames.isEmpty()) {
                    int n = wsFrames.size();
                    JMenuItem ws = new JMenuItem(
                            "Export " + n + " WebSocket message(s)");
                    ws.addActionListener(e -> onExportWebSocket());
                    items.add(ws);
                }
            }
        }

        // Export entire proxy HTTP history
        if (bulkContext) {
            JMenuItem allHttp = new JMenuItem(
                    "Export all Proxy History");
            allHttp.addActionListener(e -> onExportAllHttpHistory());
            items.add(allHttp);
        }

        // Export everything (HTTP + WebSocket)
        if (bulkContext) {
            JMenuItem allMi = new JMenuItem(
                    "Export all (HTTP + WebSocket)");
            allMi.addActionListener(e -> onExportEverything());
            items.add(allMi);
        }

        return items;
    }

    /* ================================================================== */
    /*  Combined HTTP + WebSocket export                                  */
    /* ================================================================== */

    /** Export all Proxy HTTP History and all WebSocket history in one go. */
    private void onExportEverything() {
        // Gather HTTP history
        IHttpRequestResponse[] httpHistory = null;
        try {
            httpHistory = callbacks.getProxyHistory();
        } catch (Throwable ex) {
            callbacks.printError("Cannot read proxy history: " + ex);
        }
        final IHttpRequestResponse[] http =
                (httpHistory != null && httpHistory.length > 0) ? httpHistory : null;

        // Gather WS history via Montoya
        List<ProxyWebSocketMessage> wsHistory = null;
        if (montoyaApi != null) {
            try {
                wsHistory = montoyaApi.proxy().webSocketHistory();
            } catch (Throwable ex) {
                callbacks.printError("Cannot read WS history: " + ex);
            }
        }
        final List<WebSocketMessage> ws;
        if (wsHistory != null && !wsHistory.isEmpty()) {
            ws = new ArrayList<WebSocketMessage>();
            for (ProxyWebSocketMessage m : wsHistory) ws.add(m);
        } else {
            ws = null;
        }

        int httpCount = http != null ? http.length : 0;
        int wsCount   = ws   != null ? ws.size()   : 0;
        if (httpCount == 0 && wsCount == 0) {
            JOptionPane.showMessageDialog(findBurpFrame(),
                    "Both Proxy HTTP and WebSocket histories are empty.",
                    "BurpDump", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        final File baseDir = chooseExportDirectory(
                "BurpDump - Export all (HTTP + WebSocket)");
        if (baseDir == null) return;

        JFrame owner = findBurpFrame();
        final int total = httpCount + wsCount;

        JDialog dialog = new JDialog(owner,
                "BurpDump - Exporting all", false);
        dialog.setDefaultCloseOperation(JDialog.DO_NOTHING_ON_CLOSE);

        JProgressBar bar = new JProgressBar(0, total);
        bar.setStringPainted(true);
        bar.setString("0 / " + total);
        bar.setPreferredSize(new Dimension(420, 26));

        JLabel label = new JLabel("Starting export...");
        label.setBorder(BorderFactory.createEmptyBorder(0, 0, 6, 0));
        JButton cancelBtn = new JButton("Cancel");

        JPanel panel = new JPanel(new BorderLayout(8, 8));
        panel.setBorder(BorderFactory.createEmptyBorder(12, 16, 12, 16));
        panel.add(label, BorderLayout.NORTH);
        panel.add(bar,   BorderLayout.CENTER);
        JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 0, 0));
        btnPanel.add(cancelBtn);
        panel.add(btnPanel, BorderLayout.SOUTH);

        dialog.setContentPane(panel);
        dialog.setResizable(false);
        dialog.pack();
        dialog.setLocationRelativeTo(owner);

        final List<String> errors = new ArrayList<String>();

        SwingWorker<int[], Object[]> worker = new SwingWorker<int[], Object[]>() {
            @Override
            protected int[] doInBackground() {
                int okHttp = 0, failHttp = 0, skipped = 0;
                int okWs = 0, failWs = 0;
                int idx = 0;

                // Phase 1: HTTP
                if (http != null) {
                    Map<String, Integer> pathCounts =
                            new HashMap<String, Integer>();
                    for (int i = 0; i < http.length; i++) {
                        if (isCancelled()) break;
                        String desc = describeItem(http[i]);
                        publish(new Object[]{ idx, "[HTTP] " + desc });
                        try {
                            boolean exported =
                                    exportItem(http[i], baseDir, pathCounts);
                            if (exported) okHttp++; else skipped++;
                        } catch (Exception ex) {
                            failHttp++;
                            errors.add("[HTTP] " + desc + " - " + ex);
                        }
                        idx++;
                    }
                }

                // Phase 2: WebSocket
                if (ws != null && !isCancelled()) {
                    for (int i = 0; i < ws.size(); i++) {
                        if (isCancelled()) break;
                        WebSocketMessage msg = ws.get(i);
                        String desc = "(ws) " + (i + 1);
                        try {
                            URL u = new URL(msg.upgradeRequest().url());
                            String s = u.getHost() + u.getPath();
                            desc = s.length() > 80
                                    ? s.substring(0, 77) + "..." : s;
                        } catch (Throwable ignored) { }
                        publish(new Object[]{ idx, "[WS] " + desc });
                        try {
                            exportMontoyaWsMessage(msg, baseDir);
                            okWs++;
                        } catch (Throwable ex) {
                            failWs++;
                            errors.add("[WS] " + desc + " - "
                                    + ex.getClass().getName()
                                    + ": " + ex.getMessage());
                        }
                        idx++;
                    }
                }
                return new int[]{ okHttp, failHttp, skipped, okWs, failWs };
            }

            @Override
            protected void process(List<Object[]> chunks) {
                Object[] last = chunks.get(chunks.size() - 1);
                int i       = (int) last[0];
                String desc = (String) last[1];
                bar.setValue(i + 1);
                bar.setString((i + 1) + " / " + total);
                label.setText(desc);
            }

            @Override
            protected void done() {
                dialog.dispose();
                try {
                    if (isCancelled()) {
                        callbacks.printOutput("Export-all cancelled.");
                        return;
                    }
                    int[] r = get();
                    String msg = String.format(
                            "HTTP: %d exported, %d skipped, %d error(s).\n"
                            + "WebSocket: %d exported, %d error(s).",
                            r[0], r[2], r[1], r[3], r[4]);
                    showExportResult(owner, msg, errors);
                } catch (Exception ex) {
                    callbacks.printError("Error: " + ex);
                }
            }
        };

        cancelBtn.addActionListener(e -> worker.cancel(false));
        dialog.addWindowListener(new java.awt.event.WindowAdapter() {
            @Override
            public void windowClosing(java.awt.event.WindowEvent e) {
                worker.cancel(false);
            }
        });

        worker.execute();
        dialog.setVisible(true);
    }

    /* ================================================================== */
    /*  HTTP export orchestration with progress bar                       */
    /* ================================================================== */

    private void onExport(IHttpRequestResponse[] messages) {
        onExport(messages, (byte) -1);
    }

    private void onExport(IHttpRequestResponse[] messages, byte context) {
        // When invoked from the Target Site Map tree, Burp passes only one
        // representative item per selected node.  Expand via getSiteMap().
        if (context == IContextMenuInvocation.CONTEXT_TARGET_SITE_MAP_TREE) {
            try {
                LinkedHashSet<String> prefixes = new LinkedHashSet<String>();
                for (IHttpRequestResponse m : messages) {
                    IRequestInfo ri = helpers.analyzeRequest(m);
                    URL selectedUrl = ri.getUrl();
                    String prefix = selectedUrl.getProtocol() + "://"
                            + selectedUrl.getHost();
                    int port = selectedUrl.getPort();
                    if (port > 0
                            && port != selectedUrl.getDefaultPort()) {
                        prefix += ":" + port;
                    }
                    String path = selectedUrl.getPath();
                    if (path != null && !path.isEmpty()
                            && !path.equals("/")) {
                        prefix += path;
                    }
                    prefixes.add(prefix);
                }
                List<IHttpRequestResponse> expanded =
                        new ArrayList<IHttpRequestResponse>();
                for (String prefix : prefixes) {
                    IHttpRequestResponse[] sub =
                            callbacks.getSiteMap(prefix);
                    if (sub != null) {
                        for (IHttpRequestResponse item : sub)
                            expanded.add(item);
                    }
                }
                if (!expanded.isEmpty()) {
                    messages = expanded.toArray(
                            new IHttpRequestResponse[0]);
                }
            } catch (Exception ex) {
                callbacks.printError(
                        "Site map expansion failed: " + ex);
            }
        }

        final File baseDir = chooseExportDirectory(
                "BurpDump - Select export directory");
        if (baseDir == null) return;

        final IHttpRequestResponse[] items = messages;
        JFrame owner = findBurpFrame();
        final int total = items.length;

        /* ---- build progress dialog ---- */
        JDialog dialog = new JDialog(owner, "BurpDump - Exporting", false);
        dialog.setDefaultCloseOperation(JDialog.DO_NOTHING_ON_CLOSE);

        JProgressBar bar = new JProgressBar(0, total);
        bar.setStringPainted(true);
        bar.setString("0 / " + total);
        bar.setPreferredSize(new Dimension(420, 26));

        JLabel label = new JLabel("Starting export...");
        label.setBorder(BorderFactory.createEmptyBorder(0, 0, 6, 0));

        JButton cancelBtn = new JButton("Cancel");

        JPanel panel = new JPanel(new BorderLayout(8, 8));
        panel.setBorder(BorderFactory.createEmptyBorder(12, 16, 12, 16));
        panel.add(label, BorderLayout.NORTH);
        panel.add(bar,   BorderLayout.CENTER);

        JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 0, 0));
        btnPanel.add(cancelBtn);
        panel.add(btnPanel, BorderLayout.SOUTH);

        dialog.setContentPane(panel);
        dialog.setResizable(false);
        dialog.pack();
        dialog.setLocationRelativeTo(owner);

        final List<String> errors = new ArrayList<String>();

        /* ---- background worker ---- */
        SwingWorker<int[], Object[]> worker = new SwingWorker<int[], Object[]>() {
            @Override
            protected int[] doInBackground() {
                int ok = 0, fail = 0, skipped = 0;
                Map<String, Integer> pathCounts = new HashMap<String, Integer>();
                for (int i = 0; i < items.length; i++) {
                    if (isCancelled()) break;
                    String desc = describeItem(items[i]);
                    publish(new Object[]{ i, desc });
                    try {
                        boolean exported = exportItem(items[i], baseDir, pathCounts);
                        if (exported) ok++; else skipped++;
                    } catch (Exception ex) {
                        fail++;
                        errors.add(desc + " - " + ex);
                    }
                }
                return new int[]{ ok, fail, skipped };
            }

            @Override
            protected void process(List<Object[]> chunks) {
                Object[] last = chunks.get(chunks.size() - 1);
                int idx     = (int) last[0];
                String desc = (String) last[1];
                bar.setValue(idx + 1);
                bar.setString((idx + 1) + " / " + total);
                label.setText(desc);
            }

            @Override
            protected void done() {
                dialog.dispose();
                try {
                    if (isCancelled()) {
                        callbacks.printOutput("Export cancelled by user.");
                        return;
                    }
                    int[] r = get();
                    String msg = String.format(
                            "Exported %d item(s), %d skipped (not modified), %d error(s).",
                            r[0], r[2], r[1]);
                    showExportResult(owner, msg, errors);
                } catch (Exception ex) {
                    callbacks.printError("Error: " + ex);
                }
            }
        };

        cancelBtn.addActionListener(e -> worker.cancel(false));
        dialog.addWindowListener(new java.awt.event.WindowAdapter() {
            @Override
            public void windowClosing(java.awt.event.WindowEvent e) {
                worker.cancel(false);
            }
        });

        worker.execute();
        dialog.setVisible(true);
    }

    /** Short human-readable label for a request (used in progress bar). */
    private String describeItem(IHttpRequestResponse msg) {
        try {
            byte[] req = msg.getRequest();
            if (req != null) {
                IRequestInfo ri = helpers.analyzeRequest(msg);
                URL u = ri.getUrl();
                String s = u.getHost() + u.getPath();
                return s.length() > 80 ? s.substring(0, 77) + "..." : s;
            }
        } catch (Exception ignored) { }
        return "(unknown)";
    }

    /** Export the entire Proxy HTTP History. */
    private void onExportAllHttpHistory() {
        IHttpRequestResponse[] history;
        try {
            history = callbacks.getProxyHistory();
        } catch (Exception ex) {
            callbacks.printError("Cannot read proxy history: " + ex);
            JOptionPane.showMessageDialog(findBurpFrame(),
                    "Could not read Proxy History:\n" + ex.getMessage(),
                    "BurpDump", JOptionPane.ERROR_MESSAGE);
            return;
        }
        if (history == null || history.length == 0) {
            JOptionPane.showMessageDialog(findBurpFrame(),
                    "Proxy History is empty.", "BurpDump",
                    JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        onExport(history);
    }

    /* ================================================================== */
    /*  WebSocket export orchestration                                    */
    /* ================================================================== */

    private void onExportWebSocket() {
        final File baseDir = chooseExportDirectory(
                "BurpDump - Select WebSocket export directory");
        if (baseDir == null) return;

        JFrame owner = findBurpFrame();
        final List<WsFrame> snapshot;
        synchronized (wsFrames) {
            snapshot = new ArrayList<>(wsFrames);
        }
        final int total = snapshot.size();

        JDialog dialog = new JDialog(owner,
                "BurpDump - WebSocket export", false);
        dialog.setDefaultCloseOperation(JDialog.DO_NOTHING_ON_CLOSE);

        JProgressBar bar = new JProgressBar(0, total);
        bar.setStringPainted(true);
        bar.setString("0 / " + total);
        bar.setPreferredSize(new Dimension(420, 26));

        JLabel label = new JLabel("Starting WebSocket export...");
        label.setBorder(BorderFactory.createEmptyBorder(0, 0, 6, 0));

        JButton cancelBtn = new JButton("Cancel");

        JPanel panel = new JPanel(new BorderLayout(8, 8));
        panel.setBorder(BorderFactory.createEmptyBorder(12, 16, 12, 16));
        panel.add(label, BorderLayout.NORTH);
        panel.add(bar,   BorderLayout.CENTER);

        JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 0, 0));
        btnPanel.add(cancelBtn);
        panel.add(btnPanel, BorderLayout.SOUTH);

        dialog.setContentPane(panel);
        dialog.setResizable(false);
        dialog.pack();
        dialog.setLocationRelativeTo(owner);

        final List<String> errors = new ArrayList<String>();

        SwingWorker<int[], Object[]> worker = new SwingWorker<int[], Object[]>() {
            @Override
            protected int[] doInBackground() {
                int ok = 0, fail = 0;
                for (int i = 0; i < snapshot.size(); i++) {
                    if (isCancelled()) break;
                    WsFrame f = snapshot.get(i);
                    publish(new Object[]{ i, f.host + f.path });
                    try {
                        exportWsFrame(f, baseDir);
                        ok++;
                    } catch (Exception ex) {
                        fail++;
                        errors.add(f.host + f.path + " - " + ex);
                    }
                }
                return new int[]{ ok, fail };
            }

            @Override
            protected void process(List<Object[]> chunks) {
                Object[] last = chunks.get(chunks.size() - 1);
                int idx     = (int) last[0];
                String desc = (String) last[1];
                bar.setValue(idx + 1);
                bar.setString((idx + 1) + " / " + total);
                label.setText(desc);
            }

            @Override
            protected void done() {
                dialog.dispose();
                try {
                    if (isCancelled()) {
                        callbacks.printOutput("WS export cancelled.");
                        return;
                    }
                    int[] r = get();
                    String msg = String.format(
                            "Exported %d WebSocket message(s), %d error(s).",
                            r[0], r[1]);
                    showExportResult(owner, msg, errors);
                } catch (Exception ex) {
                    callbacks.printError("Error: " + ex);
                }
            }
        };

        cancelBtn.addActionListener(e -> worker.cancel(false));
        dialog.addWindowListener(new java.awt.event.WindowAdapter() {
            @Override
            public void windowClosing(java.awt.event.WindowEvent e) {
                worker.cancel(false);
            }
        });

        worker.execute();
        dialog.setVisible(true);
    }

    /* ================================================================== */
    /*  Single HTTP item export                                           */
    /* ================================================================== */

    /**
     * @return true if the item was exported, false if it was skipped (e.g. 304).
     */
    private boolean exportItem(IHttpRequestResponse msg, File baseDir,
                                Map<String, Integer> pathCounts)
            throws Exception {

        byte[] requestBytes = msg.getRequest();
        if (requestBytes == null || requestBytes.length == 0) return false;

        /* ---- analyse response early: skip 304 ---- */
        byte[] responseBytes = msg.getResponse();
        IResponseInfo respInfo = null;
        if (responseBytes != null && responseBytes.length > 0) {
            respInfo = helpers.analyzeResponse(responseBytes);
            if (respInfo.getStatusCode() == 304) return false;   // skip 304
        }

        IRequestInfo reqInfo = helpers.analyzeRequest(msg);
        URL url = reqInfo.getUrl();

        // ---- group & host directory names ----
        String rawHost = url.getHost();
        String group = extractGroup(rawHost);

        String host = rawHost;
        int port = url.getPort();
        if (port > 0 && port != 80 && port != 443) {
            host = host + "_" + port;
        }
        host  = sanitizeComponent(host);
        group = sanitizeComponent(group);

        // ---- URL path & query ----
        String urlPath = url.getPath();
        if (urlPath == null || urlPath.isEmpty()) urlPath = "/";

        String query = url.getQuery();

        // URL-decode (%20 -> ' ', etc.) keeping literal '+' as '+'
        urlPath = urlDecodeSafe(urlPath);
        if (query != null) query = urlDecodeSafe(query);

        // Build relative filename: '?' replaced with '#'
        String relPath = urlPath;
        if (query != null && !query.isEmpty()) {
            relPath = relPath + "#" + query;
        }

        // Handle root or trailing-slash paths
        if (relPath.equals("/") || relPath.isEmpty()) {
            relPath = "/index";
        } else if (relPath.endsWith("/")) {
            relPath = relPath + "index";
        }

        // Split into components, sanitize each, and rejoin
        String[] parts = relPath.split("/");
        StringBuilder sanitized = new StringBuilder();
        for (String part : parts) {
            if (part.isEmpty()) continue;
            if (sanitized.length() > 0) sanitized.append(File.separator);
            sanitized.append(sanitizeComponent(part));
        }

        Path filePath = baseDir.toPath()
                .resolve(group)
                .resolve(host)
                .resolve(sanitized.toString());

        // ---- deduplicate: append .(N) when the same path appears more than once ----
        String pathKey = filePath.toString();
        int occurrence = pathCounts.getOrDefault(pathKey, 0) + 1;
        pathCounts.put(pathKey, occurrence);
        if (occurrence > 1) {
            filePath = Paths.get(pathKey + ".(" + occurrence + ")");
        }

        Files.createDirectories(filePath.getParent());

        // ---- determine timestamp from response Date header ----
        long timestamp = 0;
        if (respInfo != null) {
            String dateHeader = findHeaderValue(respInfo.getHeaders(), "Date");
            timestamp = parseHttpDate(dateHeader);
        }
        if (timestamp <= 0) timestamp = System.currentTimeMillis();

        // ---- Request header ----
        Path reqHeaderPath = withSuffix(filePath, ".request");
        writeBytes(reqHeaderPath,
                joinHeaders(reqInfo.getHeaders()).getBytes(StandardCharsets.UTF_8));
        setFileTimestamp(reqHeaderPath, timestamp);

        // ---- Request body (only if present) ----
        int reqBodyOff = reqInfo.getBodyOffset();
        if (reqBodyOff < requestBytes.length) {
            byte[] reqBody = Arrays.copyOfRange(requestBytes, reqBodyOff,
                    requestBytes.length);
            if (reqBody.length > 0) {
                reqBody = decompressIfNeeded(reqBody, reqInfo.getHeaders());
                Path reqDataPath = withSuffix(filePath, ".request.data");
                writeBytes(reqDataPath, reqBody);
                setFileTimestamp(reqDataPath, timestamp);
            }
        }

        // ---- Response ----
        if (responseBytes != null && responseBytes.length > 0 && respInfo != null) {
            // Response header
            Path respHeaderPath = withSuffix(filePath, ".response");
            writeBytes(respHeaderPath,
                    joinHeaders(respInfo.getHeaders()).getBytes(StandardCharsets.UTF_8));
            setFileTimestamp(respHeaderPath, timestamp);

            // Response body (decompressed)
            int respBodyOff = respInfo.getBodyOffset();
            if (respBodyOff < responseBytes.length) {
                byte[] respBody = Arrays.copyOfRange(
                        responseBytes, respBodyOff, responseBytes.length);
                if (respBody.length > 0) {
                    respBody = decompressIfNeeded(respBody, respInfo.getHeaders());
                    writeBytes(filePath, respBody);
                    setFileTimestamp(filePath, timestamp);
                }
            }
        }
        return true;
    }

    /* ================================================================== */
    /*  Single WebSocket frame export                                     */
    /* ================================================================== */

    private void exportWsFrame(WsFrame frame, File baseDir) throws Exception {
        String rawHost = frame.host;
        String group   = extractGroup(rawHost);

        String host = rawHost;
        if (frame.port > 0 && frame.port != 80 && frame.port != 443) {
            host = host + "_" + frame.port;
        }
        host  = sanitizeComponent(host);
        group = sanitizeComponent(group);

        // Process URL path
        String urlPath = frame.path;
        if (urlPath == null || urlPath.isEmpty()) urlPath = "/";
        urlPath = urlDecodeSafe(urlPath);

        if (urlPath.equals("/") || urlPath.isEmpty()) {
            urlPath = "/index";
        } else if (urlPath.endsWith("/")) {
            urlPath = urlPath + "index";
        }

        String[] parts = urlPath.split("/");
        StringBuilder sanitized = new StringBuilder();
        for (String part : parts) {
            if (part.isEmpty()) continue;
            if (sanitized.length() > 0) sanitized.append(File.separator);
            sanitized.append(sanitizeComponent(part));
        }

        // Build base path:  {baseDir}/{group}/{host}/{path-components}
        Path basePath = baseDir.toPath().resolve(group).resolve(host);
        String rel = sanitized.toString();

        // Split into parent directory and last component
        int lastSep = rel.lastIndexOf(File.separatorChar);
        Path dir;
        String lastComponent;
        if (lastSep >= 0) {
            dir           = basePath.resolve(rel.substring(0, lastSep));
            lastComponent = rel.substring(lastSep + 1);
        } else {
            dir           = basePath;
            lastComponent = rel;
        }

        String direction  = frame.isSend ? "send" : "recv";
        String wsFilename = lastComponent + "#ws." + frame.uniqueId + "." + direction;

        Files.createDirectories(dir);
        Path filePath = dir.resolve(wsFilename);
        writeBytes(filePath, frame.payload != null ? frame.payload : new byte[0]);
        setFileTimestamp(filePath, frame.timestampMillis);
    }

    /* ================================================================== */
    /*  Group extraction - second-level domain                            */
    /* ================================================================== */

    /**
     * Extracts the second-level domain from a hostname.
     * <pre>
     *   accounts.google.com           -> google.com
     *   android.clients.google.com    -> google.com
     *   google.com                    -> google.com
     *   localhost                     -> localhost
     *   192.168.1.1                   -> 192.168.1.1  (IP kept as-is)
     * </pre>
     */
    static String extractGroup(String host) {
        if (host == null || host.isEmpty()) return "_";

        // IPv4 address - keep as-is
        if (host.matches("^\\d{1,3}(\\.\\d{1,3}){3}$")) return host;
        // IPv6 address
        if (host.startsWith("[") || host.contains(":")) return host;

        String[] parts = host.split("\\.");
        if (parts.length <= 2) return host;         // already 2 levels or fewer
        return parts[parts.length - 2] + "." + parts[parts.length - 1];
    }

    /* ================================================================== */
    /*  Path helpers                                                      */
    /* ================================================================== */

    /** URL-decode preserving literal '+' (which URLDecoder would turn into ' '). */
    private static String urlDecodeSafe(String s) {
        try {
            s = s.replace("+", "%2B");          // protect '+'
            return URLDecoder.decode(s, "UTF-8");
        } catch (Exception e) {
            return s;
        }
    }

    /**
     * Make a single path component safe for NTFS / most file systems.
     * Replaces '?' with '#', strips control chars, handles reserved names, etc.
     */
    private static String sanitizeComponent(String name) {
        if (name == null || name.isEmpty()) return "_";

        name = name.replace('?', '#');      // as per requirements
        name = name.replace('<', '_');
        name = name.replace('>', '_');
        name = name.replace(':', '_');
        name = name.replace('"', '\'');
        name = name.replace('|', '_');
        name = name.replace('*', '_');
        name = name.replace('\\', '_');
        name = name.replaceAll("[\\x00-\\x1f]", ""); // control chars

        // Windows: no trailing dots or spaces
        name = name.replaceAll("[. ]+$", "_");

        // Windows reserved device names
        if (name.matches("(?i)(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\\..*)?")) {
            name = "_" + name;
        }

        // Keep path components reasonably short
        if (name.length() > 240) {
            name = name.substring(0, 240);
        }
        return name.isEmpty() ? "_" : name;
    }

    private static Path withSuffix(Path base, String suffix) {
        return Paths.get(base.toString() + suffix);
    }

    /* ================================================================== */
    /*  Header helpers                                                    */
    /* ================================================================== */

    private static String joinHeaders(List<String> headers) {
        StringBuilder sb = new StringBuilder();
        for (String h : headers) sb.append(h).append("\r\n");
        sb.append("\r\n");
        return sb.toString();
    }

    private static String findHeaderValue(List<String> headers, String name) {
        String prefix = name.toLowerCase() + ":";
        for (String h : headers) {
            if (h.toLowerCase().startsWith(prefix)) {
                return h.substring(name.length() + 1).trim();
            }
        }
        return null;
    }

    /* ================================================================== */
    /*  Decompression                                                     */
    /* ================================================================== */

    private byte[] decompressIfNeeded(byte[] body, List<String> headers) {
        String enc = findHeaderValue(headers, "Content-Encoding");
        if (enc == null) return body;
        enc = enc.trim().toLowerCase();
        try {
            if (enc.contains("gzip") || enc.contains("x-gzip")) {
                return decompressGzip(body);
            } else if (enc.contains("deflate")) {
                return decompressDeflate(body);
            }
        } catch (Exception e) {
            callbacks.printError("Decompression (" + enc + ") failed: " + e.getMessage());
        }
        return body;  // return as-is if unknown encoding or error
    }

    private static byte[] decompressGzip(byte[] data) throws IOException {
        try (ByteArrayInputStream bis = new ByteArrayInputStream(data);
             GZIPInputStream gis = new GZIPInputStream(bis);
             ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
            byte[] buf = new byte[8192];
            int n;
            while ((n = gis.read(buf)) > 0) bos.write(buf, 0, n);
            return bos.toByteArray();
        }
    }

    private static byte[] decompressDeflate(byte[] data) throws IOException {
        try (ByteArrayInputStream bis = new ByteArrayInputStream(data);
             InflaterInputStream iis = new InflaterInputStream(bis);
             ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
            byte[] buf = new byte[8192];
            int n;
            while ((n = iis.read(buf)) > 0) bos.write(buf, 0, n);
            return bos.toByteArray();
        }
    }

    /* ================================================================== */
    /*  Timestamp helpers                                                 */
    /* ================================================================== */

    /**
     * Parse an HTTP-date header (RFC 7231 sec. 7.1.1.1).
     * Returns epoch millis, or 0 if parsing fails.
     */
    private static long parseHttpDate(String dateStr) {
        if (dateStr == null || dateStr.isEmpty()) return 0;
        String[] patterns = {
                "EEE, dd MMM yyyy HH:mm:ss zzz",   // RFC 1123
                "EEEE, dd-MMM-yy HH:mm:ss zzz",    // RFC 850
                "EEE MMM dd HH:mm:ss yyyy",         // ANSI C asctime()
                "EEE, dd MMM yyyy HH:mm:ss z",
        };
        for (String pattern : patterns) {
            try {
                SimpleDateFormat sdf = new SimpleDateFormat(pattern, Locale.US);
                sdf.setTimeZone(TimeZone.getTimeZone("GMT"));
                return sdf.parse(dateStr).getTime();
            } catch (Exception ignored) { }
        }
        return 0;
    }

    /**
     * Set both creation time and last-modified time on a file.
     * Silently ignores errors (e.g. filesystem doesn't support creation time).
     */
    private static void setFileTimestamp(Path path, long millis) {
        if (millis <= 0) return;
        try {
            FileTime ft = FileTime.fromMillis(millis);
            BasicFileAttributeView view =
                    Files.getFileAttributeView(path, BasicFileAttributeView.class);
            if (view != null) {
                // setTimes(lastModified, lastAccess, creationTime)
                view.setTimes(ft, ft, ft);
            }
        } catch (Exception ignored) { }
    }

    /* ================================================================== */
    /*  I/O & UI helpers                                                  */
    /* ================================================================== */

    private static void writeBytes(Path path, byte[] data) throws IOException {
        Files.write(path, data, StandardOpenOption.CREATE,
                StandardOpenOption.TRUNCATE_EXISTING);
    }

    /**
     * Show a directory-chooser dialog, remembering the last selected folder.
     * The choice is persisted via Burp extension settings so it survives restarts.
     * @return the selected directory, or {@code null} if the user cancelled.
     */
    private File chooseExportDirectory(String title) {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle(title);
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        chooser.setAcceptAllFileFilterUsed(false);
        if (lastExportDir != null && lastExportDir.isDirectory()) {
            chooser.setCurrentDirectory(lastExportDir);
        }
        JFrame owner = findBurpFrame();
        if (chooser.showSaveDialog(owner) != JFileChooser.APPROVE_OPTION) {
            return null;
        }
        File dir = chooser.getSelectedFile();
        lastExportDir = dir;
        try {
            callbacks.saveExtensionSetting("lastExportDir",
                    dir.getAbsolutePath());
        } catch (Exception ignored) { }
        return dir;
    }

    /**
     * Show a summary dialog after export.  When there are errors, a
     * scrollable text area lists every failed item with its exception.
     */
    private void showExportResult(JFrame owner, String summary,
                                   List<String> errors) {
        callbacks.printOutput(summary);
        for (String err : errors) callbacks.printError(err);

        if (errors.isEmpty()) {
            JOptionPane.showMessageDialog(owner, summary,
                    "BurpDump", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        // Build a panel: summary label on top, scrollable error list below
        JPanel panel = new JPanel(new BorderLayout(8, 8));
        panel.setBorder(BorderFactory.createEmptyBorder(4, 0, 4, 0));
        panel.add(new JLabel(summary), BorderLayout.NORTH);

        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < errors.size(); i++) {
            sb.append(errors.get(i)).append("\n");
        }
        JTextArea textArea = new JTextArea(sb.toString().trim());
        textArea.setEditable(false);
        textArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        textArea.setCaretPosition(0);

        JScrollPane scroll = new JScrollPane(textArea);
        int rows = Math.min(errors.size(), 20);
        scroll.setPreferredSize(new Dimension(600, rows * 18 + 40));
        panel.add(scroll, BorderLayout.CENTER);

        JOptionPane.showMessageDialog(owner, panel,
                "BurpDump", JOptionPane.WARNING_MESSAGE);
    }

    private static JFrame findBurpFrame() {
        for (java.awt.Frame f : JFrame.getFrames()) {
            if (f.isVisible() && f instanceof JFrame) return (JFrame) f;
        }
        return null;
    }
}
