package burp;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.reflect.TypeToken;
import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.regex.Pattern;

public class BurpExtender implements IBurpExtender, ITab, IHttpListener {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private final Gson gson = new Gson();

    private JTabbedPane mainTabbedPane;
    private JTextField aiUrlField;

    // 配置页规则模型
    private DefaultTableModel requestRuleModel;
    private JTable requestRuleTable;
    private DefaultTableModel responseRuleModel;
    private JTable responseRuleTable;

    // 结果页主从表
    private JTable masterTable;
    private DefaultTableModel masterModel;
    private final List<MasterResult> masterData = new ArrayList<>();
    private JTable detailTable;
    private DefaultTableModel detailModel;

    private final ExecutorService threadPool = Executors.newFixedThreadPool(10);
    private static final String SETTING_AI_URL = "AI_SERVER_URL";

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        callbacks.setExtensionName("嗅探JS-AI专业版");

        String savedUrl = callbacks.loadExtensionSetting(SETTING_AI_URL);
        if (savedUrl == null || savedUrl.isEmpty()) savedUrl = "http://127.0.0.1:8899/api/chat/";

        final String initialUrl = savedUrl;

        SwingUtilities.invokeLater(() -> {
            mainTabbedPane = new JTabbedPane();

            // ==========================================
            // 1. 配置页
            // ==========================================
            JPanel configPage = new JPanel(new BorderLayout());
            JPanel topControl = new JPanel(new FlowLayout(FlowLayout.LEFT));
            topControl.setBorder(BorderFactory.createTitledBorder("配置控制"));
            topControl.add(new JLabel("AI 基础 URL: "));
            aiUrlField = new JTextField(initialUrl, 45);
            topControl.add(aiUrlField);
            JButton saveBtn = new JButton("保存配置");
            saveBtn.addActionListener(e -> {
                this.callbacks.saveExtensionSetting(SETTING_AI_URL, aiUrlField.getText().trim());
                JOptionPane.showMessageDialog(null, "配置保存成功！");
            });
            topControl.add(saveBtn);

            // 创建左右两个规则面板
            JPanel leftColumn = createRulePanel("请求过滤规则", true);
            JPanel rightColumn = createRulePanel("响应匹配规则", false);

            JSplitPane configSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, leftColumn, rightColumn);
            configSplit.setDividerLocation(600);
            configSplit.setResizeWeight(0.5);

            configPage.add(topControl, BorderLayout.NORTH);
            configPage.add(configSplit, BorderLayout.CENTER);

            // ==========================================
            // 2. 结果页
            // ==========================================
            JPanel resultPage = new JPanel(new BorderLayout());
            masterModel = new DefaultTableModel(new String[]{"序号", "发现链接总数", "嗅探的目标URL"}, 0);
            masterTable = new JTable(masterModel);
            detailModel = new DefaultTableModel(new String[]{"序号", "发现链接", "用途说明", "标签"}, 0);
            detailTable = new JTable(detailModel);

            // 主从表联动逻辑
            masterTable.getSelectionModel().addListSelectionListener(e -> {
                int row = masterTable.getSelectedRow();
                if (row != -1 && !e.getValueIsAdjusting()) {
                    detailModel.setRowCount(0);
                    synchronized (masterData) {
                        if (row < masterData.size()) {
                            MasterResult mr = masterData.get(row);
                            if (mr.details != null) {
                                for (DetailResult dr : mr.details) {
                                    detailModel.addRow(new Object[]{dr.序号, dr.地址, dr.用途说明, dr.标签});
                                }
                            }
                        }
                    }
                }
            });

            JSplitPane resultSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, new JScrollPane(masterTable), new JScrollPane(detailTable));
            resultSplit.setDividerLocation(250);

            JPanel resultToolbar = new JPanel(new FlowLayout(FlowLayout.LEFT));
            JButton clearBtn = new JButton("清空所有嗅探结果");
            clearBtn.addActionListener(e -> {
                synchronized (masterData) {
                    masterData.clear();
                    masterModel.setRowCount(0);
                    detailModel.setRowCount(0);
                }
            });
            resultToolbar.add(clearBtn);

            resultPage.add(resultToolbar, BorderLayout.NORTH);
            resultPage.add(resultSplit, BorderLayout.CENTER);

            mainTabbedPane.addTab(" 配置 ", configPage);
            mainTabbedPane.addTab(" 结果 ", resultPage);

            this.callbacks.addSuiteTab(this);
        });

        this.callbacks.registerHttpListener(this);
    }

    /**
     * 创建规则面板，集成海量推荐规则库
     */
    private JPanel createRulePanel(String title, boolean isRequest) {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createTitledBorder(null, title, TitledBorder.DEFAULT_JUSTIFICATION, TitledBorder.DEFAULT_POSITION, new Font("SansSerif", Font.BOLD, 12)));

        // 1. 上方：当前生效的规则表
        DefaultTableModel activeModel = new DefaultTableModel(new String[]{"匹配模式", "说明"}, 0);
        if (isRequest) {
            requestRuleModel = activeModel;
            requestRuleModel.addRow(new Object[]{"\\.js|\\.html|\\.htm", "默认通用Web嗅探"});
        } else {
            responseRuleModel = activeModel;
            responseRuleModel.addRow(new Object[]{"path|url|endpoint", "默认关键字段"});
        }
        JTable activeTable = new JTable(activeModel);

        // 2. 下方：海量推荐规则库（不可编辑，双击添加）
        DefaultTableModel recModel = new DefaultTableModel(new String[]{"推荐模式 (双击选择)", "场景说明"}, 0) {
            @Override public boolean isCellEditable(int row, int column) { return false; }
        };

        if (isRequest) {
            recModel.addRow(new Object[]{"\\.js|\\.html|\\.htm", "【WEB】常用静态资源嗅探"});
            recModel.addRow(new Object[]{"(^POST /api/.*)|(^GET /api/.*)", "【API】标准接口流量监控"});
            recModel.addRow(new Object[]{".*wechat.*\\.js", "【小程序】微信业务JS提取"});
            recModel.addRow(new Object[]{"/v1/|/v2/|/v3/", "【API】版本化接口监控"});
            recModel.addRow(new Object[]{".*\\.json$", "【敏感】监控JSON响应内容"});
            recModel.addRow(new Object[]{"graphql", "【API】监控GraphQL查询流量"});
            recModel.addRow(new Object[]{".*chunk.*\\.js", "【框架】Vue/React打包文件提取"});
            recModel.addRow(new Object[]{"login|auth|user", "【业务】监控关键业务代码"});
        } else {
            recModel.addRow(new Object[]{"path|url|endpoint|route", "【核心】匹配所有路由变量"});
            recModel.addRow(new Object[]{"token|auth|key|secret", "【敏感】查找鉴权信息/密钥"});
            recModel.addRow(new Object[]{"/admin/|/manage/|/config/", "【后台】搜索管理台路径"});
            recModel.addRow(new Object[]{"127.0.0.1|localhost|192.168.", "【内网】查找硬编码内网IP"});
            recModel.addRow(new Object[]{"s3\\.amazonaws\\.com|oss-cn-", "【云端】查找云存储Bucket地址"});
            recModel.addRow(new Object[]{"password|user_id|email", "【个人】匹配潜在敏感字段"});
            recModel.addRow(new Object[]{"debug|test|dev", "【环境】搜索测试/调试接口"});
        }

        JTable recTable = new JTable(recModel);
        recTable.setBackground(new Color(245, 245, 245));
        recTable.addMouseListener(new MouseAdapter() {
            @Override public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) {
                    int row = recTable.getSelectedRow();
                    if (row != -1) activeModel.addRow(new Object[]{recModel.getValueAt(row, 0), recModel.getValueAt(row, 1)});
                }
            }
        });

        JSplitPane innerSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, new JScrollPane(activeTable), new JScrollPane(recTable));
        innerSplit.setDividerLocation(200);
        panel.add(innerSplit, BorderLayout.CENTER);

        JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        JButton addBtn = new JButton("自定义添加规则");
        addBtn.addActionListener(e -> showAddRuleDialog(activeModel));
        JButton delBtn = new JButton("删除选中规则");
        delBtn.addActionListener(e -> {
            int row = activeTable.getSelectedRow();
            if (row != -1) activeModel.removeRow(row);
        });
        btnPanel.add(addBtn); btnPanel.add(delBtn);
        panel.add(btnPanel, BorderLayout.SOUTH);

        return panel;
    }

    private void showAddRuleDialog(DefaultTableModel model) {
        JTextField ruleField = new JTextField();
        JTextField descField = new JTextField();
        Object[] message = { "匹配模式 (正则, 必填):", ruleField, "说明:", descField };
        int option = JOptionPane.showConfirmDialog(null, message, "添加规则", JOptionPane.OK_CANCEL_OPTION);
        if (option == JOptionPane.OK_OPTION) {
            String rule = ruleField.getText().trim();
            if (rule.isEmpty()) {
                JOptionPane.showMessageDialog(null, "模式不能为空");
            } else {
                model.addRow(new Object[]{rule, descField.getText().trim()});
            }
        }
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (messageIsRequest) return;

        byte[] response = messageInfo.getResponse();
        if (response == null) return;

        IResponseInfo respInfo = helpers.analyzeResponse(response);
        IRequestInfo reqInfo = helpers.analyzeRequest(messageInfo);
        String url = reqInfo.getUrl().toString();

        StringBuilder headersText = new StringBuilder();
        for (String h : reqInfo.getHeaders()) headersText.append(h).append("\n");
        String headers = headersText.toString();

        // 1. 请求过滤检查 (无规则则默认全捕获)
        boolean reqMatch = (requestRuleModel == null || requestRuleModel.getRowCount() == 0);
        if (!reqMatch) {
            for (int i = 0; i < requestRuleModel.getRowCount(); i++) {
                String pStr = (String) requestRuleModel.getValueAt(i, 0);
                if (!pStr.isEmpty()) {
                    try {
                        if (Pattern.compile(pStr, Pattern.CASE_INSENSITIVE).matcher(headers).find() ||
                                Pattern.compile(pStr, Pattern.CASE_INSENSITIVE).matcher(url).find()) {
                            reqMatch = true; break;
                        }
                    } catch (Exception e) {}
                }
            }
        }
        if (!reqMatch) return;

        // 2. 响应预过滤检查
        int offset = respInfo.getBodyOffset();
        String body = new String(Arrays.copyOfRange(response, offset, response.length), StandardCharsets.UTF_8);

        boolean resMatch = (responseRuleModel == null || responseRuleModel.getRowCount() == 0);
        if (!resMatch) {
            for (int i = 0; i < responseRuleModel.getRowCount(); i++) {
                String pStr = (String) responseRuleModel.getValueAt(i, 0);
                if (!pStr.isEmpty()) {
                    try {
                        if (Pattern.compile(pStr, Pattern.CASE_INSENSITIVE).matcher(body).find()) {
                            resMatch = true; break;
                        }
                    } catch (Exception e) {}
                }
            }
        }

        if (resMatch && body.length() > 20) {
            this.callbacks.printOutput("[+] 匹配成功: " + url);
            threadPool.submit(() -> {
                try {
                    String apiUrl = aiUrlField.getText().trim();
                    if (!apiUrl.endsWith("/")) apiUrl += "/";
                    String aiJson = HttpUtil.sendPost(apiUrl + "find_url", body);

                    JsonObject obj = gson.fromJson(aiJson, JsonObject.class);
                    String total = obj.get("总数").getAsString();
                    List<DetailResult> details = gson.fromJson(obj.get("明细"), new TypeToken<List<DetailResult>>(){}.getType());

                    synchronized (masterData) {
                        int id = masterData.size() + 1;
                        MasterResult mr = new MasterResult(id, url, total, details);
                        masterData.add(mr);
                        SwingUtilities.invokeLater(() -> masterModel.addRow(new Object[]{mr.id, mr.totalCount, mr.targetUrl}));
                    }
                } catch (Exception e) {
                    this.callbacks.printError("AI解析失败: " + e.getMessage());
                }
            });
        }
    }

    @Override public String getTabCaption() { return "嗅探JS-AI"; }
    @Override public Component getUiComponent() { return mainTabbedPane; }
}
