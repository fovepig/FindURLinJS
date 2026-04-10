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

public class BurpExtender implements IBurpExtender, ITab, IHttpListener {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private final Gson gson = new Gson();

    private JTabbedPane mainTabbedPane;
    private JTextField aiUrlField;

    private DefaultTableModel requestRuleModel;
    private JTable requestRuleTable;
    private DefaultTableModel responseRuleModel;
    private JTable responseRuleTable;

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
                String currentUrl = aiUrlField.getText().trim();
                this.callbacks.saveExtensionSetting(SETTING_AI_URL, currentUrl);
                JOptionPane.showMessageDialog(null, "配置保存成功！");
            });
            topControl.add(saveBtn);

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

    private JPanel createRulePanel(String title, boolean isRequest) {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createTitledBorder(null, title, TitledBorder.DEFAULT_JUSTIFICATION, TitledBorder.DEFAULT_POSITION, new Font("SansSerif", Font.BOLD, 12)));

        // 生效表（可编辑）
        DefaultTableModel activeModel = new DefaultTableModel(new String[]{"匹配模式", "说明"}, 0);
        if (isRequest) {
            requestRuleModel = activeModel;
            requestRuleModel.addRow(new Object[]{"(^GET /.*\\.js)|(^GET /.*\\.html)", "默认通用WEB"});
        } else {
            responseRuleModel = activeModel;
            responseRuleModel.addRow(new Object[]{"path|url|endpoint", "默认关键路径"});
        }
        JTable activeTable = new JTable(activeModel);

        // 推荐表（不可编辑，修复双击问题）
        DefaultTableModel recModel = new DefaultTableModel(new String[]{"推荐模式 (双击选择)", "场景说明"}, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false; // 禁止直接编辑，确保双击逻辑生效
            }
        };

        // --- 开始填充海量推荐规则 (按频率排序) ---
        if (isRequest) {
            // 请求侧规则
            recModel.addRow(new Object[]{"(^GET /.*\\.js)|(^GET /.*\\.html)", "【高频】标准WEB嗅探 (JS/HTML)"});
            recModel.addRow(new Object[]{"(^POST /api/.*)|(^GET /api/.*)", "【高频】标准RESTful API 监控"});
            recModel.addRow(new Object[]{".*wechat.*\\.js", "【小程序】微信侧业务代码提取"});
            recModel.addRow(new Object[]{"/v1/|/v2/|/v3/", "【API】监控版本化接口流量"});
            recModel.addRow(new Object[]{".*\\.json$", "【数据】监控JSON配置文件响应"});
            recModel.addRow(new Object[]{"graphql", "【API】监控GraphQL查询流量"});
            recModel.addRow(new Object[]{".*chunk.*\\.js", "【框架】Vue/React 打包文件提取"});
            recModel.addRow(new Object[]{"login|auth|user", "【业务】监控登录/鉴权相关代码"});
            recModel.addRow(new Object[]{".*map$", "【调试】查找 JS SourceMap 文件"});
        } else {
            // 响应侧规则
            recModel.addRow(new Object[]{"path|url|endpoint|route", "【核心】匹配所有路径/路由变量"});
            recModel.addRow(new Object[]{"token|auth|key|secret", "【敏感】查找鉴权信息/密钥/Token"});
            recModel.addRow(new Object[]{"/admin/|/manage/|/config/", "【后台】搜索管理台路径/配置路径"});
            recModel.addRow(new Object[]{"127.0.0.1|localhost|192.168.", "【内网】查找硬编码的内部IP/地址"});
            recModel.addRow(new Object[]{"s3\\.amazonaws\\.com|oss-cn-", "【云端】查找云存储 Bucket 地址"});
            recModel.addRow(new Object[]{"password|user_id|email", "【个人信息】匹配潜在的敏感字段"});
            recModel.addRow(new Object[]{"debug|test|dev", "【环境】搜索测试/开发/调试接口"});
            recModel.addRow(new Object[]{"\\.sql|\\.bak|\\.zip", "【附件】搜索源代码中的文件引用"});
            recModel.addRow(new Object[]{"docker|kube|cluster", "【容器】查找云原生/架构信息"});
        }

        JTable recTable = new JTable(recModel);
        recTable.setBackground(new Color(245, 245, 245));

        // 绑定双击事件：推荐 -> 生效
        recTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) {
                    int row = recTable.getSelectedRow();
                    if (row != -1) {
                        activeModel.addRow(new Object[]{
                                recModel.getValueAt(row, 0),
                                recModel.getValueAt(row, 1)
                        });
                    }
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
        Object[] message = { "匹配模式 (正则, 必填):", ruleField, "场景说明 (可选):", descField };

        int option = JOptionPane.showConfirmDialog(null, message, "添加自定义规则", JOptionPane.OK_CANCEL_OPTION);
        if (option == JOptionPane.OK_OPTION) {
            String rule = ruleField.getText().trim();
            if (rule.isEmpty()) {
                JOptionPane.showMessageDialog(null, "错误：匹配模式不能为空！", "提示", JOptionPane.ERROR_MESSAGE);
                showAddRuleDialog(model);
            } else {
                model.addRow(new Object[]{rule, descField.getText().trim()});
            }
        }
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (!messageIsRequest) {
            byte[] response = messageInfo.getResponse();
            if (response == null) return;
            IResponseInfo respInfo = helpers.analyzeResponse(response);
            IRequestInfo reqInfo = helpers.analyzeRequest(messageInfo);
            String url = reqInfo.getUrl().toString();
            String firstHeader = reqInfo.getHeaders().get(0);

            boolean reqMatch = false;
            if (requestRuleModel != null) {
                for (int i = 0; i < requestRuleModel.getRowCount(); i++) {
                    String p = (String) requestRuleModel.getValueAt(i, 0);
                    if (!p.isEmpty() && firstHeader.matches(".*" + p + ".*")) { reqMatch = true; break; }
                }
            }
            if (!reqMatch) return;

            int offset = respInfo.getBodyOffset();
            String sourceCode = new String(Arrays.copyOfRange(response, offset, response.length), StandardCharsets.UTF_8);

            boolean resMatch = true;
            if (responseRuleModel != null && responseRuleModel.getRowCount() > 0) {
                resMatch = false;
                for (int i = 0; i < responseRuleModel.getRowCount(); i++) {
                    String p = (String) responseRuleModel.getValueAt(i, 0);
                    if (!p.isEmpty() && sourceCode.toLowerCase().contains(p.toLowerCase())) { resMatch = true; break; }
                }
            }

            if (resMatch && sourceCode.length() > 20) {
                threadPool.submit(() -> {
                    try {
                        String apiUrl = aiUrlField.getText().trim();
                        if (!apiUrl.endsWith("/")) apiUrl += "/";
                        String aiJson = HttpUtil.sendPost(apiUrl + "find_url", sourceCode);
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
    }

    @Override public String getTabCaption() { return "嗅探JS-AI"; }
    @Override public Component getUiComponent() { return mainTabbedPane; }
}
