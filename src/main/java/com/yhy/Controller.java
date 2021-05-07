package com.yhy;

import com.google.common.hash.Hashing;
import com.yhy.core.Constants;
import com.yhy.core.ExploitInterface;
import com.yhy.core.Job;
import com.yhy.core.VulInfo;
import com.yhy.tools.HttpTool;
import com.yhy.tools.Tools;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.fxml.FXML;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.control.*;
import javafx.scene.control.Alert.AlertType;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.image.Image;
import javafx.scene.image.ImageView;
import javafx.scene.input.Clipboard;
import javafx.scene.input.ClipboardContent;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Region;
import javafx.scene.text.Text;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import javafx.stage.Window;

import java.io.File;
import java.io.IOException;
import java.net.Authenticator;
import java.net.InetSocketAddress;
import java.net.PasswordAuthentication;
import java.net.Proxy;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

// JavaFX图形化界面的控制类
public class Controller {

    @FXML
    private Label tool_name;
    @FXML
    private Label proxyStatusLabel;
    @FXML
    private Label author;
    @FXML
    private ChoiceBox choice_cve;
    @FXML
    private ChoiceBox encoding;
    @FXML
    private ChoiceBox platform;
    @FXML
    private ChoiceBox thread;
    @FXML
    private ChoiceBox fofa_size;
    @FXML
    private Text time;
    @FXML
    private TextArea basic_info;
    @FXML
    private TextArea fofa_result_info;
    @FXML
    private TextArea cmd_info;
    @FXML
    private TextField cmd;
    @FXML
    private TextField fofa_info;

    @FXML
    private TextArea upload_info;
    @FXML
    private TextField upload_path;
    @FXML
    private TextArea upload_msg;
    @FXML
    private TableView<VulInfo> table_view;
    @FXML
    private TableColumn<VulInfo, String> id;
    @FXML
    private TableColumn<VulInfo, String> target;
    @FXML
    private TableColumn<VulInfo, String> isVul;

    private final ObservableList<VulInfo> datas = FXCollections.observableArrayList();
    @FXML
    private TextField url;
    @FXML
    private TextField file_path;

    private ExploitInterface ei;

    @FXML
    private MenuItem proxySetupBtn;

    @FXML
    private Button fofa_check;

    @FXML
    private MenuItem fofa_setting;

    // 设置相关信息保存
    public static Map<String, Object> settingInfo = new HashMap();
    // fofa 结果
    public static HashSet<String> fofa_result = new HashSet<String>();


    // 监听菜单关于事件
    @FXML
    public void about() {
        Alert alert = new Alert(AlertType.NONE);

        // 点 x 退出
        Window window = alert.getDialogPane().getScene().getWindow();
        window.setOnCloseRequest((e) -> {
            window.hide();
        });

        DialogPane dialogPane = new DialogPane();

        TextArea textArea = new TextArea(Constants.BASICINFO);
        textArea.setEditable(false);
        textArea.setWrapText(true);

        dialogPane.setContent(textArea);


        Image image = new Image(String.valueOf(getClass().getClassLoader().getResource("weixin.jpg")));
        ImageView imageView = new ImageView();
        imageView.setImage(image);

        imageView.setFitWidth(200);
        imageView.setPreserveRatio(true);

        dialogPane.setGraphic(imageView);

        ButtonType confirm = new ButtonType("确认");
        dialogPane.getButtonTypes().setAll(confirm);
        alert.setDialogPane(dialogPane);

        alert.showAndWait();


    }

    // 监听菜单事件
    private void initToolbar() {
        //代理 设置
        this.proxySetupBtn.setOnAction((event) -> {
            Alert inputDialog = new Alert(AlertType.NONE);
            Window window = inputDialog.getDialogPane().getScene().getWindow();
            window.setOnCloseRequest((e) -> {
                window.hide();
            });
            ToggleGroup statusGroup = new ToggleGroup();
            RadioButton enableRadio = new RadioButton("启用");
            RadioButton disableRadio = new RadioButton("禁用");
            enableRadio.setToggleGroup(statusGroup);
            disableRadio.setToggleGroup(statusGroup);
            disableRadio.setSelected(true);
            HBox statusHbox = new HBox();
            statusHbox.setSpacing(10.0D);
            statusHbox.getChildren().add(enableRadio);
            statusHbox.getChildren().add(disableRadio);
            GridPane proxyGridPane = new GridPane();
            proxyGridPane.setVgap(15.0D);
            proxyGridPane.setPadding(new Insets(20.0D, 20.0D, 0.0D, 10.0D));
            Label typeLabel = new Label("类型：");
            ComboBox typeCombo = new ComboBox();
            typeCombo.setItems(FXCollections.observableArrayList(new String[]{"HTTP", "SOCKS"}));
            typeCombo.getSelectionModel().select(0);
            Label IPLabel = new Label("IP地址：");
            TextField IPText = new TextField();
            Label PortLabel = new Label("端口：");
            TextField PortText = new TextField();
            Label userNameLabel = new Label("用户名：");
            TextField userNameText = new TextField();
            Label passwordLabel = new Label("密码：");
            TextField passwordText = new TextField();
            Button cancelBtn = new Button("取消");
            Button saveBtn = new Button("保存");


            try {
                Proxy proxy = (Proxy)settingInfo.get("proxy");

                if (proxy != null) {
                    enableRadio.setSelected(true);

                } else {
                    disableRadio.setSelected(true);
                }

                if(settingInfo.size() > 0) {
                    String type = (String)settingInfo.get("type");
                    if (type.equals("HTTP")) {
                        typeCombo.getSelectionModel().select(0);
                    } else if (type.equals("SOCKS")) {
                        typeCombo.getSelectionModel().select(1);
                    }

                    String ip = (String)settingInfo.get("ip");
                    String port = (String)settingInfo.get("port");
                    IPText.setText(ip);
                    PortText.setText(port);
                    String username = (String)settingInfo.get("username");
                    String password = (String)settingInfo.get("password");
                    userNameText.setText(username);
                    passwordText.setText(password);
                }


            } catch (Exception var28) {
                this.proxyStatusLabel.setText("代理服务器配置加载失败。");
                var28.printStackTrace();
            }


            saveBtn.setOnAction((e) -> {
                if (disableRadio.isSelected()) {
                    this.settingInfo.put("proxy", (Object)null);
                    this.proxyStatusLabel.setText("");
                    inputDialog.getDialogPane().getScene().getWindow().hide();
                } else {

                    final String type;
                    if (!userNameText.getText().trim().equals("")) {
                        final String proxyUser = userNameText.getText().trim();
                        type = passwordText.getText();
                        Authenticator.setDefault(new Authenticator() {
                            public PasswordAuthentication getPasswordAuthentication() {
                                return new PasswordAuthentication(proxyUser, type.toCharArray());
                            }
                        });
                    } else {
                        Authenticator.setDefault((Authenticator)null);
                    }

                    this.settingInfo.put("username", userNameText.getText());
                    this.settingInfo.put("password", passwordText.getText());
                    InetSocketAddress proxyAddr = new InetSocketAddress(IPText.getText(), Integer.parseInt(PortText.getText()));

                    this.settingInfo.put("ip", IPText.getText());
                    this.settingInfo.put("port", PortText.getText());
                    String proxy_type = typeCombo.getValue().toString();
                    settingInfo.put("type", proxy_type);
                    Proxy proxy;
                    if (proxy_type.equals("HTTP")) {
                        proxy = new Proxy(Proxy.Type.HTTP, proxyAddr);
                        this.settingInfo.put("proxy", proxy);
                    } else if (proxy_type.equals("SOCKS")) {
                        proxy = new Proxy(Proxy.Type.SOCKS, proxyAddr);
                        this.settingInfo.put("proxy", proxy);
                    }

                    this.proxyStatusLabel.setText("代理生效中");
                    inputDialog.getDialogPane().getScene().getWindow().hide();
                }
            });

            cancelBtn.setOnAction((e) -> {
                inputDialog.getDialogPane().getScene().getWindow().hide();
            });
            proxyGridPane.add(statusHbox, 1, 0);
            proxyGridPane.add(typeLabel, 0, 1);
            proxyGridPane.add(typeCombo, 1, 1);
            proxyGridPane.add(IPLabel, 0, 2);
            proxyGridPane.add(IPText, 1, 2);
            proxyGridPane.add(PortLabel, 0, 3);
            proxyGridPane.add(PortText, 1, 3);
            proxyGridPane.add(userNameLabel, 0, 4);
            proxyGridPane.add(userNameText, 1, 4);
            proxyGridPane.add(passwordLabel, 0, 5);
            proxyGridPane.add(passwordText, 1, 5);
            HBox buttonBox = new HBox();
            buttonBox.setSpacing(20.0D);
            buttonBox.setAlignment(Pos.CENTER);
            buttonBox.getChildren().add(cancelBtn);
            buttonBox.getChildren().add(saveBtn);
            GridPane.setColumnSpan(buttonBox, 2);
            proxyGridPane.add(buttonBox, 0, 6);
            inputDialog.getDialogPane().setContent(proxyGridPane);
            inputDialog.showAndWait();
        });

        //fofa 设置
        this.fofa_setting.setOnAction((event) -> {
            Alert inputDialog = new Alert(AlertType.NONE);
            Window window = inputDialog.getDialogPane().getScene().getWindow();
            window.setOnCloseRequest((e) -> {
                window.hide();
            });

            HBox statusHbox = new HBox();
            statusHbox.setSpacing(10.0D);

            GridPane proxyGridPane = new GridPane();
            proxyGridPane.setVgap(15.0D);
            proxyGridPane.setPadding(new Insets(20.0D, 20.0D, 0.0D, 10.0D));
            Label fofaEmailLabel = new Label("fofa_email：");
            TextField fofaEmailText = new TextField();
            Label fofaKeyLabel = new Label("fofa_key：");
            TextField fofaKeyText = new TextField();

            Button cancelBtn = new Button("取消");

            Button saveBtn = new Button("保存");
            File file = new File(Constants.FOFAPATH);
            try {
                if (file.exists()) {
                    String values = Tools.read(Constants.FOFAPATH,"UTF-8", false).toString();
                    values = values.substring(1,values.length()-1);;

                    System.out.println(values);
                    String[] EmaliKey = values.split(":");
                    if(EmaliKey.length == 2) {
                        String email = EmaliKey[0];
                        String key = EmaliKey[1];
                        fofaEmailText.setText(email);
                        fofaKeyText.setText(key);
                        this.settingInfo.put("fofa_email", email);
                        this.settingInfo.put("fofa_key", key);
                    } else {
                        Alert alert = new Alert(AlertType.INFORMATION);
                        alert.setTitle("提示");
                        alert.setHeaderText(null);
                        alert.setContentText("fofa 配置错误\n");

                        alert.showAndWait();
                    }
                }


            } catch (Exception var28) {
                this.proxyStatusLabel.setText("fofa配置加载失败。");
                var28.printStackTrace();
            }


            saveBtn.setOnAction((e) -> {
                this.settingInfo.put("fofa_email", fofaEmailText.getText());
                this.settingInfo.put("fofa_key", fofaKeyText.getText());
                try {
                    if (!file.exists()) {
                        file.createNewFile();
                        Tools.write(Constants.FOFAPATH, fofaEmailText.getText() + ":" + fofaKeyText.getText());
                        System.out.println("fofa配置已保存");
                    } else {
                        Tools.write(Constants.FOFAPATH, fofaEmailText.getText() + ":" + fofaKeyText.getText());
                    }
                } catch (IOException e1) {
                    e1.printStackTrace();
                }

                this.proxyStatusLabel.setText("fofa配置已保存");
                inputDialog.getDialogPane().getScene().getWindow().hide();

            });

            cancelBtn.setOnAction((e) -> {
                inputDialog.getDialogPane().getScene().getWindow().hide();
            });
            proxyGridPane.add(statusHbox, 1, 0);
            proxyGridPane.add(fofaEmailLabel, 0, 2);
            proxyGridPane.add(fofaEmailText, 1, 2);
            proxyGridPane.add(fofaKeyLabel, 0, 3);
            proxyGridPane.add(fofaKeyText, 1, 3);
            HBox buttonBox = new HBox();
            buttonBox.setAlignment(Pos.CENTER);
            buttonBox.setSpacing(20.0D);
            buttonBox.getChildren().add(cancelBtn);
            buttonBox.getChildren().add(saveBtn);
            GridPane.setColumnSpan(buttonBox, 2);
            proxyGridPane.add(buttonBox, 0, 6);
            inputDialog.getDialogPane().setContent(proxyGridPane);
            inputDialog.showAndWait();
        });
    }


    // 界面显示  一些默认的基本信息，漏洞列表、编码选项、线程、shell、页脚
    public void defaultInformation() {
        this.choice_cve.setValue(Constants.CVES[0]);
        for (String cve : Constants.CVES) {
            this.choice_cve.getItems().add(cve);
        }

        this.encoding.setValue(Constants.ENCODING[0]);
        for (String coding : Constants.ENCODING) {
            this.encoding.getItems().add(coding);
        }

        this.thread.setValue(10);
        for(int i=1; i<30; i++) {
            this.thread.getItems().add(i);
        }


        this.fofa_size.setValue(100);
        for(int i : Constants.SIZE) {
            this.fofa_size.getItems().add(i);
        }
        // 默认为冰蝎3 的shell
        this.upload_info.setText(Constants.SHELL);
        this.upload_info.setWrapText(true);

        // 命令执行
        this.cmd_info.setText(" ");
        this.cmd_info.setEditable(false);
        this.cmd_info.setWrapText(true);

        this.upload_msg.setText("默认为 冰蝎3 的shell.jspx , 密码：rebeyond");


        this.platform.setValue("Linux");
        this.platform.getItems().add("Linux");
        this.platform.getItems().add("Windows");

        this.time.setText((String.format(this.time.getText(), 0)));

        this.fofa_result_info.setText("\r\n\r\n\r\n\t\t在 设置 -> FOFA 中设置fofa邮箱和key，之后保存（保存后，会在当前目录下生成fofa.conf文件，供以后使用加载）\r\n\r\n" +
                "\t\tFOFA:\t查询\r\n\r\n\t\tCheck:\t一键导入到批量检查中进行漏洞检测\r\n\r\n" +
                "\t\tICON:\t通过输入icon的url，计算hash值，供fofa高级会员查询icon hash");

        // 页脚
        this.tool_name.setText(String.format(this.tool_name.getText(), Constants.NAME, Constants.VERSION));
        this.author.setText(String.format(this.author.getText(), Constants.AUTHOR));

    }

    // 基本信息
    public void basic() {
        this.basic_info.setText(Constants.BASICINFO);
        this.basic_info.setEditable(false);
        this.basic_info.setWrapText(true);

    }


    // 点击检测，获取url 和 要检测的漏洞
    @FXML
    public void get_url() {
        String url = this.url.getText().trim();
        String cve = this.choice_cve.getValue().toString().trim();

        if(Tools.checkTheURL(url)) {
            this.ei = Tools.getExploit(cve);

            try {

                if(this.ei.checkVUL(url)) {
                    this.basic_info.setText(url + " 存在 " + cve + "漏洞 \r\n");
                } else {
                    this.basic_info.setText(url + " 不存在 " + cve + "漏洞 \r\n");
                }
            } catch (Exception e) {
                this.basic_info.setText("检测异常 \r\n" + e.toString());
            }

        } else {
            Tools.alert("URL检查", "URL格式不符合要求，示例：http://127.0.0.1:7001/");
        }

    }

    // 命令执行
    @FXML
    public void get_execute_cmd() {
        String cmd = this.cmd.getText();
        String encoding = this.encoding.getValue().toString().trim();
        if(cmd.length() == 0) {
            cmd = "whoami";
        }

        if(this.ei.isVul()) {
            try {
                String result = this.ei.exeCMD(cmd, encoding);
                this.cmd_info.setText(result);
                System.out.println(result);
            } catch (Exception var4) {
                this.cmd_info.setText(var4.toString());
            }

        }

    }

    // 点击上传文件，获取上传的文件信息
    @FXML
    public void get_shell_file() {

        String shell_info = this.upload_info.getText();
        String upload_path = this.upload_path.getText();
        String platform = this.platform.getValue().toString().trim();


        if(upload_path.length() == 0) {
            upload_path = "test.jspx";
        }

        if(shell_info.length() > 0) {

            if(this.ei.isVul()) {
                try {
                    String web_shell_path = this.ei.uploadFile(shell_info, upload_path, platform);

                    this.upload_msg.setText("文件上传成功！地址：" + web_shell_path);
                } catch (Exception var4) {
                    this.upload_msg.setText(var4.toString());
                }

            } else {
                this.upload_msg.setText("文件上传失败！");
                System.out.println( this.ei.isVul());

            }

        } else {
            Tools.alert("文件上传", "上传的文件不能为空");
        }


    }

    // 双击时复制url
    private void copyString(String str) {
        Clipboard clipboard = Clipboard.getSystemClipboard();
        ClipboardContent content = new ClipboardContent();
        content.putString(str);
        clipboard.setContent(content);
    }

    // 批量检测数据映射到图形化界面表格中
    public void table_view(HashSet<String> values) {
        int i = 0;

        long startTime = System.currentTimeMillis(); //程序开始记录时间

        // 获取用户选择的线程池数量， 创建对应容量的线程池。
        int n = new Integer(this.thread.getValue().toString());

        ExecutorService pool = Executors.newFixedThreadPool(n);
        String cve = this.choice_cve.getValue().toString().trim();
        try {
            // 读取每行的目标
            for(String target: values) {
                i++;
                Job t = new Job(target, cve);
                // 线程池
                Future f = pool.submit(t);
                String isVul = f.get().toString();

                this.datas.add(new VulInfo(String.valueOf(i), target, isVul));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }


        //映射数据进每列
        this.id.setCellValueFactory(new PropertyValueFactory("id"));
        this.id.setSortable(false);

        this.target.setCellValueFactory(new PropertyValueFactory("target"));
        this.target.setSortable(false);

        this.isVul.setCellValueFactory(new PropertyValueFactory("isVul"));

        // 所有项目添加进datas
        this.table_view.setItems(this.datas);


        long endTime   = System.currentTimeMillis(); //程序结束记录时间
        long totalTime = endTime - startTime;       //总消耗时间 ,毫秒
        this.time.setText((String.format("用时 %s s", (double)totalTime/1000)));
        //双击复制url
        this.table_view.setRowFactory( tv -> {
            TableRow<VulInfo> row = new TableRow<VulInfo>();
            row.setOnMouseClicked(event -> {
                if (event.getClickCount() == 2 && (! row.isEmpty()) ) {
                    VulInfo url = row.getItem();
                    url.getTarget();
                    this.copyString(url.getTarget());
                }
            });
            return row;
        });

    }

    @FXML
    // url批量导入
    public void batch_test() {
        this.datas.clear();
        Stage stage = new Stage();
        FileChooser fileChooser = new FileChooser();
        FileChooser.ExtensionFilter extFilter = new FileChooser.ExtensionFilter("TXT files (*.txt)", "*.txt");
        fileChooser.getExtensionFilters().add(extFilter);
        File file = fileChooser.showOpenDialog(stage); // 文件路径

        this.file_path.setText(file.toString());

        HashSet<String> values = Tools.read(file.toString(), "UTF-8", true);

        table_view(values);
    }


    @FXML
    // 导出漏洞存在的url
    public void export() {

        FileChooser fileChooser = new FileChooser();
        FileChooser.ExtensionFilter extFilter = new FileChooser.ExtensionFilter("TXT files (*.txt)", "*.txt");
        fileChooser.getExtensionFilters().add(extFilter);
        Stage s = new Stage();
        File file = fileChooser.showSaveDialog(s);
        if (file == null)
            return;
        if(file.exists()){ //文件已存在，则删除覆盖文件
            file.delete();
        }
        String exportFilePath = file.getAbsolutePath();

        StringBuilder sBuilder = new StringBuilder();
        if (this.datas.size() > 0) {
            for(VulInfo vulInfo: this.datas) {
                if(vulInfo.getIsVul().equals("存在")) {
                    System.out.println(vulInfo.getTarget());
                    sBuilder.append(vulInfo.getTarget() + "\r\n");
                }

            }
        }
        if(Tools.write(exportFilePath, sBuilder.toString())) {
            System.out.println("文件创建成功！");
            Alert alert = new Alert(AlertType.INFORMATION);
            alert.setTitle("提示");
            alert.setHeaderText(null);
            alert.setContentText("导出成功!保存路径:\n"+exportFilePath);

            alert.showAndWait();
        }


    }


    @FXML
    // fofa 搜索
    public void fofa_search() {

        int page = (int) this.fofa_size.getValue();

        String fofa_info = this.fofa_info.getText();

        if(fofa_info.length() == 0) {
            fofa_info = "app=\"Solr\"";
        }

        String result = "";

        File file = new File(Constants.FOFAPATH);
        try {
            if (file.exists()) {
                String values = Tools.read(Constants.FOFAPATH,"UTF-8", false).toString();
                values = values.substring(1,values.length()-1);;

                System.out.println(values);
                String[] EmaliKey = values.split(":");
                if(EmaliKey.length == 2) {
                    String email = EmaliKey[0];
                    String key = EmaliKey[1];
                    result = Tools.fofaHTTP(email, key, fofa_info, page);

                    String[] str = result.split("\r\n");
                    for (String s:str) {
                        fofa_result.add(s);
                    }

                    this.proxyStatusLabel.setText("fofa查询完成");

                } else {
                    Alert alert = new Alert(AlertType.INFORMATION);
                    alert.setTitle("提示");
                    alert.setHeaderText(null);
                    alert.setContentText("fofa 配置错误\n");

                    alert.showAndWait();
                }
            }


        } catch (Exception e) {
            e.printStackTrace();
            result = e.getStackTrace().toString();
        }


        fofa_check.setOnAction((e) -> {
            table_view(fofa_result);
            this.proxyStatusLabel.setText("批量检查完成，请到批量检查界面查看");

        });

        this.fofa_result_info.setText(result);

    }

    // fofa icon 计算
    public void fofa_icon() {
        Alert inputDialog = new Alert(AlertType.NONE);
        inputDialog.setTitle("ICON Hash 计算");
        Window window = inputDialog.getDialogPane().getScene().getWindow();
        window.setOnCloseRequest((e) -> {
            window.hide();
        });

        HBox statusHbox = new HBox();
        statusHbox.setSpacing(20.0D);

        GridPane proxyGridPane = new GridPane();
        proxyGridPane.setVgap(15.0D);
        proxyGridPane.setPadding(new Insets(20.0D, 20.0D, 0.0D, 10.0D));
        Label iconUrlLabel = new Label("icon url：");
        TextField iconUrlText = new TextField();
        Label iconHashLabel = new Label("iconHash：");
        TextField iconHashText = new TextField();

        Button iconHash = new Button("iconHash");


        iconHash.setOnAction((e) -> {

            String ste = HttpTool.ImageToBase64ByOnline(iconUrlText.getText());

            int hashcode = Hashing.murmur3_32().hashString(ste.replaceAll("\r", "") + "\n", StandardCharsets.UTF_8).asInt();

            iconHashText.setText("icon_hash=\"" + hashcode + "\"");


            System.out.println(ste);
            System.out.println(hashcode);

        });


        proxyGridPane.add(statusHbox, 1, 0);
        proxyGridPane.add(iconUrlLabel, 0, 2);
        proxyGridPane.add(iconUrlText, 1, 2);
        proxyGridPane.add(iconHashLabel, 0, 3);
        proxyGridPane.add(iconHashText, 1, 3);
        HBox buttonBox = new HBox();
        buttonBox.setAlignment(Pos.CENTER);
        buttonBox.setSpacing(20.0D);
        buttonBox.getChildren().add(iconHash);
        GridPane.setColumnSpan(buttonBox, 2);
        proxyGridPane.add(buttonBox, 0, 5);
        inputDialog.getDialogPane().setContent(proxyGridPane);
        inputDialog.showAndWait();
    }


    // 加载
    public void initialize() {
        try {
            this.initToolbar();
            this.defaultInformation();
            this.basic();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
