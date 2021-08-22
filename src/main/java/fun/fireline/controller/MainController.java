package fun.fireline.controller;

import com.jfoenix.controls.JFXButton;
import fun.fireline.core.Constants;
import javafx.collections.FXCollections;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Node;
import javafx.scene.control.*;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.MenuItem;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.image.Image;
import javafx.scene.image.ImageView;
import javafx.scene.input.MouseEvent;
import javafx.scene.layout.AnchorPane;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;
import javafx.stage.Window;
import org.apache.log4j.Logger;

import java.awt.*;
import java.net.*;
import java.util.HashMap;
import java.util.Map;

// 主页面相关逻辑
public class MainController  {
    public static  Logger logger = Logger.getLogger(MainController.class);
    @FXML
    private MenuItem proxySetupBtn;
    @FXML
    private Label tool_name;
    @FXML
    private Label author;
    @FXML
    private Label proxyStatusLabel;
    @FXML
    private VBox selectButton;      // 漏洞种类按钮
    @FXML
    private AnchorPane content;     // 按钮对应的功能
    @FXML
    private JFXButton yhy;



    public static Map<String, Object> history = new HashMap<String, Object>();

    // 设置相关信息保存
    public static Map<String, Object> settingInfo = new HashMap();

    // 监听菜单关于事件
    @FXML
    public void about() {
        Alert alert = new Alert(Alert.AlertType.NONE);
        // 点 x 退出
        Window window = alert.getDialogPane().getScene().getWindow();
        window.setOnCloseRequest((e) -> {
            window.hide();
        });

        DialogPane dialogPane = new DialogPane();

        TextArea textArea = new TextArea(Constants.UPDATEINFO);
        textArea.setEditable(false);
        textArea.setWrapText(true);

        dialogPane.setContent(textArea);

        Image image = new Image((getClass().getResource("/img/weixin.jpg")).toString());
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
            Alert inputDialog = new Alert(Alert.AlertType.NONE);
            Window window = inputDialog.getDialogPane().getScene().getWindow();
            window.setOnCloseRequest((e) -> {
                window.hide();
            });
            inputDialog.setTitle("代理设置");
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
            TextField IPText = new TextField("127.0.0.1");
            Label PortLabel = new Label("端口：");
            TextField PortText = new TextField("8080");
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


            } catch (Exception var) {
                proxyStatusLabel.setText("代理服务器配置加载失败。");
                logger.debug(var);
            }


            saveBtn.setOnAction((e) -> {
                if (disableRadio.isSelected()) {
                    settingInfo.put("proxy", (Object)null);
                    proxyStatusLabel.setText("");
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

                    settingInfo.put("username", userNameText.getText());
                    settingInfo.put("password", passwordText.getText());
                    InetSocketAddress proxyAddr = new InetSocketAddress(IPText.getText(), Integer.parseInt(PortText.getText()));

                    settingInfo.put("ip", IPText.getText());
                    settingInfo.put("port", PortText.getText());
                    String proxy_type = typeCombo.getValue().toString();
                    settingInfo.put("type", proxy_type);
                    Proxy proxy;
                    if (proxy_type.equals("HTTP")) {
                        proxy = new Proxy(Proxy.Type.HTTP, proxyAddr);
                        settingInfo.put("proxy", proxy);
                    } else if (proxy_type.equals("SOCKS")) {
                        proxy = new Proxy(Proxy.Type.SOCKS, proxyAddr);
                        settingInfo.put("proxy", proxy);
                    }

                    proxyStatusLabel.setText("代理生效中");
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
    }

    // 加载
    @FXML
    public void initialize() {
        // 设置
        this.initToolbar();
        // 页脚
        this.tool_name.setText(String.format(this.tool_name.getText(), Constants.NAME, Constants.VERSION));
        this.author.setText(String.format(this.author.getText(), Constants.AUTHOR));

        this.yhy.setOnAction((e) -> {
            try {
                Desktop.getDesktop().browse(new URL("https://github.com/yhy0").toURI());
            } catch (Exception e1) {
                logger.debug(e1);
            }
        });

        // lambda 表达式获取 drawer 中的按钮，切换界面
        for (Node node: selectButton.getChildren()){
            if (node.getAccessibleText() != null){
                node.addEventHandler(MouseEvent.MOUSE_CLICKED, (e) -> {
                    refreshPage(node.getAccessibleText());
                });
            }
        }
        refreshPage("Others");
    }

    private void refreshPage(String page){
        try {
            this.content.getChildren().clear();
            AnchorPane contentPage = FXMLLoader.load(getClass().getClassLoader().getResource("fxml/" + page + ".fxml"));

            this.content.getChildren().add(contentPage);
        } catch (Exception e) {
            logger.debug(e);
        }
    }

    public void setProxyStatusLabel(String value) {
        this.proxyStatusLabel.setText(value);
    }

}