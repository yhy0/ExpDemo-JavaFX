package fun.fireline.controller;

import com.jfoenix.controls.JFXButton;
import com.jfoenix.controls.JFXDrawer.DrawerDirection;
import com.jfoenix.controls.JFXDrawer;
import com.jfoenix.controls.JFXDrawersStack;
import com.jfoenix.controls.JFXHamburger;
import com.jfoenix.transitions.hamburger.HamburgerBackArrowBasicTransition;
import de.jensd.fx.glyphs.fontawesome.FontAwesomeIconView;
import fun.fireline.core.Constants;
import fun.fireline.tools.Tools;
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
import javafx.scene.layout.*;
import javafx.scene.paint.Paint;
import javafx.stage.Window;
import org.apache.log4j.Logger;

import javax.xml.soap.Text;
import java.awt.*;
import java.io.File;
import java.io.IOException;
import java.net.*;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;


public class MainController {
    private static final Logger logger = Logger.getLogger(MainController.class);

    @FXML
    private Label tool_name;
    @FXML
    public static Label proxyStatusLabel = new Label();
    @FXML
    private Label author;

    @FXML
    private AnchorPane body;

    @FXML
    private AnchorPane content;

    @FXML
    private JFXHamburger hamburger;

    private HamburgerBackArrowBasicTransition ht;

    private JFXDrawersStack drawersStack;

    private JFXDrawer leftDrawer;

    @FXML
    private Label title;

    @FXML
    private FontAwesomeIconView titleIcon;

    @FXML
    private MenuItem fofa_setting;

    @FXML
    private MenuItem proxySetupBtn;

    // 设置相关信息保存
    public static Map<String, Object> settingInfo = new HashMap();

    public JFXButton yhy;

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

        TextArea textArea = new TextArea(Constants.BASICINFO);
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


            } catch (Exception var) {
                this.proxyStatusLabel.setText("代理服务器配置加载失败。");
                logger.error(var.getStackTrace());
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
            Alert inputDialog = new Alert(Alert.AlertType.NONE);
            Window window = inputDialog.getDialogPane().getScene().getWindow();
            window.setOnCloseRequest((e) -> {
                window.hide();
            });
            inputDialog.setTitle("fofa 设置");
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
                        Alert alert = new Alert(Alert.AlertType.INFORMATION);
                        alert.setTitle("提示");
                        alert.setHeaderText(null);
                        alert.setContentText("fofa 配置错误\n");

                        alert.showAndWait();
                    }
                }


            } catch (Exception var) {
                this.proxyStatusLabel.setText("fofa配置加载失败。");
                logger.error(var.getStackTrace());
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

                proxyStatusLabel.setText("fofa配置已保存");
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


    // 加载
    @FXML
    public void initialize() {
        // 设置
        this.initToolbar();

        // 页脚
        this.tool_name.setText(String.format(this.tool_name.getText(), Constants.NAME, Constants.VERSION));
        this.author.setText(String.format(this.author.getText(), Constants.AUTHOR));

        drawersStack = new JFXDrawersStack();
        // drawer的起始位置定点，默认0
        drawersStack.setLayoutY(29);
//        drawersStack.setLayoutX(100);
        body.getChildren().add(drawersStack);

        leftDrawer = new JFXDrawer();
        VBox vBox = null;
        try {
            vBox = FXMLLoader.load(Objects.requireNonNull(getClass().getClassLoader().getResource("fxml/drawer.fxml")));
        } catch (IOException e) {
            e.printStackTrace();
        }
        // lambda 表达式获取 drawer 中的按钮，切换界面
        for (Node node: vBox.getChildren()){
            if (node.getAccessibleText() != null){
                node.addEventHandler(MouseEvent.MOUSE_CLICKED, (e) -> {
                    String page = node.getAccessibleText();
                    if (page.equals("yhy")) {
                        try {
                            Desktop.getDesktop().browse(new URL("https://github.com/yhy0").toURI());
                        } catch (Exception e1) {
                            logger.error(e1.getStackTrace());
                        }
                    } else {
                        refreshPage(node.getAccessibleText());
                        toggerDrawer();
                    }

                });
            }
        }
        leftDrawer.setSidePane(vBox);
        leftDrawer.setDirection(DrawerDirection.LEFT); // 默认 LEFT
        leftDrawer.setDefaultDrawerSize(160);
        leftDrawer.setResizeContent(false);
        leftDrawer.setOverLayVisible(false);
        leftDrawer.setResizableOnDrag(true);


        //hamburger 点击动态切换
        ht = new HamburgerBackArrowBasicTransition(hamburger);
        ht.setRate(-1);
        hamburger.addEventHandler(MouseEvent.MOUSE_PRESSED, e -> {
            toggerDrawer();
        });

        //抽屉打开状态下，点击content抽屉以关闭
        content.addEventHandler(MouseEvent.MOUSE_CLICKED, (e) -> {
            if (ht.getRate()!= -1){
                toggerDrawer();
            }
        });

        refreshPage("Others");

    }

    private void refreshPage(String page){
        try {
            content.getChildren().clear();
            AnchorPane contentPage = FXMLLoader.load(getClass().getClassLoader().getResource("fxml/" + page + ".fxml"));

            content.getChildren().add(contentPage);
            switch (page){
                case "Struts2" : {
                    title.setText("Struts2");
                    titleIcon.setGlyphName("SCRIBD");
                    titleIcon.setFill(Paint.valueOf("#4d9dab"));
                    return;
                }
                case "Weblogic" : {
                    title.setText("Weblogic");
                    titleIcon.setGlyphName("GOOGLE_WALLET");
                    titleIcon.setFill(Paint.valueOf("#d72f2f"));
                    return;
                }
                case "Shiro": {
                    title.setText("Shiro");
                    titleIcon.setGlyphName("LASTFM");
                    titleIcon.setFill(Paint.valueOf("#176129"));
                    return;
                }
                case "Fastjson" : {
                    title.setText("Fastjson");
                    titleIcon.setGlyphName("FOURSQUARE");
                    titleIcon.setFill(Paint.valueOf("#2b5d97"));
                    return;
                }
                case "Others" : {
                    title.setText("Others");
                    titleIcon.setGlyphName("XING");
                    titleIcon.setFill(Paint.valueOf("#2b5d97"));
                    return;
                }
            }
        } catch (IOException e) {
            logger.error(e.getStackTrace());
        }
    }

    private void toggerDrawer() {
        ht.setRate(ht.getRate() * -1);
        ht.play();
        drawersStack.toggle(leftDrawer);
    }

}
