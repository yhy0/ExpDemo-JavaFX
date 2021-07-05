package fun.fireline.controller;

import com.alibaba.fastjson.JSONObject;
import com.google.common.hash.Hashing;
import fun.fireline.core.*;
import fun.fireline.tools.HttpTool;
import fun.fireline.tools.Tools;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.fxml.FXML;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.control.*;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.input.Clipboard;
import javafx.scene.input.ClipboardContent;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.HBox;
import javafx.scene.text.Text;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import javafx.stage.Window;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

/**
 * @author yhy
 * @date 2021/7/3 13:15
 * @github https://github.com/yhy0
 */

// JavaFX图形化界面的控制类
public class Struts2Controller {
    @FXML
    private ChoiceBox<String> choice_cve;
    @FXML
    private ChoiceBox<String> encoding;
    @FXML
    private ChoiceBox<String> platform;
    @FXML
    private ChoiceBox<Integer> thread;
    @FXML
    private ChoiceBox<Integer> fofa_size;
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
    private Button fofa_check;

    // fofa 结果
    public static HashSet<String> fofa_result = new HashSet<String>();

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
                this.cmd_info.setText("error: " + var4.toString());
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

        String cve = this.choice_cve.getValue().toString().trim();

        ExecutorService pool = Executors.newFixedThreadPool(n);

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
        this.id.setCellValueFactory(new PropertyValueFactory<>("id"));
        this.id.setSortable(false);

        this.target.setCellValueFactory(new PropertyValueFactory<>("target"));
        this.target.setSortable(false);

        this.isVul.setCellValueFactory(new PropertyValueFactory<>("isVul"));

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
            Alert alert = new Alert(Alert.AlertType.INFORMATION);
            alert.setTitle("提示");
            alert.setHeaderText(null);
            alert.setContentText("导出成功!保存路径:\n"+exportFilePath);

            alert.showAndWait();
        }


    }


    @FXML
    // fofa 搜索
    public void fofa_search() {
        String result = "";
        try {
            int page = this.fofa_size.getValue();

            String fofa_info = this.fofa_info.getText();

            if(fofa_info.length() == 0) {
                fofa_info = "app=\"Solr\"";
            }

            File file = new File(Constants.FOFAPATH);

            if (file.exists()) {
                String values = Tools.read(Constants.FOFAPATH,"UTF-8", false).toString();
                values = values.substring(1,values.length()-1);;

                System.out.println(values);
                String[] EmaliKey = values.split(":");
                if(EmaliKey.length == 2) {
                    String email = EmaliKey[0];
                    String key = EmaliKey[1];

                    String fResult = Tools.fofaHTTP(email, key, fofa_info, page, fofa_result_info);

                    JSONObject object = (JSONObject) JSONObject.parse(fResult);
                    List<String> listStr = object.parseArray(object.getJSONArray("results").toJSONString(), String.class);

                    for (String s:listStr) {
                        s = s.replace("\"","").replace("\\r\\n","").replace("\\t","");
                        String host = s.split(",", 2)[0].replace("[","");
                        String title = s.split(",", 2)[1].replace("]","");
                        result += host + "\t\t\t" + title + "\r\n";
                        this.fofa_result.add(host);
                    }

                    MainController.proxyStatusLabel.setText("fofa查询完成");

                } else {
                    Alert alert = new Alert(Alert.AlertType.INFORMATION);
                    alert.setTitle("提示");
                    alert.setHeaderText(null);
                    alert.setContentText("fofa 配置错误\n");

                    alert.showAndWait();

                    MainController.proxyStatusLabel.setText("asasdadas配置错误");
                }
            } else {
                this.fofa_result_info.setText("fofa.conf文件没找到！！！！！\r\n");
            }


        } catch (Exception e) {
            e.printStackTrace();
            result = e.getStackTrace().toString();

        }

        this.fofa_result_info.setText(result);

        fofa_check.setOnAction((e) -> {
            table_view(fofa_result);
            MainController.proxyStatusLabel.setText("批量检查完成，请到批量检查界面查看");

        });


    }

    // fofa icon 计算
    public void fofa_icon() {
        Alert inputDialog = new Alert(Alert.AlertType.NONE);
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
            this.defaultInformation();
            this.basic();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
