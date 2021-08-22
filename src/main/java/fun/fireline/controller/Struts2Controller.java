package fun.fireline.controller;

import com.jfoenix.controls.JFXButton;
import fun.fireline.core.Constants;
import fun.fireline.core.ExploitInterface;
import fun.fireline.core.Job;
import fun.fireline.core.VulCheckTask;
import fun.fireline.exp.apache.struts2.*;
import fun.fireline.tools.Tools;

import javafx.fxml.FXML;
import javafx.scene.control.*;


import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;


/**
 * @author yhy
 * @date 2021/7/3 13:15
 * @github https://github.com/yhy0
 */

// JavaFX图形化界面的控制类
public class Struts2Controller extends MainController{
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

    private ExploitInterface ei;

    public static String BASICINFO = Constants.SECURITYSTATEMENT +

            "支持检测: \r\n" +
            "\ts2-005: \tXWork ParameterInterceptors 绕过允许远程命令执行   https://cwiki.apache.org/confluence/display/WW/S2-005 \r\n" +
            "\ts2-009: \tParameterInterceptor 漏洞允许远程命令执行   https://cwiki.apache.org/confluence/display/WW/S2-009 \r\n" +
            "\ts2-016: \t通过操纵前缀为“action:”/“redirect:”/“redirectAction:”的参数引入的漏洞允许远程命令执行   https://cwiki.apache.org/confluence/display/WW/S2-016 \r\n" +
            "\ts2-019: \t动态方法执行   https://cwiki.apache.org/confluence/display/WW/S2-019 \r\n" +
            "\ts2-032: \t启用动态方法调用时，可以通过 method: 前缀执行远程代码执行   https://cwiki.apache.org/confluence/display/WW/S2-032 \r\n" +
            "\ts2-045: \t基于 Jakarta Multipart 解析器执行文件上传时可能的远程代码执行   https://cwiki.apache.org/confluence/display/WW/S2-045 \r\n" +
            "\ts2-046: \t基于 Jakarta Multipart 解析器执行文件上传时可能的 RCE（类似于 S2-045）   https://cwiki.apache.org/confluence/display/WW/S2-046 \r\n" +
            "\ts2-devMode: \t当Struts2开启devMode模式时，将导致严重远程代码执行漏洞 \r\n\r\n\r\n" +

            Constants.UPDATEINFO;

    public static String[] STRUTS2 = {
            "all",
            "S2-005",
            "S2-009",
            "S2-016",
            "S2-019",
            "S2-032",
            "S2-045",
            "S2-046",
            "S2-DevMode",
    };



    // 界面显示  一些默认的基本信息，漏洞列表、编码选项、线程、shell、页脚
    public void defaultInformation() {
        this.choice_cve.setValue(STRUTS2[0]);
        for (String cve : STRUTS2) {
            this.choice_cve.getItems().add(cve);
        }
        this.encoding.setValue(Constants.ENCODING[0]);

        for (String coding : Constants.ENCODING) {
            this.encoding.getItems().add(coding);
        }

        // 默认为冰蝎3 的shell
        this.upload_info.setText(Constants.SHELL);
        this.upload_info.setWrapText(true);

        // 命令执行
        this.cmd_info.setText(" ");
        this.cmd_info.setWrapText(true);

        this.upload_msg.setText("默认为 冰蝎3 Bate 11 的shell.jsp , 密码：rebeyond");


        this.platform.setValue("Linux");
        this.platform.getItems().add("Linux");
        this.platform.getItems().add("Windows");

    }

    // 基本信息
    public void basic() {
        // 切换界面保留原来的记录
        // 基本信息的历史记录
        if(history.containsKey("Struts2_url")) {
            this.url.setText((String) history.get("Struts2_url"));
        }
        if(history.containsKey("Struts2_vulName")) {
            this.choice_cve.setValue((String) history.get("Struts2_vulName"));
        }
        if(history.containsKey("Struts2_ei")) {
            this.ei = (ExploitInterface) history.get("Struts2_ei");
        }
        if(history.containsKey("Struts2_basic_info")) {
            this.basic_info.setText((String) history.get("Struts2_basic_info"));
        } else {
            this.basic_info.setText(BASICINFO);
        }
        this.basic_info.setWrapText(true);

        // 命令执行的历史记录
        if(history.containsKey("Struts2_cmd")) {
            this.cmd.setText((String) history.get("Struts2_cmd"));
        }
        if(history.containsKey("Struts2_encoding")) {
            this.encoding.setValue((String) history.get("Struts2_encoding"));
        }
        if(history.containsKey("Struts2_cmd_info")) {
            this.cmd_info.setText((String) history.get("Struts2_cmd_info"));
        }

        // 文件上传的历史记录
        if(history.containsKey("Struts2_upload_info")) {
            this.upload_info.setText((String) history.get("Struts2_upload_info"));
        }
        if(history.containsKey("Struts2_upload_path")) {
            this.upload_path.setText((String) history.get("Struts2_upload_path"));
        }
        if(history.containsKey("Struts2_platform")) {
            this.platform.setValue((String) history.get("Struts2_platform"));
        }
        if(history.containsKey("Struts2_upload_msg")) {
            this.upload_msg.setText((String) history.get("Struts2_upload_msg"));
        }
    }

    // 点击检测，获取url 和 要检测的漏洞
    @FXML
    public void check() {
        String url = Tools.urlParse(this.url.getText().trim());
        history.put("Struts2_url", this.url.getText());
        String vulName = this.choice_cve.getValue().toString().trim();

        history.put("Struts2_vulName", this.choice_cve.getValue());

        try {
            if (vulName.equals("all")) {
                this.basic_info.setText("");
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

        history.put("Struts2_ei", this.ei);

        history.put("Struts2_basic_info", this.basic_info.getText());

    }

    // 命令执行
    @FXML
    public void get_execute_cmd() {
        String cmd = this.cmd.getText();
        String encoding = this.encoding.getValue().toString().trim();

        history.put("Struts2_cmd", this.cmd.getText());
        history.put("Struts2_encoding", this.encoding.getValue());

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
        history.put("Struts2_cmd_info", this.cmd_info.getText());
    }


    // 点击上传文件，获取上传的文件信息
    @FXML
    public void get_shell_file() {
        String shell_info = this.upload_info.getText();
        String upload_path = this.upload_path.getText();
        String platform = this.platform.getValue().toString().trim();

        history.put("Struts2_upload_info", this.upload_info.getText());
        history.put("Struts2_upload_path", this.upload_path.getText());
        history.put("Struts2_platform", this.platform.getValue());

        if(upload_path.length() == 0) {
            upload_path = "test.jsp";
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
            history.put("Struts2_upload_msg", this.upload_msg.getText());
        } else {
            Tools.alert("文件上传", "上传的文件不能为空");
        }

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
