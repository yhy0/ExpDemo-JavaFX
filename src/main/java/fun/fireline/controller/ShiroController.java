package fun.fireline.controller;

import fun.fireline.core.Constants;
import fun.fireline.core.ExploitInterface;
import fun.fireline.core.Job;
import fun.fireline.tools.Tools;
import javafx.fxml.FXML;
import javafx.scene.control.ChoiceBox;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;


/**
 * @author yhy
 * @date 2021/7/3 13:15
 * @github https://github.com/yhy0
 */

// JavaFX图形化界面的控制类
public class ShiroController extends MainController{
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
            "\tShrio550 \r\n" +
            "\t \r\n\r\n\r\n" +

            Constants.UPDATEINFO;

    public static String[] SHIRO = {
            "S2-005",
            "S2-009",
            "S2-016",
            "S2-019",
            "S2-032",
            "S2-045",
            "S2-046",
            "S2-DevMode",
            "all",
    };



    // 界面显示  一些默认的基本信息，漏洞列表、编码选项、线程、shell、页脚
    public void defaultInformation() {
        this.choice_cve.setValue(SHIRO[0]);
        for (String cve : SHIRO) {
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
        if(history.containsKey("SHIRO_url")) {
            this.url.setText((String) history.get("SHIRO_url"));
        }
        if(history.containsKey("SHIRO_vulName")) {
            this.choice_cve.setValue((String) history.get("SHIRO_vulName"));
        }
        if(history.containsKey("SHIRO_ei")) {
            this.ei = (ExploitInterface) history.get("SHIRO_ei");
        }
        if(history.containsKey("SHIRO_basic_info")) {
            this.basic_info.setText((String) history.get("SHIRO_basic_info"));
        } else {
            this.basic_info.setText(BASICINFO);
        }
        this.basic_info.setWrapText(true);

        // 命令执行的历史记录
        if(history.containsKey("SHIRO_cmd")) {
            this.cmd.setText((String) history.get("SHIRO_cmd"));
        }
        if(history.containsKey("SHIRO_encoding")) {
            this.encoding.setValue((String) history.get("SHIRO_encoding"));
        }
        if(history.containsKey("SHIRO_cmd_info")) {
            this.cmd_info.setText((String) history.get("SHIRO_cmd_info"));
        }

        // 文件上传的历史记录
        if(history.containsKey("SHIRO_upload_info")) {
            this.upload_info.setText((String) history.get("SHIRO_upload_info"));
        }
        if(history.containsKey("SHIRO_upload_path")) {
            this.upload_path.setText((String) history.get("SHIRO_upload_path"));
        }
        if(history.containsKey("SHIRO_platform")) {
            this.platform.setValue((String) history.get("SHIRO_platform"));
        }
        if(history.containsKey("SHIRO_upload_msg")) {
            this.upload_msg.setText((String) history.get("SHIRO_upload_msg"));
        }
    }

    // 点击检测，获取url 和 要检测的漏洞
    @FXML
    public void check() {
        String url = this.url.getText().trim();
        history.put("SHIRO_url", this.url.getText());
        String vulName = this.choice_cve.getValue().toString().trim();

        history.put("SHIRO_vulName", this.choice_cve.getValue());

        if(Tools.checkTheURL(url)) {
            try {
                if (vulName.equals("all")) {
                    this.basic_info.setText("");
                    ExecutorService pool = Executors.newFixedThreadPool(3);
                    for (String vul : this.choice_cve.getItems()) {
                        if (!vul.equals("all")) {
                            Job t = new Job(url, vul);
                            // 线程池
                            Future f = pool.submit(t);
                            try {
                                if ((Boolean) f.get()) {
                                    this.basic_info.setText(this.basic_info.getText() + "\r\n\t[ + ] " + url + " 存在 " + vul + " 漏洞  O(∩_∩)O~" + "\r\n");
                                } else {
                                    this.basic_info.setText(this.basic_info.getText() + "\r\n\t[ - ] " + url + " 不存在 " + vul + " 漏洞 \r\n");
                                }
                            } catch (Exception e1) {
                                logger.error(e1.toString());
                            }
                        }
                    }
                } else {
                    this.ei = Tools.getExploit(vulName);

                    if(this.ei.checkVul(url)) {
                        this.basic_info.setText("\r\n\t[ + ] " + url + " 存在 " + vulName + " 漏洞" + "\r\n\r\n\twebPath:\r\n\t\t" + this.ei.getWebPath());
                    } else {
                        this.basic_info.setText("\r\n\t[ - ] " + url + " 不存在 " + vulName + " 漏洞 \r\n");
                    }
                    history.put("SHIRO_ei", this.ei);
                }

            } catch (Exception e) {
                this.basic_info.setText("\r\n\t检测异常 \r\n\t\t\t" + e.toString());
            }


        } else {
            Tools.alert("URL检查", "URL格式不符合要求，示例：http://127.0.0.1:7001/");
        }

        history.put("SHIRO_basic_info", this.basic_info.getText());

    }

    // 命令执行
    @FXML
    public void get_execute_cmd() {
        String cmd = this.cmd.getText();
        String encoding = this.encoding.getValue().toString().trim();

        history.put("SHIRO_cmd", this.cmd.getText());
        history.put("SHIRO_encoding", this.encoding.getValue());

        if(cmd.length() == 0) {
            cmd = "whoami";
        }

        if(this.ei.isVul()) {
            try {
                String result = this.ei.exeCmd(cmd, encoding);
                if(result.contains("fail")) {
                    this.cmd_info.setText("命令执行失败");
                } else {
                    this.cmd_info.setText(result);
                }

            } catch (Exception var4) {
                this.cmd_info.setText("error: " + var4.toString());
            }

        } else {
            this.cmd_info.setText("请先进行漏洞检测，确认漏洞存在");
        }
        history.put("SHIRO_cmd_info", this.cmd_info.getText());
    }


    // 点击上传文件，获取上传的文件信息
    @FXML
    public void get_shell_file() {
        String shell_info = this.upload_info.getText();
        String upload_path = this.upload_path.getText();
        String platform = this.platform.getValue().toString().trim();

        history.put("SHIRO_upload_info", this.upload_info.getText());
        history.put("SHIRO_upload_path", this.upload_path.getText());
        history.put("SHIRO_platform", this.platform.getValue());

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
                System.out.println( this.ei.isVul());
            }
            history.put("SHIRO_upload_msg", this.upload_msg.getText());
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
