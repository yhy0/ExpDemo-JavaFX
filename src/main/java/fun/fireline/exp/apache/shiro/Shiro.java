package fun.fireline.exp.apache.shiro;

import fun.fireline.core.ExploitInterface;
import fun.fireline.tools.HttpTools;
import fun.fireline.tools.Response;

import java.util.HashMap;

/**
 * @author yhy
 * @date 2021/8/19 11:05
 * @github https://github.com/yhy0
 */

public class Shiro implements ExploitInterface {
    private String target = null;

    private boolean isVul = false;

    private  HashMap<String, String> headers = new HashMap();
    
    @Override
    public String checkVul(String url) {
        this.target = url;

        HashMap<String, String> map = new HashMap();       //请求headers
        // 设置 header ，检测是否为 shiro
        this.headers.put("Cookie", "rememberMe=1111");


        Response response = HttpTools.get(this.target, this.headers, "UTF-8");

        try {






//            String data = this.payload.replace("payload", "echo " + uuid);
//            String result = HttpTool.postHttpReuest(this.target, "application/x-www-form-urlencoded", data, "UTF-8");
//            boolean flag = result.contains(uuid);
//            if(flag) {
//                this.isVul = true;
//            }
//            return flag;
        } catch (Exception e) {
            logger.debug(e);
        }
        return "";
    }

    @Override
    public String exeCmd(String cmd, String encoding) {
        return null;
    }

    @Override
    public String getWebPath() {
        return null;
    }

    @Override
    public String uploadFile(String fileContent, String filename, String platform) throws Exception {
        return null;
    }

    @Override
    public boolean isVul() {
        return false;
    }
}
