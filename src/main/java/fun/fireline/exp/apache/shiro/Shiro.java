package fun.fireline.exp.apache.shiro;

import fun.fireline.core.ExploitInterface;
import fun.fireline.tools.HttpTool;

import java.util.HashMap;

/**
 * @author yhy
 * @date 2021/8/19 11:05
 * @github https://github.com/yhy0
 */

public class Shiro implements ExploitInterface {
    private String target = null;

    private boolean isVul = false;
    
    @Override
    public boolean checkVul(String url) {
        this.target = url;

        HashMap<String, String> map = new HashMap();       //请求headers
        // 设置 header ，检测是否为 shiro
        map.put("Cookie", "rememberMe=1111");

        try {
            String result = HttpTool.httpReuest(this.target, "GET", map, "", "", "UTF-8");




//            String data = this.payload.replace("payload", "echo " + uuid);
//            String result = HttpTool.postHttpReuest(this.target, "application/x-www-form-urlencoded", data, "UTF-8");
//            boolean flag = result.contains(uuid);
//            if(flag) {
//                this.isVul = true;
//            }
//            return flag;
        } catch (Exception e) {
            logger.error(e);
        }
        return false;
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
