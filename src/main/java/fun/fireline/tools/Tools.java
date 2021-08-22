package fun.fireline.tools;

/**
 * @author yhy
 * @date 2021/3/25 11:20
 * @github https://github.com/yhy0
 */

// http 请求对象，取自 shack2 的Java反序列化漏洞利用工具V1.7

import fun.fireline.controller.MainController;
import fun.fireline.core.ExploitInterface;

import fun.fireline.exp.apache.struts2.*;
import fun.fireline.exp.oracle.weblogic.*;
import fun.fireline.exp.php.thinkphp.*;
import fun.fireline.exp.cms.nc.CNVD_2021_30167;
import fun.fireline.others.CVE_2021_22986;

import javafx.scene.control.Alert;
import javafx.stage.Window;
import org.apache.log4j.Logger;

import java.io.*;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Tools {
    public static Logger logger = Logger.getLogger(MainController.class);
    public Tools() {
    }


    public static void alert(String header_text, String content_text) {
        Alert alert = new Alert(Alert.AlertType.WARNING);
        // 点 x 退出
        Window window = alert.getDialogPane().getScene().getWindow();
        window.setOnCloseRequest((e) -> {
            window.hide();
        });

        alert.setHeaderText(header_text);
        alert.setContentText(content_text);
        alert.show();
    }

    // 因为使用echo 写 shell ，这里需要对 < > 转义
    public static String get_escape_shell(String str, String platform) {
        String key1 = "<";
        String key2 = ">";

        if (platform.equals("Linux")) {

            return "'" + str + "'";
        } else {
            return escape(key2, escape(key1, str, "^"), "^");
        }

    }

    public static String escape(String key, String str, String escape_str) {
        StringBuffer stringBuilder1 = new StringBuffer(str);
        int a = str.indexOf(key);
        int i = 0;
        while (a != -1) {
            stringBuilder1.insert(a + i, escape_str);
            a = str.indexOf(key, a + 1);
            i++;
        }

        return stringBuilder1.toString();
    }

    public static String checkTheDomain(String weburl) {
        if ("".equals(weburl.trim())) {
            return "";
        } else {
            if (!weburl.startsWith("http")) {
                weburl = "http://" + weburl;
            }

            if (!weburl.endsWith("/")) {
                weburl = weburl + "/";
            }

            return weburl;
        }
    }

    public static String urlParse(String url) {
        if (!url.contains("http")) {
            url = "http://" + url;
        }

        if (url.endsWith("/")) {
            url = url.substring(0, url.length() - 1);
        }

        return url;
    }


    public static boolean checkTheURL(String weburl) {
        if ("".equals(weburl.trim())) {
            return false;
        } else {
            return weburl.startsWith("http");
        }
    }

    private static boolean match(String regex, String str) {
        Pattern pattern = Pattern.compile(regex);
        Matcher matcher = pattern.matcher(str);
        return matcher.matches();
    }

    public static String getDate() {
        Date d = new Date();
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        return sdf.format(d);
    }

    public static String reverse(String data) {
        StringBuilder sb = new StringBuilder(data);
        return sb.reverse().toString();
    }

    public static HashSet<String> read(String path, String encode, Boolean domain) {
        HashSet list = new HashSet();

        try {
            FileInputStream fs = new FileInputStream(new File(path));
            InputStreamReader isr = null;
            if (encode.equals("")) {
                isr = new InputStreamReader(fs);
            } else {
                isr = new InputStreamReader(fs, encode);
            }

            BufferedReader br = new BufferedReader(isr);
            String tem = null;

            while ((tem = br.readLine()) != null) {
                if (domain) {
                    tem = checkTheDomain(tem);
                }
                if (!list.contains(tem)) {
                    list.add(tem);
                }
            }

            br.close();
            isr.close();
        } catch (Exception var7) {
        }

        return list;
    }

    public static boolean write(String path, String value) {
        try {
            BufferedWriter out = new BufferedWriter(new FileWriter(path));
            out.write(value);
            out.close();
        } catch (IOException e) {
            return false;
        }
        return true;
    }


    // 根据选择对应的漏洞检测
    public static ExploitInterface getExploit(String vulName) {
        ExploitInterface ei = null;
        if (vulName.contains("S2-005")) {
            ei = new S2_005();
        } else if(vulName.contains("S2-009")) {
            ei = new S2_009();
        } else if(vulName.contains("S2-016")) {
            ei = new S2_016();
        } else if(vulName.contains("S2-019")) {
            ei = new S2_019();
        } else if(vulName.contains("S2-032")) {
            ei = new S2_032();
        } else if(vulName.contains("S2-045")) {
            ei = new S2_045();
        } else if(vulName.contains("S2-046")) {
            ei = new S2_046();
        } else if(vulName.contains("S2-DevMode")) {
            ei = new S2_DevMode();


        } else if(vulName.contains("ThinkPHP 2.x")){
            ei = new ThinkPHP2x();
        } else if(vulName.contains("TP5_construct_code_exec_1")) {
            // 这里创建你的cve漏洞检测，注意要实现 ExploitInterface 接口
            ei = new TP5_construct_code_exec_1();
        } else if(vulName.contains("TP5_construct_code_exec_2")){
            ei = new TP5_construct_code_exec_2();
        } else if(vulName.contains("TP5_construct_code_exec_3")){
            ei = new TP5_construct_code_exec_3();
        } else if(vulName.contains("TP5_construct_code_exec_4")){
            ei = new TP5_construct_code_exec_4();
        } else if(vulName.contains("TP5_construct_debug_rce")){
            ei = new TP5_construct_debug_rce();
        } else if(vulName.contains("TP5_driver_display_rce")){
            ei = new TP5_driver_display_rce();
        } else if(vulName.contains("TP5_index_construct_rce")){
            ei = new TP5_index_construct_rce();
        } else if(vulName.contains("TP5_invoke_func_code_exec_1")){
            ei = new TP5_invoke_func_code_exec_1();
        } else if(vulName.contains("TP5_invoke_func_code_exec_2")){
            ei = new TP5_invoke_func_code_exec_2();
        } else if(vulName.contains("TP5_method_filter_code_exec")){
            ei = new TP5_method_filter_code_exec();
        } else if(vulName.contains("TP5_request_input_rce")){
            ei = new TP5_request_input_rce();
        } else if(vulName.contains("TP5_templalte_driver_rce")){
            ei = new TP5_templalte_driver_rce();
        } else if(vulName.contains("TP6_session_file_write")){
            ei = new TP6_session_file_write();
        } else if(vulName.contains("TP_cache")){
            ei = new TP_cache();
        } else if(vulName.contains("TP5_index_showid_rce")){
            ei = new TP5_index_showid_rce();
        } else if(vulName.contains("TP5_debug_index_ids_sqli")){
            ei = new TP5_debug_index_ids_sqli();
        } else if(vulName.contains("TP_checkcode_time_sqli")){
            ei = new TP_checkcode_time_sqli();
        } else if(vulName.contains("TP_multi_sql_leak")){
            ei = new TP_multi_sql_leak();
        } else if(vulName.contains("TP_pay_orderid_sqli")){
            ei = new TP_pay_orderid_sqli();
        } else if(vulName.contains("TP_update_sql")){
            ei = new TP_update_sql();
        } else if(vulName.contains("TP_view_recent_xff_sqli")) {
            ei = new TP_view_recent_xff_sqli();


        } else if (vulName.contains("CVE-2017-10271 Weblogic10")) {
            ei = new CVE_2017_10271_10();
        } else if (vulName.contains("CVE-2017-10271 Weblogic12")) {
            ei = new CVE_2017_10271_12();
        } else if (vulName.contains("CVE-2019-2725 Weblogic10")) {
            ei = new CVE_2019_2725_10();
        } else if (vulName.contains("CVE-2019-2725 Weblogic12")) {
            ei = new CVE_2019_2725_12();
        } else if (vulName.contains("CVE-2019-2725-Bypass Weblogic10")) {
            ei = new CVE_2019_2725_10_bypass();
 

        } else if(vulName.contains("CVE-2021-22986")) {
            // 这里创建你的cve漏洞检测，注意要实现 ExploitInterface 接口
            ei = new CVE_2021_22986();
        } else if(vulName.contains("CNVD-2021-30167")){
            ei = new CNVD_2021_30167();
        }

        return (ExploitInterface) ei;
    }


    public static String str2Hex(String str) {
        char[] chars = "0123456789ABCDEF".toCharArray();
        StringBuilder sb = new StringBuilder("");
        byte[] bs = str.getBytes();

        for (int i = 0; i < bs.length; ++i) {
            int bit = (bs[i] & 240) >> 4;
            sb.append(chars[bit]);
            bit = bs[i] & 15;
            sb.append(chars[bit]);
        }

        return sb.toString().trim();
    }

    public static String hex2Str(String hexStr) {
        String str = "0123456789ABCDEF";
        char[] hexs = hexStr.toCharArray();
        byte[] bytes = new byte[hexStr.length() / 2];

        for (int i = 0; i < bytes.length; ++i) {
            int n = str.indexOf(hexs[2 * i]) * 16;
            n += str.indexOf(hexs[2 * i + 1]);
            bytes[i] = (byte) (n & 255);
        }

        return new String(bytes);
    }

    public static String loadExp(String path) {
        try {
            Properties pro = new Properties();
            FileInputStream in = new FileInputStream(path);
            pro.load(in);
            String exp = (String) pro.get("exp");
            return exp;
        } catch (IOException var4) {
            logger.debug(var4);
            return "";
        }
    }

    // 去除html
    public static String regReplace(String content) {
        String pattern = "<.*html.*>[\\s\\S]*</html>";
        String newString = "";
        Pattern p = Pattern.compile(pattern);
        Matcher m = p.matcher(content);
        String result = m.replaceAll(newString);
        return result;
    }

    // 随机字符
    public static String getRandomString(int length) {
        String str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        Random random = new Random();
        StringBuilder sb = new StringBuilder();

        for(int i = 0; i < length; ++i) {
            int number = random.nextInt(62);
            sb.append(str.charAt(number));
        }

        return sb.toString();
    }



    // base64编码
    public static String Base64Encode(String txt) {
        try {
            return Base64.getEncoder().encodeToString(txt.getBytes("UTF-8"));
        } catch (Exception var2) {
            logger.debug(var2);
            return "";
        }
    }

    // 获取weblogic 的exp文本
    public static String getExp(String path) {
        InputStream in = Tools.class.getClassLoader().getResourceAsStream(path);

        Scanner s = (new Scanner(in)).useDelimiter("\\A");
        String str = s.hasNext() ? s.next() : "";

        return str;
    }

}
