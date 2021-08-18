package fun.fireline.tools;

/**
 * @author yhy
 * @date 2021/3/25 11:20
 * @github https://github.com/yhy0
 */

// http 请求对象，取自 shack2 的Java反序列化漏洞利用工具V1.7

import fun.fireline.exp.others.CVE_2021_22986;
import fun.fireline.core.ExploitInterface;
import fun.fireline.exp.apache.struts2.*;
import fun.fireline.exp.cms.nc.CNVD_2021_30167;
import javafx.scene.control.Alert;
import javafx.scene.control.TextArea;
import javafx.stage.Window;

import java.io.*;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;
import java.util.HashSet;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Tools {
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


    // 根据cve选择对应的漏洞检测
    public static ExploitInterface getStruts2Exploit(String vulName) {
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
        }

        return (ExploitInterface) ei;
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
            Logger.getLogger(Tools.class.getName()).log(Level.SEVERE, (String) null, var4);
            return "";
        }
    }


    public static String fofaHTTP(String emali, String key, String value, int size, TextArea fofa_result_info) throws Exception {

        String qbase64 = Base64.getEncoder().encodeToString(value.getBytes());

        String url = "https://fofa.so/api/v1/search/all?email=" + emali + "&key=" + key + "&qbase64=" + qbase64 + "&full=true&fields=host,title&size=" + size;
        System.out.println(url);
        String result = "";

        result = HttpTool.getHttpReuest(url, "text/xml", "UTF-8");

        return result;
    }

}
