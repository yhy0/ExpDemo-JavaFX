package com.yhy.tools;

/**
 * @author yhy
 * @date 2021/3/25 11:20
 * @github https://github.com/yhy0
 */

// http 请求对象，取自 shack2 的Java反序列化漏洞利用工具V1.7

import com.yhy.core.CVE_2020_14882;
import com.yhy.core.CVE_2021_22986;
import com.yhy.core.ExploitInterface;
import javafx.scene.control.Alert;
import javafx.stage.Window;

import java.io.*;

import java.text.SimpleDateFormat;
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

        if(platform.equals("Linux")) {

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
            stringBuilder1.insert(a + i,escape_str);
            a = str.indexOf(key,a + 1);
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

    public static HashSet<String> read(String path, String encode) {
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

            while((tem = br.readLine()) != null) {
                tem = checkTheDomain(tem);
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





    // 根据cve选择对应的漏洞检测
    public static ExploitInterface getExploit(String select) {
        ExploitInterface ei = null;

        if (select.startsWith("CVE-2020-14882")) {
            ei = new CVE_2020_14882();
        } else if (select.startsWith("CVE-2021-22986")) {
            // 这里创建你的cve漏洞检测，注意要实现 ExploitInterface 接口
            ei = new CVE_2021_22986();
        }

        return (ExploitInterface)ei;
    }


//    // 根据cve选择对应的漏洞检测
//    public static boolean checkAllExp(String target) {
//        CVE_2020_14882 cve_2020_14882 = new CVE_2020_14882();
//
//        try {
//            if(cve_2020_14882.checkVUL(target)) {
//                return true;
////            } else if(cve_2020_14882.checkVUL(target)) {   // 根据实际漏洞检查写
////                return true;
//            } else {
//                return false;
//            }
//
//        } catch (Exception var4) {
//            System.out.println(" checkAllExp  " + var4.toString());
//        }
//
//        return false;
//    }


    public static String str2Hex(String str) {
        char[] chars = "0123456789ABCDEF".toCharArray();
        StringBuilder sb = new StringBuilder("");
        byte[] bs = str.getBytes();

        for(int i = 0; i < bs.length; ++i) {
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

        for(int i = 0; i < bytes.length; ++i) {
            int n = str.indexOf(hexs[2 * i]) * 16;
            n += str.indexOf(hexs[2 * i + 1]);
            bytes[i] = (byte)(n & 255);
        }

        return new String(bytes);
    }

    public static String loadExp(String path) {
        try {
            Properties pro = new Properties();
            FileInputStream in = new FileInputStream(path);
            pro.load(in);
            String exp = (String)pro.get("exp");
            return exp;
        } catch (IOException var4) {
            Logger.getLogger(Tools.class.getName()).log(Level.SEVERE, (String)null, var4);
            return "";
        }
    }
}
