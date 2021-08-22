package fun.fireline.core;

import fun.fireline.exp.php.thinkphp.TP_log;

/**
 * @author yhy
 * @date 2021/8/21 14:18
 * @github https://github.com/yhy0
 */


public class LogAnalysis {
    public LogAnalysis() {
    }

    public static String logAnalysis(String target, String path, String year, String mouth, String day) {
        String results = null;
        TP_log tplog = new TP_log();
        results = tplog.checkVul(target, path, year, mouth, day);
        return results;
    }
}
