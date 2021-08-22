package fun.fireline.core;

import fun.fireline.tools.Tools;
import org.apache.log4j.Logger;

import java.util.concurrent.Callable;

/**
 * @author yhy
 * @date 2021/3/26 21:57
 * @github https://github.com/yhy0
 * 批量检查使用的线程池
 */

public class Job implements Callable<Boolean> {
    private static final Logger logger = Logger.getLogger(Job.class);

    private String target;
    private String vulName;


    public Job(String target, String vulName) {
        this.target = target;
        this.vulName = vulName;
    }

    // 根据cve选择对应的漏洞检测
    public boolean checkAllExp() {
        ExploitInterface ei = Tools.getExploit(vulName);

        try {
            ei.checkVul(this.target);
            if(ei.isVul()) {
                return true;
            } else {
                return false;
            }
        } catch (Exception e) {
            logger.debug(e.toString());
        }
        return false;
    }

    @Override
    public Boolean call() {
        return this.checkAllExp();
    }
}
