package com.yhy.core;

import com.yhy.tools.Tools;

import java.util.concurrent.Callable;

/**
 * @author yhy
 * @date 2021/3/26 21:57
 * @github https://github.com/yhy0
 * 批量检查使用的线程池
 */

public class Job implements Callable<String> {
    private String target;
    private String cve;

    public Job(String target, String cve) {
        this.target = target;
        this.cve = cve;
    }

    // 根据cve选择对应的漏洞检测
    public boolean checkAllExp() {
        ExploitInterface ei = Tools.getExploit(cve);

        try {
            if(ei.checkVUL(this.target)) {
                return true;
            } else {
                return false;
            }
        } catch (Exception var4) {
            System.out.println(" checkAllExp  " + var4.toString());
        }
        return false;
    }



    @Override
    public String call() throws Exception {
        String isVul = "";
//        System.out.println("线程:" + this.target + " -> 运行...");
        if (this.checkAllExp()) {
            isVul = "存在";
        } else {
            isVul = "不存在";
        }
//        System.out.println("线程:" + this.target + " -> 结束.");

        return isVul;
    }
}
