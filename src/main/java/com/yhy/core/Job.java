package com.yhy.core;

import java.util.concurrent.Callable;

/**
 * @author yhy
 * @date 2021/3/26 21:57
 * @github https://github.com/yhy0
 * 批量检查使用的线程池
 */

public class Job implements Callable<String> {
    private String target;

    public Job(String target) {
        this.target = target;
    }

    // 根据cve选择对应的漏洞检测
    public boolean checkAllExp() {
        CVE_2020_14882 cve_2020_14882 = new CVE_2020_14882();

        try {
            if(cve_2020_14882.checkVUL(this.target)) {
                return true;
//            } else if(cve_2020_14882.checkVUL(target)) {   // 根据实际漏洞检查写
//                return true;
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
