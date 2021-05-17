package com.yhy.tools;

import java.nio.charset.StandardCharsets;

import java.util.Arrays;

import org.springframework.util.Base64Utils;

/**
 * @author yhy
 * @date 2021/5/13 15:42
 * @github https://github.com/yhy0
 */

public class Ttt {

    // 计算 shiro key
    public static void main(String[] args) {
        String encryptKey = "yunjiglobal";
        byte[] encryptKeyBytes = encryptKey.getBytes(StandardCharsets.UTF_8);

        String rememberKey = Base64Utils.encodeToString(Arrays.copyOf(encryptKeyBytes, 16));

        // ZmVic19zaGlyb19rZXkAAA==
        System.out.println(rememberKey);
    }

}
