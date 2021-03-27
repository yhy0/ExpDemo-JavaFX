package com.yhy.tools;

/**
 * @author yhy
 * @date 2021/3/25 21:00
 * @github https://github.com/yhy0
 */

// 取自 shack2 的Java反序列化漏洞利用工具V1.7

import javax.net.ssl.X509TrustManager;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class MyCERT implements X509TrustManager {
    public MyCERT() {
    }

    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
    }

    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
    }

    public X509Certificate[] getAcceptedIssuers() {
        return null;
    }
}
