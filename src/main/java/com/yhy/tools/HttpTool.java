package com.yhy.tools;

/**
 * @author yhy
 * @date 2021/3/25 20:59
 * @github https://github.com/yhy0
 */

// http 请求对象，取自 shack2 的Java反序列化漏洞利用工具V1.7

import javax.net.ssl.*;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.security.SecureRandom;
import java.util.HashMap;

public class HttpTool {
    private static int Timeout = 10000;

    private static String DefalutEncoding = "UTF-8";

    public static String httpRequest(String requestUrl, int timeOut, String requestMethod, String contentType, String postString, String encoding) throws Exception {


        if ("".equals(encoding) || encoding == null)
            encoding = DefalutEncoding;
        URLConnection httpUrlConn = null;
        HttpsURLConnection hsc = null;
        HttpURLConnection hc = null;
        InputStream inputStream = null;

        try {
            URL url = new URL(requestUrl);
            if (requestUrl.startsWith("https")) {
                SSLContext sslContext = SSLContext.getInstance("SSL");
                TrustManager[] tm = { new MyCERT() };
                sslContext.init(null, tm, new SecureRandom());
                SSLSocketFactory ssf = sslContext.getSocketFactory();
                hsc = (HttpsURLConnection)url.openConnection();
                hsc.setSSLSocketFactory(ssf);
                hsc.setHostnameVerifier(allHostsValid);
                httpUrlConn = hsc;
            } else {
//                InetSocketAddress addr = new InetSocketAddress("127.0.0.1", 8080);
//                // http 代理
//                Proxy proxy = new Proxy(Proxy.Type.HTTP, addr);
//                // 试图连接并取得返回状态码

//                hc = (HttpURLConnection)url.openConnection(proxy);
                hc = (HttpURLConnection)url.openConnection();
                hc.setRequestMethod(requestMethod);
                //禁止302 跳转
                hc.setInstanceFollowRedirects(false);
                System.out.println(hc.getRequestProperties());
                httpUrlConn = hc;
            }

            httpUrlConn.setConnectTimeout(timeOut);
            httpUrlConn.setReadTimeout(timeOut);
            if (contentType != null && !"".equals(contentType))
                httpUrlConn.setRequestProperty("Content-Type", contentType);


            httpUrlConn.setRequestProperty("User-Agent", "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)");
            httpUrlConn.setRequestProperty("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9");
            httpUrlConn.setRequestProperty("Accept-Encoding", "gzip, deflate");
            httpUrlConn.setRequestProperty("Accept-Language","zh-CN,zh;q=0.9");
            httpUrlConn.setRequestProperty("Connection","close");

            httpUrlConn.setDoOutput(true);
            httpUrlConn.setDoInput(true);

            httpUrlConn.connect();

            if (null != postString && !"".equals(postString)) {
                OutputStream outputStream = httpUrlConn.getOutputStream();
                outputStream.write(postString.getBytes(encoding));
                outputStream.flush();
                outputStream.close();
            }
            inputStream = httpUrlConn.getInputStream();
            String result = readString(inputStream, encoding);
            return result;
        } catch (IOException ie) {
            System.out.println(ie);

            if (hsc != null)
                return readString(hsc.getErrorStream(), encoding);
            if (hc != null)
                return readString(hc.getErrorStream(), encoding);
            return "";
        } catch (Exception e) {
            System.out.println(e);
            throw e;
        } finally {
            if (hsc != null)
                hsc.disconnect();
            if (hc != null)
                hc.disconnect();
        }
    }

    public static HostnameVerifier allHostsValid = new HostnameVerifier() {
        public boolean verify(String hostname, SSLSession session) {
            return true;
        }
    };

    public static String readString(InputStream inputStream, String encoding) throws IOException {
        BufferedInputStream bis = null;
        ByteArrayOutputStream baos = null;
        try {
            bis = new BufferedInputStream(inputStream);
            baos = new ByteArrayOutputStream();
            int len = 0;
            byte[] arr = new byte[1];
            while ((len = bis.read(arr)) != -1) {
                baos.write(arr, 0, len);
            }


        } catch (IOException e) {

        } finally {
            if (baos != null) {
                baos.flush();
                baos.close();
            }
            if (bis != null)
                bis.close();
            if (inputStream != null)
                inputStream.close();
            return baos.toString(encoding);
        }

    }

    public static String httpRequestAddHeader(String requestUrl, int timeOut, String requestMethod, String contentType, String postString, String encoding, HashMap<String, String> headers) throws Exception {
        if ("".equals(encoding) || encoding == null)
            encoding = DefalutEncoding;
        URLConnection httpUrlConn = null;
        HttpsURLConnection hsc = null;
        HttpURLConnection hc = null;
        InputStream inputStream = null;
        BufferedInputStream bis = null;
        ByteArrayOutputStream baos = null;
        try {
            URL url = new URL(requestUrl);
            if (requestUrl.startsWith("https")) {
                SSLContext sslContext = SSLContext.getInstance("SSL");
                TrustManager[] tm = { new MyCERT() };
                sslContext.init(null, tm, new SecureRandom());
                SSLSocketFactory ssf = sslContext.getSocketFactory();
                hsc = (HttpsURLConnection)url.openConnection();
                hsc.setSSLSocketFactory(ssf);
                hsc.setHostnameVerifier(allHostsValid);
                httpUrlConn = hsc;
            } else {
//                InetSocketAddress addr = new InetSocketAddress("127.0.0.1", 8080);
//                // http 代理
//                Proxy proxy = new Proxy(Proxy.Type.HTTP, addr);
//                // 试图连接并取得返回状态码

//                hc = (HttpURLConnection)url.openConnection(proxy);

                // 打开和URL之间的连接
                hc = (HttpURLConnection)url.openConnection();
                hc.setRequestMethod(requestMethod);
                hc.setInstanceFollowRedirects(false);
                httpUrlConn = hc;
            }
            httpUrlConn.setConnectTimeout(timeOut);
            httpUrlConn.setReadTimeout(timeOut);
            if (contentType != null && !"".equals(contentType)) {
                httpUrlConn.setRequestProperty("Content-Type", contentType);
            }

            httpUrlConn.setRequestProperty("User-Agent", "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)");
            httpUrlConn.setRequestProperty("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9");
            httpUrlConn.setRequestProperty("Accept-Encoding", "gzip, deflate");
            httpUrlConn.setRequestProperty("Accept-Language","zh-CN,zh;q=0.9");
            httpUrlConn.setRequestProperty("Connection","close");

            if (headers != null)
                for (String key : headers.keySet()) {
                    String val = headers.get(key);
                    httpUrlConn.addRequestProperty(key, val);
                }
            httpUrlConn.setDoOutput(true);
            httpUrlConn.setDoInput(true);
            // 建立实际的连接
            httpUrlConn.connect();

            if (null != postString && !"".equals(postString)) {

                OutputStream outputStream = httpUrlConn.getOutputStream();
                outputStream.write(postString.getBytes(encoding));
                outputStream.close();
            }

            inputStream = httpUrlConn.getInputStream();

            String result = readString(inputStream, encoding);

            return result;


        } catch (IOException e) {
            System.out.println(e);
            if (hsc != null) {
                System.out.println("1");
                System.out.println(hsc.getErrorStream());
                return readString(hsc.getErrorStream(), encoding);
            }

            if (hc != null) {
                System.out.println("2");
                System.out.println(hc.getErrorStream());
                return readString(hc.getErrorStream(), encoding);
            }

            return "";
        } catch (Exception e) {
            System.out.println("3");
            System.out.println(e);
            throw e;
        } finally {
            if (hsc != null)
                hsc.disconnect();
            if (hc != null)
                hc.disconnect();
        }
    }

    public static int codeByHttpRequest(String requestUrl, int timeOut, String requestMethod, String contentType, String postString, String encoding) throws Exception {
        if ("".equals(encoding) || encoding == null)
            encoding = DefalutEncoding;
        URLConnection httpUrlConn = null;
        HttpsURLConnection hsc = null;
        HttpURLConnection hc = null;
        InputStream inputStream = null;
        InputStreamReader isr = null;
        BufferedReader br = null;
        try {
            URL url = new URL(requestUrl);
            if (requestUrl.startsWith("https")) {
                SSLContext sslContext = SSLContext.getInstance("SSL");
                TrustManager[] tm = { new MyCERT() };
                sslContext.init(null, tm, new SecureRandom());
                SSLSocketFactory ssf = sslContext.getSocketFactory();
                hsc = (HttpsURLConnection)url.openConnection();
                hsc.setSSLSocketFactory(ssf);
                hsc.setHostnameVerifier(allHostsValid);
                httpUrlConn = hsc;
            } else {
                hc = (HttpURLConnection)url.openConnection();
                hc.setRequestMethod(requestMethod);
                httpUrlConn = hc;
            }
            httpUrlConn.setReadTimeout(timeOut);
            if (contentType != null && !"".equals(contentType))
                httpUrlConn.setRequestProperty("Content-Type", contentType);
            httpUrlConn.setRequestProperty("User-Agent", "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)");
            httpUrlConn.setRequestProperty("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9");
            httpUrlConn.setRequestProperty("Accept-Encoding", "gzip, deflate");
            httpUrlConn.setRequestProperty("Accept-Language","zh-CN,zh;q=0.9");
            httpUrlConn.setRequestProperty("Connection","close");

            httpUrlConn.setDoOutput(true);
            httpUrlConn.setDoInput(true);
            httpUrlConn.setUseCaches(false);
            httpUrlConn.connect();
            if (null != postString && !"".equals(postString)) {
                OutputStream outputStream = httpUrlConn.getOutputStream();
                outputStream.write(postString.getBytes(encoding));
                outputStream.close();
            }
            if (hsc != null)
                return hsc.getResponseCode();
            if (hc != null)
                return hc.getResponseCode();
            return 0;
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw e;
        } finally {
            if (br != null)
                br.close();
            if (isr != null)
                isr.close();
            if (inputStream != null)
                inputStream.close();
            if (hsc != null)
                hsc.disconnect();
            if (hc != null)
                hc.disconnect();
        }
    }

    public static String httpReuest(String requestUrl, String method, String contentType, String postString, String encoding) throws Exception {
        return httpRequest(requestUrl, Timeout, method, contentType, postString, encoding);
    }

    public static String postHttpReuest(String requestUrl, int timeOut, String contentType, String postString, String encoding) throws Exception {
        return httpRequest(requestUrl, timeOut, "POST", contentType, postString, encoding);
    }

    public static String postHttpReuest(String requestUrl, String postString, String encoding, HashMap<String, String> headers, String contentType) throws Exception {
        return httpRequestAddHeader(requestUrl, Timeout, "POST", contentType, postString, encoding, headers);
    }

    public static String postHttpReuest(String requestUrl, String contentType, String postString, String encoding) throws Exception {
        return httpRequest(requestUrl, Timeout, "POST", contentType, postString, encoding);
    }

    public static String postHttpReuest(String requestUrl, int timeOut, String postString, String encoding) throws Exception {
        return httpRequest(requestUrl, timeOut, "POST", "application/x-www-form-urlencoded", postString, encoding);
    }

    public static String postHttpReuest(String requestUrl, String postString, String encoding) throws Exception {
        return httpRequest(requestUrl, Timeout, "POST", "application/x-www-form-urlencoded", postString, encoding);
    }

    public static String getHttpReuest(String requestUrl, String contentType, String encoding) throws Exception {
        return httpRequest(requestUrl, Timeout, "GET", contentType, "", encoding);
    }

    public static String postHttpReuestByXML(String requestUrl, int timeOut, String postString, String encoding) throws Exception {
        return httpRequest(requestUrl, timeOut, "POST", "text/xml", postString, encoding);
    }

    public static String postHttpReuestByXML(String requestUrl, String postString, String encoding) throws Exception {
        return httpRequest(requestUrl, Timeout, "POST", "text/xml", postString, encoding);
    }

    public static String postHttpReuestByXMLAddHeader(String requestUrl, String postString, String encoding, HashMap<String, String> headers) throws Exception {
        return httpRequestAddHeader(requestUrl, Timeout, "POST", "text/xml", postString, encoding, headers);
    }

    public static int codeByHttpRequest(String requestUrl, String method, String contentType, String postString, String encoding) throws Exception {
        return codeByHttpRequest(requestUrl, Timeout, method, contentType, postString, encoding);
    }

    public static int getCodeByHttpRequest(String requestUrl, String encoding) throws Exception {
        return codeByHttpRequest(requestUrl, "GET", null, "", encoding);
    }

    public static int getCodeByHttpRequest(String requestUrl, int timeout, String encoding) throws Exception {
        return codeByHttpRequest(requestUrl, timeout, "GET", null, "", encoding);
    }

    public static int postCodeByHttpRequest(String requestUrl, String contentType, String postString, String encoding) throws Exception {
        return codeByHttpRequest(requestUrl, Timeout, "POST", contentType, postString, encoding);
    }

    public static int postCodeByHttpRequestWithNoContenType(String requestUrl, String postString, String encoding) throws Exception {
        return codeByHttpRequest(requestUrl, Timeout, "POST", null, postString, encoding);
    }

    public static int postCodeByHttpRequest(String requestUrl, String encoding) throws Exception {
        return codeByHttpRequest(requestUrl, Timeout, "POST", null, null, encoding);
    }

    public static int postCodeByHttpRequest(String requestUrl, String postString, String encoding) throws Exception {
        return codeByHttpRequest(requestUrl, Timeout, "POST", "application/x-www-form-urlencoded", postString, encoding);
    }

    public static int postCodeByHttpRequestXML(String requestUrl, String postString, String encoding) throws Exception {
        return codeByHttpRequest(requestUrl, Timeout, "POST", "text/xml", postString, encoding);
    }

    public static boolean downloadFile(String downURL, File file) throws Exception {
        HttpURLConnection httpURLConnection = null;
        BufferedInputStream bin = null;
        OutputStream out = null;
        try {
            URL url = new URL(downURL);
            httpURLConnection = (HttpURLConnection)url.openConnection();
            httpURLConnection.setRequestMethod("GET");
            httpURLConnection.connect();
            bin = new BufferedInputStream(httpURLConnection.getInputStream());
            if (!file.getParentFile().exists())
                file.getParentFile().mkdirs();
            out = new FileOutputStream(file);
            int size = 0;
            int len = 0;
            byte[] buf = new byte[1024];
            while ((size = bin.read(buf)) != -1) {
                len += size;
                out.write(buf, 0, size);
            }
        } catch (Exception e) {
            throw e;
        } finally {
            if (bin != null)
                bin.close();
            if (out != null) {
                out.flush();
                out.close();
            }
            if (httpURLConnection != null)
                httpURLConnection.disconnect();
        }
        return true;
    }

    public static boolean downloadFile(String downURL, String path) throws Exception {
        return downloadFile(downURL, new File(path));
    }

}