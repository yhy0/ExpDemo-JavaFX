package fun.fireline.tools;

/**
 * @author yhy
 * @date 2021/3/25 20:59
 * @github https://github.com/yhy0
 */

// http 请求对象，取自 shack2 的Java反序列化漏洞利用工具V1.7
// 已弃用， 后续都是用 HttpTools

import fun.fireline.controller.MainController;
import org.apache.log4j.Logger;
import sun.misc.BASE64Encoder;

import javax.net.ssl.*;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.Proxy;
import java.net.URL;
import java.net.URLConnection;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class HttpToolOld {
    private static final Logger logger = Logger.getLogger(MainController.class);

    private static int Timeout = 10000;
    private static String DefalutEncoding = "UTF-8";

    public static int status;
    public static Map<String,List<String>> responseHeaders;


    public static String httpRequest(String requestUrl, int timeOut, String requestMethod, String contentType, String postString, String encoding) throws Exception {
        URLConnection httpUrlConn = null;
        HttpsURLConnection hsc = null;
        HttpURLConnection hc = null;
        InputStream inputStream = null;

        // url中没有协议，默认走http协议
        if(!requestUrl.contains("http")) {
            requestUrl = "http://" + requestUrl;
        }

        try {
            URL url = new URL(requestUrl);
            if (requestUrl.startsWith("https")) {
                SSLContext sslContext = SSLContext.getInstance("SSL");
                TrustManager[] tm = { new Cert() };
                sslContext.init(null, tm, new SecureRandom());
                SSLSocketFactory ssf = sslContext.getSocketFactory();
                //代理
                Proxy proxy = (Proxy) MainController.settingInfo.get("proxy");

                if(proxy != null) {
                    hsc = (HttpsURLConnection)url.openConnection(proxy);
                } else {
                    hsc = (HttpsURLConnection)url.openConnection();
                }
                hsc.setSSLSocketFactory(ssf);
                hsc.setHostnameVerifier(allHostsValid);
                httpUrlConn = hsc;
            } else {
                //代理
                Proxy proxy = (Proxy) MainController.settingInfo.get("proxy");

                if(proxy != null) {
                    hc = (HttpURLConnection)url.openConnection(proxy);
                } else {
                    hc = (HttpURLConnection)url.openConnection();
                }
                hc.setRequestMethod(requestMethod);
                //禁止302 跳转
                hc.setInstanceFollowRedirects(false);
                httpUrlConn = hc;
            }

            httpUrlConn.setConnectTimeout(timeOut);
            httpUrlConn.setReadTimeout(timeOut);
            if (contentType != null && !"".equals(contentType))
                httpUrlConn.setRequestProperty("Content-Type", contentType);

            httpUrlConn.setRequestProperty("User-Agent", "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)");
            httpUrlConn.setRequestProperty("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9");
            httpUrlConn.setRequestProperty("Accept-Language","zh-CN,zh;q=0.9");
            httpUrlConn.setRequestProperty("Connection","close");

            httpUrlConn.setDoOutput(true);
            httpUrlConn.setDoInput(true);

            httpUrlConn.connect();

            if (null != postString && !"".equals(postString)) {
                OutputStream outputStream = httpUrlConn.getOutputStream();
                if(encoding.equals("")) {
                    outputStream.write(postString.getBytes());
                } else {
                    outputStream.write(postString.getBytes(encoding));
                }
                outputStream.flush();
                outputStream.close();
            }

            inputStream = httpUrlConn.getInputStream();

            String result = readString(inputStream, encoding);
            status = hc.getResponseCode();
            responseHeaders = hc.getHeaderFields();
            return result;
        } catch (IOException ie) {
            logger.debug(ie);
            if (hsc != null)
                return readString(hsc.getErrorStream(), encoding);
            if (hc != null)
                return readString(hc.getErrorStream(), encoding);
            return "";
        } catch (Exception e) {
            logger.debug(e);
            throw e;
        } finally {
            if (hsc != null)
                hsc.disconnect();
            if (hc != null)
                hc.disconnect();
        }
    }

    public static String headerByHttpRequest(String requestUrl, int timeOut, String requestMethod, String contentType, String postString, String encoding, HashMap<String, String> headers) throws Exception {
        if ("".equals(encoding) || encoding == null)
            encoding = DefalutEncoding;
        URLConnection httpUrlConn = null;
        HttpsURLConnection hsc = null;
        HttpURLConnection hc = null;
        InputStream inputStream = null;
        InputStreamReader isr = null;
        BufferedReader br = null;
        // url中没有协议，默认走http协议
        if(!requestUrl.contains("http")) {
            requestUrl = "http://" + requestUrl;
        }

        try {
            URL url = new URL(requestUrl);
            //代理
            Proxy proxy = (Proxy) MainController.settingInfo.get("proxy");

            if (requestUrl.startsWith("https")) {
                SSLContext sslContext = SSLContext.getInstance("SSL");
                TrustManager[] tm = { new Cert() };
                sslContext.init(null, tm, new SecureRandom());
                SSLSocketFactory ssf = sslContext.getSocketFactory();

                if (proxy != null) {
                    hsc = (HttpsURLConnection)url.openConnection(proxy);
                } else {
                    hsc = (HttpsURLConnection)url.openConnection();
                }

                hsc.setSSLSocketFactory(ssf);
                hsc.setHostnameVerifier(allHostsValid);
                httpUrlConn = hsc;
            } else {
                if (proxy != null) {
                    hc = (HttpURLConnection)url.openConnection(proxy);
                } else {
                    hc = (HttpURLConnection)url.openConnection();
                }

                hc.setRequestMethod(requestMethod);
                httpUrlConn = hc;
            }


            httpUrlConn.setReadTimeout(timeOut);

            if (contentType != null && !"".equals(contentType))
                httpUrlConn.setRequestProperty("Content-Type", contentType);
            httpUrlConn.setRequestProperty("User-Agent", "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)");
            httpUrlConn.setRequestProperty("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9");
            httpUrlConn.setRequestProperty("Accept-Encoding", "gzip, deflate");
            httpUrlConn.setRequestProperty("Accept-Language", "zh-CN,zh;q=0.9");
            httpUrlConn.setRequestProperty("Connection", "close");
            if (headers != null)
                for (String key : headers.keySet()) {
                    String val = headers.get(key);
                    httpUrlConn.addRequestProperty(key, val);
                }
            httpUrlConn.setDoOutput(true);
            httpUrlConn.setDoInput(true);
            httpUrlConn.connect();
            if (null != postString && !"".equals(postString)) {
                OutputStream outputStream = httpUrlConn.getOutputStream();
                outputStream.write(postString.getBytes(encoding));
                outputStream.close();
            }
            if (hsc != null) {
                String responseHeaderString = "";
                Map<String, List<String>> responseheaders = hsc.getHeaderFields();
                Set<String> keys = responseheaders.keySet();
                for (String key : keys) {
                    String val = hsc.getHeaderField(key);
                    responseHeaderString = responseHeaderString + val + "\r\n";
                }
                return responseHeaderString;
            }
            if (hc != null) {
                String responseHeaderString = "";
                Map<String, List<String>> responseheaders = hc.getHeaderFields();
                Set<String> keys = responseheaders.keySet();
                for (String key : keys) {
                    List<String> val = responseheaders.get(key);
                    responseHeaderString = responseHeaderString + key + ": " + val.toString();
                }
                return responseHeaderString;
            }
            return "";
        } catch (IOException e) {
            logger.debug(e);
            throw e;
        } catch (Exception e) {
            logger.debug(e);
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

    public static HttpURLConnection getHttpURLConnection(String requestUrl, String requestMethod, String contentType, String postString, String encoding, HashMap<String, String> headers) throws Exception {
        URLConnection httpUrlConn = null;
        HttpsURLConnection hsc = null;
        HttpURLConnection hc = null;
        InputStream inputStream = null;

        // url中没有协议，默认走http协议
        if(!requestUrl.contains("http")) {
            requestUrl = "http://" + requestUrl;
        }

        try {
            URL url = new URL(requestUrl);

            if (requestUrl.startsWith("https")) {
                SSLContext sslContext = SSLContext.getInstance("SSL");
                TrustManager[] tm = { new Cert() };
                sslContext.init(null, tm, new SecureRandom());
                SSLSocketFactory ssf = sslContext.getSocketFactory();
                //代理
                Proxy proxy = (Proxy) MainController.settingInfo.get("proxy");

                if(proxy != null) {
                    hsc = (HttpsURLConnection)url.openConnection(proxy);
                } else {
                    hsc = (HttpsURLConnection)url.openConnection();
                }
                hsc.setSSLSocketFactory(ssf);
                hsc.setHostnameVerifier(allHostsValid);
                httpUrlConn = hsc;
            } else {
                //代理
                Proxy proxy = (Proxy) MainController.settingInfo.get("proxy");

                if(proxy != null) {
                    hc = (HttpURLConnection)url.openConnection(proxy);
                } else {
                    hc = (HttpURLConnection)url.openConnection();
                }
                hc.setRequestMethod(requestMethod);
                //禁止302 跳转
                hc.setInstanceFollowRedirects(false);
                httpUrlConn = hc;
            }

            httpUrlConn.setConnectTimeout(Timeout);
            httpUrlConn.setReadTimeout(Timeout);
            if(contentType.equals("")) {
                httpUrlConn.setRequestProperty("Content-Type", "text/html");
            } else {
                httpUrlConn.setRequestProperty("Content-Type", contentType);
            }


            httpUrlConn.setRequestProperty("User-Agent", "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)");
            httpUrlConn.setRequestProperty("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9");
            httpUrlConn.setRequestProperty("Accept-Language","zh-CN,zh;q=0.9");
            httpUrlConn.setRequestProperty("Connection","close");

            httpUrlConn.setDoOutput(true);
            httpUrlConn.setDoInput(true);

            httpUrlConn.connect();

            return hc;
        } catch (IOException ie) {
            logger.debug(ie);
            if (hsc != null)
                return hc;
            if (hc != null)
                return hc;
            return null;
        } catch (Exception e) {
            logger.debug(e);
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
            logger.debug(e);
        } finally {
            if (baos != null) {
                baos.flush();
                baos.close();
            }
            if (bis != null)
                bis.close();
            if (inputStream != null)
                inputStream.close();

            if (encoding.equals("")) {
                return baos.toString();
            }
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

        String res = null;

        // url中没有协议，默认走http协议
        if(!requestUrl.contains("http")) {
            requestUrl = "http://" + requestUrl;
        }

        try {
            URL url = new URL(requestUrl);
            //代理
            Proxy proxy = (Proxy) MainController.settingInfo.get("proxy");
            if (requestUrl.startsWith("https")) {
                SSLContext sslContext = SSLContext.getInstance("SSL");
                TrustManager[] tm = { new Cert() };
                sslContext.init(null, tm, new SecureRandom());

                SSLSocketFactory ssf = sslContext.getSocketFactory();

                if (proxy != null) {
                    hsc = (HttpsURLConnection)url.openConnection(proxy);
                } else {
                    hsc = (HttpsURLConnection)url.openConnection();
                }
                hsc.setSSLSocketFactory(ssf);
                hsc.setHostnameVerifier(allHostsValid);
                httpUrlConn = hsc;
            } else {

                if (proxy != null) {
                    hc = (HttpURLConnection)url.openConnection(proxy);
                } else {
                    hc = (HttpURLConnection)url.openConnection();
                }

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

            if (hsc != null) {
                hsc.disconnect();
            }

            if (hc != null) {
                hc.disconnect();
            }

            return result;

        } catch (Exception e) {
            if (hsc != null) {
                hsc.disconnect();
            }

            if (hc != null) {
                hc.disconnect();
            }
            logger.debug(e);
            throw e;
        }

    }


    public static String ImageToBase64ByOnline(String imgURL) {
        ByteArrayOutputStream data = new ByteArrayOutputStream();
        try {
            // 创建URL
            URL url = new URL(imgURL);
            byte[] by = new byte[1024];
            // 创建链接
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(5000);
            InputStream is = conn.getInputStream();
            // 将内容读取内存中
            int len = -1;
            while ((len = is.read(by)) != -1) {
                data.write(by, 0, len);
            }
            // 关闭流
            is.close();
        } catch (IOException e) {
            logger.debug(e);
            e.printStackTrace();
        }
        // 对字节数组Base64编码
        BASE64Encoder encoder = new BASE64Encoder();
        return encoder.encode(data.toByteArray());
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

        // url中没有协议，默认走http协议
        if(!requestUrl.contains("http")) {
            requestUrl = "http://" + requestUrl;
        }
        try {
            URL url = new URL(requestUrl);
            //代理
            Proxy proxy = (Proxy) MainController.settingInfo.get("proxy");
            if (requestUrl.startsWith("https")) {
                SSLContext sslContext = SSLContext.getInstance("SSL");
                TrustManager[] tm = { new Cert() };
                sslContext.init(null, tm, new SecureRandom());
                SSLSocketFactory ssf = sslContext.getSocketFactory();

                if (proxy != null) {
                    hsc = (HttpsURLConnection)url.openConnection(proxy);
                } else {
                    hsc = (HttpsURLConnection)url.openConnection();
                }

                hsc.setSSLSocketFactory(ssf);
                hsc.setHostnameVerifier(allHostsValid);
                httpUrlConn = hsc;
            } else {
                if (proxy != null) {
                    hc = (HttpURLConnection)url.openConnection(proxy);
                } else {
                    hc = (HttpURLConnection)url.openConnection();
                }
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
            logger.debug(e);
            throw e;
        } catch (Exception e) {
            logger.debug(e);
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

    public static String httpReuest(String requestUrl, String method, HashMap<String, String> headers, String contentType, String postString, String encoding) throws Exception {
        return httpRequestAddHeader(requestUrl, Timeout, method, contentType, postString, encoding, headers);
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

    public static String getHttpReuest(String requestUrl, String encoding) throws Exception {
        return httpRequest(requestUrl, Timeout, "GET", "text/html", "", encoding);
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

    public static String getHeaderByHttpRequest(String requestUrl, String encoding, HashMap<String, String> headers) throws Exception {
        return headerByHttpRequest(requestUrl, Timeout, "GET", "text/xml", "", encoding, headers);
    }

    public static String postHeaderByHttpRequest(String requestUrl, String encoding, String postString, HashMap<String, String> headers) throws Exception {
        return headerByHttpRequest(requestUrl, Timeout, "POST", "text/xml", postString, encoding, headers);
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
            logger.debug(e);
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