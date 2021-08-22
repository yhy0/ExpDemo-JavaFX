package fun.fireline.tools;

import fun.fireline.controller.MainController;
import org.apache.log4j.Logger;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.Proxy;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Iterator;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;

/**
 * @author yhy
 * @date 2021/8/20 22:57
 * @github https://github.com/yhy0
 * 取自 https://github.com/bewhale/thinkphp_gui_tools
 * 蓝鲸 师傅封装的 http 包比较好用
 * 感谢蓝鲸师傅，蓝鲸 yyds
 */



public class HttpTools {
    private static String UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.90 Safari/537.36";

    private static final Logger logger = Logger.getLogger(MainController.class);

    public HttpTools() {
    }

    public static Response get(String url, HashMap<String, String> headers, String encoding) {
        Response response = new Response(0, (String)null, (String)null, (String)null);

        try {
            HttpURLConnection conn = getCoon(url);
            conn.setRequestMethod("GET");
            Iterator var4 = headers.keySet().iterator();

            while(var4.hasNext()) {
                String key = (String)var4.next();
                conn.setRequestProperty(key, (String)headers.get(key));
            }

            response = getResponse(conn, encoding);
        } catch (SocketTimeoutException var6) {
            logger.debug(var6.getMessage());
            response.setError("连接超时!");
        } catch (IOException var7) {
            logger.debug(var7.getMessage());
            response.setError(var7.getMessage());
        } catch (KeyManagementException | NoSuchProviderException | NoSuchAlgorithmException var8) {
            logger.debug(var8.getMessage());
            response.setError(var8.getMessage());
        }
        return response;
    }

    public static Response post(String url, String postString, HashMap<String, String> headers, String encoding) {
        Response response = new Response(0, (String)null, (String)null, (String)null);

        try {
            HttpURLConnection conn = getCoon(url);
            conn.setRequestMethod("POST");
            Iterator var5 = headers.keySet().iterator();

            while(var5.hasNext()) {
                String key = (String)var5.next();
                conn.setRequestProperty(key, (String)headers.get(key));
            }

            OutputStream outputStream = conn.getOutputStream();
            outputStream.write(postString.getBytes());
            outputStream.flush();
            outputStream.close();
            response = getResponse(conn, encoding);
        } catch (Exception var8) {
            logger.debug(var8.getMessage());
            response.setError(var8.getMessage());
        }

        return response;
    }

    private static Response getResponse(HttpURLConnection conn, String encoding) {
        Response response = new Response(0, (String)null, (String)null, (String)null);

        try {
            conn.connect();
            response.setCode(conn.getResponseCode());
            response.setHead(conn.getHeaderFields().toString());
            response.setText(streamToString(conn.getInputStream(), encoding));
        } catch (IOException var3) {
            response.setError(var3.toString());
            logger.debug(var3.toString());
        }

        return response;
    }

    private static HttpURLConnection getCoon(String url) throws IOException, NoSuchProviderException, NoSuchAlgorithmException, KeyManagementException {
        SSLContext sslcontext = SSLContext.getInstance("SSL", "SunJSSE");
        TrustManager[] tm = new TrustManager[]{new Cert()};
        sslcontext.init((KeyManager[])null, tm, new SecureRandom());
        HostnameVerifier ignoreHostnameVerifier = new HostnameVerifier() {
            public boolean verify(String s, SSLSession sslsession) {
                logger.debug("WARNING: Hostname is not matched for cert.");
                return true;
            }
        };
        HttpsURLConnection.setDefaultHostnameVerifier(ignoreHostnameVerifier);
        HttpsURLConnection.setDefaultSSLSocketFactory(sslcontext.getSocketFactory());
        URL url_object = new URL(url);
        HttpURLConnection conn = (HttpURLConnection)url_object.openConnection();
        //代理
        Proxy proxy = (Proxy) MainController.settingInfo.get("proxy");
        if(proxy != null) {
            conn = (HttpURLConnection)url_object.openConnection(proxy);
        }

        conn.setRequestProperty("User-Agent", UA);
        conn.setRequestProperty("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9");
        conn.setRequestProperty("Accept-Language","zh-CN,zh;q=0.9");
        conn.setRequestProperty("Connection","close");

        conn.setConnectTimeout(5000);
        conn.setReadTimeout(5000);
        conn.setDoOutput(true);
        conn.setDoInput(true);
        conn.setUseCaches(false);
        conn.setInstanceFollowRedirects(false);
        return conn;
    }

    private static String streamToString(InputStream inputStream, String encoding) {
        String resultString = null;
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        int len;
        byte[] data = new byte[1024];

        try {
            while((len = inputStream.read(data)) != -1) {
                byteArrayOutputStream.write(data, 0, len);
            }
            if(encoding.equals("")) {
                encoding = "UTF-8";
            }
            resultString = byteArrayOutputStream.toString(encoding);
        } catch (IOException var6) {
            resultString = var6.getMessage();
            var6.printStackTrace();
        }

        return resultString;
    }
}

