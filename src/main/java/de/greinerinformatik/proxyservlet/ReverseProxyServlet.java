package de.greinerinformatik.proxyservlet;

import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;
import java.net.URL;
import java.net.HttpURLConnection;
import javax.net.ssl.HttpsURLConnection;
import java.net.ProtocolException;
import java.io.IOException;
import java.util.*;
import java.lang.reflect.Field;


public class ReverseProxyServlet extends HttpServlet {

   private static final long serialVersionUID = 8990663351667227929L;

   private String server;
   private int serverLength;
   
   @Override
   public void init(ServletConfig servletConfig) throws ServletException {
      server = servletConfig.getInitParameter("server");
      if (server == null) throw new ServletException("Servlet init-param 'server' must be configured in web.xml");
      if (!server.startsWith("http")) throw new ServletException("Servlet init-param 'server' must start with 'http'.");
      serverLength = server.length();
   }

   @Override
   protected void service(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
      if (req.getMethod().matches("DELETE|MKCALENDAR|MKCOL|PROPFIND|PROPPATCH|REPORT")) {
         doPost(req, resp);
      }
      else {
         super.service(req, resp); // DefaultServlet processing
      }
   }

   @Override
   public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
      doPost(request, response);
   }

   @Override
   public void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
      byte[] byteBuf = new byte[10000];

      // String dateTimeForLog = java.time.LocalDateTime.now().format(java.time.format.DateTimeFormatter.ofPattern("dd-MMM-uuuu HH:mm:ss.SSS"));
      // if (request.getPathInfo() == null || !(request.getPathInfo().matches("^(/skins/|/js/|/data/assets/|/images/).*"))) {
      //    System.out.println("\n" + dateTimeForLog + "\nrequest.getPathInfo(): " + request.getPathInfo()
      //      + "\nrequest.getPathTranslated(): " + request.getPathTranslated()
      //      + "\nrequest.getContextPath(): " + request.getContextPath()
      //      + "\nrequest.getQueryString(): " + request.getQueryString()
      //      + "\nrequest.getServletPath(): " + request.getServletPath());
      // }
      String path = request.getServletPath() + (request.getPathInfo() != null ? request.getPathInfo() : "");
      if (request.getQueryString() != null) path = path + "?" + request.getQueryString();
      // System.out.println("path: " + path);
      // URL url = new URL("http", server, path);
      URL url = new URL(server + path);
      HttpURLConnection con = (HttpURLConnection)url.openConnection();
      String methodName = request.getMethod();
      try {
         con.setRequestMethod(methodName);
      }
      catch (final ProtocolException pe) {
         try {
            final Class<?> httpURLConnectionClass = con.getClass();
            final Class<?> parentClass = httpURLConnectionClass.getSuperclass();
            final Field methodField;
            // If the implementation class is an HTTPS URL Connection, we
            // need to go up one level higher in the heirarchy to modify the
            // 'method' field.
            if (parentClass == HttpsURLConnection.class) {
               methodField = parentClass.getSuperclass().getDeclaredField("method");
            }
            else {
               methodField = parentClass.getDeclaredField("method");
            }
            methodField.setAccessible(true);
            methodField.set(con, methodName);
         }
         catch (final Exception e) {
            throw new ServletException(e);
         }
      }
      con.setDoOutput(true);
      con.setInstanceFollowRedirects(false);
      // StringBuilder requestHeadersSB = new StringBuilder("---Request headers:");
      boolean xForwardedForSet = false;
      for (Enumeration<String> e = request.getHeaderNames(); e.hasMoreElements();) {
         String headerName = e.nextElement();
         // requestHeadersSB.append("\n" + headerName + " - " + request.getHeader(headerName));
         if ("X-Forwarded-For".equals(headerName)) {
            if (xForwardedForSet) {
               throw new ServletException("More than one 'X-Forwarded-For' header.");
            }
            con.addRequestProperty(headerName, request.getHeader(headerName) + ", " + request.getRemoteAddr());
         }
         con.addRequestProperty(headerName, request.getHeader(headerName));
      }
      // con.addRequestProperty("cookie", "Bugzilla_login=post@greiner-informatik.de");
      if (!xForwardedForSet) {
         con.setRequestProperty("X-Forwarded-For", request.getRemoteAddr());
      }
      // requestHeadersSB.append("\nX-Forwarded-For - " + request.getRemoteAddr());
      // if (request.getPathInfo() == null || !(request.getPathInfo().matches("^(/skins/|/js/|/data/assets/|/images/).*"))) {
      //   System.out.println(requestHeadersSB);
      // }
      con.connect();
      if (methodName.matches("POST|MKCALENDAR|MKCOL|PROPFIND|PROPPATCH|REPORT")) {
         // StringBuilder postDataSB = new StringBuilder("---Post data: ");
         InputStream clientToProxyIS = request.getInputStream();
         OutputStream proxyToWebOS = con.getOutputStream();
         int nbBytes = clientToProxyIS.read(byteBuf);
         while (nbBytes > 0) {
            // postDataSB.append(new String(byteBuf, 0, nbBytes, java.nio.charset.Charset.forName("UTF-8")));
            proxyToWebOS.write(byteBuf, 0, nbBytes);
            nbBytes = clientToProxyIS.read(byteBuf);
         }
         clientToProxyIS.close();
         proxyToWebOS.flush();
         proxyToWebOS.close();
         // System.out.println(postDataSB + "\n---/Post data.");
      }
      int statusCode = con.getResponseCode();
      // System.out.println("statusCode: " + statusCode);
      if (statusCode == 404 || statusCode == 500) {
         try {
            con.getInputStream();
         }
         catch (IOException ioe) {
            con.disconnect();
            String errorMsg = ioe.getMessage();
            response.sendError(statusCode, errorMsg);
         }
      }
      else {
         response.setStatus(statusCode);
         // StringBuilder responseHeadersSB = new StringBuilder("---Response headers:");
         Map<String, List<String>> headerFields = con.getHeaderFields();
         for (String responseHeaderKey : headerFields.keySet()) {
            // responseHeadersSB.append("\n" + responseHeaderKey + " - " + ((List)mapEntry.getValue()).get(0).toString());
            if (responseHeaderKey != null) { // for simplicity assume that encoding is always UTF-8 nowadays
               for (String responseHeaderValue : headerFields.get(responseHeaderKey)) {
                  // System.out.println("responseHeaderValue: " + responseHeaderValue);
                  if ("Location".equals(responseHeaderKey)) {
                     // System.out.println("Location old response value: " + responseHeaderValue);
                     if (responseHeaderValue.startsWith(server)) {
                        responseHeaderValue = request.getScheme() + "://" + request.getServerName() + responseHeaderValue.substring(serverLength);
                        // System.out.println("Location new response value: " + responseHeaderValue);
                     }
                  }
                  response.addHeader(responseHeaderKey, responseHeaderValue);
               }
            }
         }
         // if (request.getPathInfo() == null || !(request.getPathInfo().matches("^(/skins/|/js/|/data/assets/|/images/).*"))) {
         //    System.out.println(responseHeadersSB);
         // }
         if (statusCode == 401 || statusCode == 403) {
            response.setIntHeader("Content-Length", 0); // tell client not to wait for data
         }
         else {
            InputStream webToProxyIS = con.getInputStream();
            OutputStream proxyToClientOS = response.getOutputStream();
            int nbBytes2 = webToProxyIS.read(byteBuf);
            while (nbBytes2 > 0) {
               proxyToClientOS.write(byteBuf, 0, nbBytes2);
               nbBytes2 = webToProxyIS.read(byteBuf);
            }
            webToProxyIS.close();
            proxyToClientOS.close();
         }
         con.disconnect();
      }
   }
}
