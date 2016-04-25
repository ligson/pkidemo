package web.ssl;

import java.io.IOException;

/**
 * Created by ligson on 2016/4/22.
 */
public class DemoServlet extends javax.servlet.http.HttpServlet {
    protected void doPost(javax.servlet.http.HttpServletRequest request, javax.servlet.http.HttpServletResponse response) throws javax.servlet.ServletException, IOException {
        System.out.println("===========");
        Object certObj = request.getAttribute("javax.servlet.request.X509Certificate");
        response.getWriter().println("ok......."+certObj);
    }

    protected void doGet(javax.servlet.http.HttpServletRequest request, javax.servlet.http.HttpServletResponse response) throws javax.servlet.ServletException, IOException {
        doPost(request, response);
    }
}
