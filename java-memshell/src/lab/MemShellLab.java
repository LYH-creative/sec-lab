package lab;

import org.apache.catalina.core.StandardContext;
import org.apache.tomcat.util.descriptor.web.FilterDef;
import org.apache.tomcat.util.descriptor.web.FilterMap;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.FilterRegistration;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.util.Arrays;

/*
 * 靶场主应用：一个最小 Spring Boot 2.3.12 / Tomcat 9 服务，五个端点。
 *
 *   /               正常业务页，用来证明「马在不在，业务都照常」
 *   /__lab/scan     防守视角：把 JVM 里真实的 filterDefs / filterMaps 全列出来
 *   /__lab/inject   模拟 RCE 入口：收一段 base64 字节码，调 MemShellInject 注入
 *   /__lab/standard 对照组：走 Servlet 3.0 标准 addFilter，实测它会被 Lifecycle 拒绝
 *   /__lab/probe    自查 classpath 里有没有 evil.EvilFilter（应当始终没有）
 *
 * /__lab/* 只在本地靶场存在，用来把「注入通道」和「内存马本体」拆开看。
 * 真实环境里没有这些端点，注入通道是反序列化 / JNDI / 表达式注入。
 */
@SpringBootApplication
@RestController
public class MemShellLab {

    public static void main(String[] args) {
        SpringApplication.run(MemShellLab.class, args);
    }

    @GetMapping(value = "/", produces = "text/plain;charset=UTF-8")
    public String index() {
        return "business-ok\napp=memshell-lab\npath=/\n";
    }

    /*
     * 检测端点。这是整份手册的判题器：磁盘扫描看不到东西，
     * 但把容器运行时内存里的注册表打出来，多出来的 Filter 一目了然。
     */
    @GetMapping(value = "/__lab/scan", produces = "text/plain;charset=UTF-8")
    public String scan(HttpServletRequest req) throws Exception {
        StandardContext ctx = MemShellInject.context(req.getServletContext());
        StringBuilder sb = new StringBuilder();
        sb.append("jvm=").append(System.getProperty("java.version"))
          .append("  process=").append(ManagementFactory.getRuntimeMXBean().getName()).append('\n');
        sb.append("context=").append(ctx.getClass().getName()).append('\n');
        sb.append("evilClassOnClasspath=").append(onClasspath()).append('\n');

        FilterDef[] defs = ctx.findFilterDefs();
        sb.append("filterDefs=").append(defs.length).append('\n');
        for (FilterDef d : defs) {
            Filter f = d.getFilter();
            sb.append("  [").append(d.getFilterName()).append("]\n");
            sb.append("    class=").append(d.getFilterClass()).append('\n');
            if (f == null) {
                sb.append("    codeSource=(no instance in FilterDef)\n");
            } else {
                sb.append("    codeSource=")
                  .append(f.getClass().getProtectionDomain().getCodeSource()).append('\n');
                sb.append("    loader=").append(f.getClass().getClassLoader().getClass().getName()).append('\n');
            }
        }

        FilterMap[] maps = ctx.findFilterMaps();
        sb.append("filterMaps=").append(maps.length).append('\n');
        for (FilterMap m : maps) {
            sb.append("  ").append(m.getFilterName())
              .append(" -> ").append(Arrays.toString(m.getURLPatterns())).append('\n');
        }
        return sb.toString();
    }

    @GetMapping(value = "/__lab/inject", produces = "text/plain;charset=UTF-8")
    public String inject(HttpServletRequest req, @RequestParam("b64") String b64) {
        try {
            return "injected: " + MemShellInject.inject(req, b64) + "\n";
        } catch (Exception e) {
            Throwable t = e;
            while (t.getCause() != null) {
                t = t.getCause();
            }
            return "inject failed: " + e.getClass().getName()
                    + "\n  cause=" + t.getClass().getName() + ": " + t.getMessage() + "\n";
        }
    }

    /*
     * 对照组：Servlet 3.0 的 ServletContext.addFilter 是合法 API，
     * 但 Tomcat 的 ApplicationContext 只允许在 STARTING_PREP 阶段调用。
     * 应用启动完成后调用会抛 IllegalStateException —— 这就是必须反射的原因。
     */
    @GetMapping(value = "/__lab/standard", produces = "text/plain;charset=UTF-8")
    public String standard(HttpServletRequest req) {
        try {
            FilterRegistration.Dynamic reg = req.getServletContext().addFilter(
                    "standard-api-test", new NoopFilter());
            reg.addMappingForUrlPatterns(null, false, "/*");
            return "standard API accepted\n";
        } catch (Exception e) {
            return "standard API rejected\n  " + e.getClass().getName()
                    + "\n  " + e.getMessage() + "\n";
        }
    }

    @GetMapping(value = "/__lab/probe", produces = "text/plain;charset=UTF-8")
    public String probe() {
        return "evilClassOnClasspath=" + onClasspath() + "\n";
    }

    private static boolean onClasspath() {
        try {
            Class.forName("evil.EvilFilter");
            return true;
        } catch (ClassNotFoundException e) {
            return false;
        }
    }

    public static class NoopFilter implements Filter {
        public void init(FilterConfig c) {
        }

        public void destroy() {
        }

        public void doFilter(ServletRequest q, ServletResponse s, FilterChain chain)
                throws IOException, ServletException {
            chain.doFilter(q, s);
        }
    }
}
