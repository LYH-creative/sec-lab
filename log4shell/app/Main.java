/*
 * SecLab · Log4Shell 靶场服务端
 *
 * 这个程序本身没有任何"漏洞代码"，它只做了一件所有业务系统都会做的事：
 * 把请求里的 User-Agent 记进日志。漏洞来自 log4j-core 2.14.1 —— 2.0-beta9
 * 到 2.14.1 的 PatternLayout 会对消息内容做 StrSubstitutor 替换，
 * 遇到 ${jndi:...} 就真的去发起一次 JNDI 查询。
 *
 * 三个 JVM 进程共用这份 class，区别只在 start.sh 里的 classpath 和 JVM 参数：
 *   8080 / 2.14.1 / trustURLCodebase=true / 带黑名单端点   L1~L3
 *   8081 / 2.14.1 / JDK 默认                               L4 对照一
 *   8082 / 2.17.1 / JDK 默认                               L4 对照二
 *
 * 触发点全文只有下面那一行 LOG.info，其余都是为了让 HTTP 能收发而写的样板。
 */

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.Executors;

public class Main {

    private static final Logger LOG = LogManager.getLogger("SecLabLog4Shell");

    public static void main(String[] args) throws Exception {
        final int port = Integer.parseInt(args[0]);
        final boolean hasFilter = args.length > 1 && "filter".equals(args[1]);
        final String label = args.length > 2 ? args[2] : "unknown";

        HttpServer server = HttpServer.create(new InetSocketAddress("0.0.0.0", port), 0);
        server.createContext("/", ex -> serve(ex, hasFilter, label));

        // HttpServer 默认只有一个线程。JNDI lookup 是同步的，会一直等到 LDAP
        // 超时；一个卡住的请求会把后面所有请求堵死，所以这里给个小线程池。
        server.setExecutor(Executors.newFixedThreadPool(8));
        server.start();
        System.out.println("[app] port=" + port + " label=" + label + " filter=" + hasFilter);
    }

    private static void serve(HttpExchange ex, boolean hasFilter, String label) throws IOException {
        String path = ex.getRequestURI().getPath();
        String ua = ex.getRequestHeaders().getFirst("User-Agent");
        if (ua == null) {
            ua = "";
        }

        // L3 的"修复"：一个很常见的天真黑名单，把关键字直接抹掉。
        // 只作用于 /filtered 这个端点，其他路径保持原样。
        boolean filtered = hasFilter && path.startsWith("/filtered");
        String value = filtered ? naiveFilter(ua) : ua;

        /*
         * 唯一的触发点。
         *
         * 注意不能写成 LOG.info("{}", value)：占位符参数同样会被替换，但这里
         * 故意用最朴素的字符串拼接，让"用户可控内容进了日志消息"这件事一眼可见。
         * 另外 log4j2.xml 必须把 root level 设成 info —— 没有配置文件时
         * log4j-core 的默认级别是 ERROR，info 事件根本不会产生，lookup 也就
         * 不会跑，这是本地复现最常见的"打了没反应"原因。
         */
        LOG.info("path=" + path + " ua=" + value);

        String body = "label=" + label
                + "\npath=" + path
                + "\nfiltered=" + filtered
                + "\nlogged_ua=" + value
                + "\n";
        byte[] out = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
        ex.sendResponseHeaders(200, out.length);
        ex.getResponseBody().write(out);
        ex.close();
    }

    /* 黑名单只认连续出现的 jndi / ldap 两个词，大小写不敏感。
       它挡不住 log4j 自己的 lookup 语法拼出来的关键字，这就是 L3 的考点。 */
    private static String naiveFilter(String s) {
        return s.replaceAll("(?i)jndi|ldap", "");
    }
}
