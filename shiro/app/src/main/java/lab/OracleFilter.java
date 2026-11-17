package lab;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 把 rememberMe 的解析结果写成响应头。
 *
 * 顺序排在最高优先级：先于 Shiro 的过滤器进入，Shiro 解析 cookie 时
 * 会往 LabState 里写结果，等整条链接返回后我们再读出来。
 *
 * 只在 721 模式下输出（否则 550 靶场里也会冒出一个"能测填充"的头，
 * 属于送答案）。真实环境没有这个头，见 LabState 里的说明。
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class OracleFilter extends OncePerRequestFilter {

    @Value("${lab.mode:550}")
    private String mode;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {

        boolean probe = "/__oracle".equals(request.getRequestURI());
        boolean hasCookie = false;
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie c : cookies) {
                if ("rememberMe".equals(c.getName())) {
                    hasCookie = true;
                    break;
                }
            }
        }

        LabState.clear();
        try {
            chain.doFilter(request, response);
        } catch (ServletException | IOException e) {
            // 探针请求要保证"永远能回一个头"，否则 oracle 会随机断线。
            // 真的抛到这里说明反序列化炸穿了 Shiro 的 catch，按 deser 记。
            if (!probe) {
                throw e;
            }
            if (LabState.get() == null) {
                LabState.set(LabState.DESER);
            }
        }

        if ("721".equals(mode) && probe && !response.isCommitted()) {
            String v = LabState.get();
            if (v == null) {
                v = hasCookie ? LabState.OK : LabState.CLEAN;
            }
            // 头只是给人看的，脚本判定用状态码（由 controller 写）。
            // 响应已经 commit 时这里静默跳过，不影响攻击。
            response.setHeader("X-Lab-Oracle", v);
        }
    }
}
