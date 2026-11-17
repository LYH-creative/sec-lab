package lab;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

/**
 * Shiro 靶场的全部 HTTP 逻辑。
 *
 * 三种角色（--lab.mode 决定）：
 *   550    Shiro 1.2.4 默认密钥 → rememberMe 反序列化 RCE
 *   721    Shiro 1.2.5 随机密钥 → 用 padding oracle 伪造身份
 *   bypass 1.4.2 / 1.5.2 / 1.6.0 / 1.7.1 → 四个路径绕过 CVE 的版本对照
 *
 * 三种模式共用同一份代码和同一个 jar，只有 filter chain 和 /admin 的
 * 判定逻辑不同——这样"差异"只可能来自 Shiro 版本本身。
 */
@SpringBootApplication
@RestController
public class ShiroLabApplication implements WebMvcConfigurer {

    @Value("${lab.mode:550}")
    private String mode;

    @Value("${lab.version:unknown}")
    private String shiroVersion;

    public static void main(String[] args) {
        // 先把两份序列化原料写到 /app/payloads/，再启动 web
        LabGen.prepare();
        SpringApplication.run(ShiroLabApplication.class, args);
    }

    // ==================================================================
    //  静态资源映射
    // ==================================================================
    /**
     * /out/**      → /tmp/out/
     *   550 的 RCE 是无回显的，payload 把 /flag 复制到这个目录，
     *   再由 HTTP 取回。这是真实攻防里最常见的"带外/落文件"套路。
     *
     * /payloads/** → /app/payloads/
     *   给 POC 脚本下载序列化原料用的。拿到明文序列化字节只是第一步，
     *   550 还缺 key、721 还缺 padding oracle，不算泄题。
     */
    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        registry.addResourceHandler("/out/**").addResourceLocations("file:/tmp/out/");
        registry.addResourceHandler("/payloads/**").addResourceLocations("file:/app/payloads/");
    }

    // ==================================================================
    //  页面
    // ==================================================================
    @GetMapping(value = "/", produces = "text/html;charset=UTF-8")
    public String index() {
        Subject subject = SecurityUtils.getSubject();
        Object principal = subject.getPrincipal();
        String who = principal == null ? "匿名" : String.valueOf(principal);

        StringBuilder body = new StringBuilder();
        body.append("<header><h1><span class=\"prompt\">>_</span> Shiro ").append(shiroVersion)
            .append("</h1><span class=\"tag\">").append(modeName()).append("</span></header>");

        body.append("<div class=\"card\">")
            .append("<div class=\"k\">当前身份</div>")
            .append("<div class=\"v\">").append(esc(who)).append("</div>")
            .append("<div class=\"sub\">authenticated=").append(subject.isAuthenticated())
            .append("　remembered=").append(subject.isRemembered()).append("</div>")
            .append("</div>");

        body.append("<div class=\"card\">")
            .append("<div class=\"k\">账号</div>")
            .append("<div class=\"sub\">root / root123　·　guest / guest123</div>")
            .append("</div>");

        if ("bypass".equals(mode)) {
            body.append("<div class=\"card\">")
                .append("<div class=\"k\">本版本要试的事</div>")
                .append("<div class=\"sub\">不登录，直接想办法让请求进到 <code>/admin</code>。")
                .append("被 Shiro 过滤器拦住会 302 到 /login；绕过去了就是 200 + flag。</div>")
                .append("</div>");
        } else if ("721".equals(mode)) {
            body.append("<div class=\"card\">")
                .append("<div class=\"k\">本版本要试的事</div>")
                .append("<div class=\"sub\">用 guest 登录并勾选「记住我」，拿到 rememberMe cookie，")
                .append("然后不改 key、只靠 <code>/__oracle</code> 的响应头，把它改成 root 的身份。</div>")
                .append("</div>");
        } else {
            body.append("<div class=\"card\">")
                .append("<div class=\"k\">本版本要试的事</div>")
                .append("<div class=\"sub\">rememberMe 用的是硬编码密钥。随便发一个自己加密的 cookie，")
                .append("看服务端会不会替你把它反序列化。</div>")
                .append("</div>");
        }

        body.append("<nav><a href=\"/login\">登录</a>")
            .append("<a href=\"/admin\">/admin</a>")
            .append("<a href=\"/logout\">登出</a></nav>");

        return page("首页", body.toString());
    }

    @GetMapping(value = "/login", produces = "text/html;charset=UTF-8")
    public String loginForm(@RequestParam(required = false) String err) {
        StringBuilder body = new StringBuilder();
        body.append("<header><h1>登录</h1><span class=\"tag\">Shiro ").append(shiroVersion)
            .append("</span></header>");
        body.append("<form method=\"post\" action=\"/login\" class=\"card\">");
        if (err != null) {
            body.append("<div class=\"err\">账号或密码不对</div>");
        }
        body.append("<label>用户名<input name=\"username\" value=\"guest\" autocomplete=\"off\"></label>")
            .append("<label>密码<input name=\"password\" value=\"guest123\" autocomplete=\"off\"></label>")
            .append("<label class=\"row\"><input type=\"checkbox\" name=\"rememberMe\" value=\"1\" checked>")
            .append(" 记住我（写 rememberMe cookie）</label>")
            .append("<button type=\"submit\">登录</button>")
            .append("</form>");
        body.append("<nav><a href=\"/\">返回</a></nav>");
        return page("登录", body.toString());
    }

    @PostMapping("/login")
    public void login(@RequestParam String username,
                      @RequestParam String password,
                      @RequestParam(required = false) String rememberMe,
                      HttpServletResponse response) throws IOException {

        UsernamePasswordToken token = new UsernamePasswordToken(username, password);
        token.setRememberMe(rememberMe != null && !"0".equals(rememberMe) && !"false".equals(rememberMe));
        try {
            SecurityUtils.getSubject().login(token);
            response.sendRedirect("/");
        } catch (AuthenticationException e) {
            response.sendRedirect("/login?err=1");
        }
    }

    @GetMapping("/logout")
    public void logout(HttpServletResponse response) throws IOException {
        SecurityUtils.getSubject().logout();
        response.sendRedirect("/");
    }

    /**
     * /admin 的判定分两种：
     *
     *   bypass 模式不在这里做任何身份检查——鉴权 100% 交给 Shiro 的
     *   filter chain（/admin/** = authc）。这正是那些 CVE 的成因：
     *   应用只信任"URL 被过滤器匹配到了"这一件事。所以只要路径能被
     *   绕过、却被 Spring 正常路由到本方法，就应当看到 flag。
     *
     *   550/721 模式额外要求 principal 是 root，用来区分"普通用户"和
     *   "被伪造出来的管理员"。
     */
    @GetMapping(value = "/admin", produces = "text/html;charset=UTF-8")
    public String admin() {
        Subject subject = SecurityUtils.getSubject();

        if (!"bypass".equals(mode)) {
            Object principal = subject.getPrincipal();
            String who = principal == null ? "" : String.valueOf(principal);
            if (!"root".equals(who)) {
                return page("403", "<header><h1>403</h1></header>"
                        + "<div class=\"card\"><div class=\"sub\">当前身份是 <code>" + esc(who)
                        + "</code>，这个页面只给 root。</div></div>"
                        + "<nav><a href=\"/\">返回</a></nav>");
            }
        }

        String flag = readFlag();
        return page("admin", "<header><h1>管理后台</h1><span class=\"tag\">Shiro "
                + shiroVersion + "</span></header>"
                + "<div class=\"card\"><div class=\"k\">flag</div><div class=\"v flag\">"
                + esc(flag) + "</div></div>"
                + "<nav><a href=\"/\">返回</a></nav>");
    }

    /**
     * padding oracle 探针。
     *
     * 判定完全走状态码，不走自定义头：
     *   204  填充合法（解密成功，不管是反序列化成功还是失败）
     *   400  填充非法
     *   404  这个靶场没开 721 模式
     *
     * 为什么不用响应头：头要在 filter 里补，而 204 一返回容器就可能把响应
     * commit 掉，头就丢了。并发一高就随机丢，表现为"跑着跑着 oracle 没了"。
     * 状态码由 Spring 正常写，不依赖时序。
     *
     * 执行到这里时 Shiro 的过滤器已经跑完，LabState 里已经有结论了。
     */
    @GetMapping("/__oracle")
    public ResponseEntity<Void> oracle() {
        if (!"721".equals(mode)) {
            return ResponseEntity.notFound().build();
        }
        String v = LabState.get();
        boolean padded = LabState.OK.equals(v) || LabState.DESER.equals(v);
        return padded ? ResponseEntity.noContent().build()
                       : ResponseEntity.badRequest().build();
    }

    // ==================================================================
    //  工具
    // ==================================================================
    private String modeName() {
        if ("721".equals(mode)) {
            return "CVE-2019-12422 padding oracle";
        }
        if ("bypass".equals(mode)) {
            return "路径绕过 · authc";
        }
        return "CVE-2016-4437 默认密钥";
    }

    private String readFlag() {
        try {
            byte[] bytes = Files.readAllBytes(Paths.get("/flag"));
            return new String(bytes, StandardCharsets.UTF_8).trim();
        } catch (Exception e) {
            return "(读不到 /flag：" + e.getMessage() + ")";
        }
    }

    private static String esc(String s) {
        if (s == null) {
            return "";
        }
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;");
    }

    private static final String CSS =
            "*{box-sizing:border-box;margin:0;padding:0}"
          + "body{background:#0a0e14;color:#dbe6f2;font-family:-apple-system,"
          + "\"PingFang SC\",\"Microsoft YaHei\",sans-serif;padding:48px 20px;"
          + "font-size:14px;line-height:1.7}"
          + ".wrap{max-width:640px;margin:0 auto}"
          + "header{display:flex;align-items:baseline;gap:12px;margin-bottom:28px}"
          + "h1{font-size:22px;font-weight:600}"
          + ".prompt{color:#2ee6a8;font-family:ui-monospace,Menlo,monospace}"
          + ".tag{font-size:11px;color:#7c8fa3;border:1px solid #223040;"
          + "border-radius:999px;padding:2px 10px}"
          + ".card{background:#121a24;border:1px solid #1a2530;border-radius:10px;"
          + "padding:18px 20px;margin-bottom:14px}"
          + ".k{font-size:11px;letter-spacing:.1em;text-transform:uppercase;color:#52616f;"
          + "margin-bottom:6px}"
          + ".v{font-family:ui-monospace,Menlo,monospace;font-size:16px;color:#2ee6a8}"
          + ".v.flag{font-size:20px;word-break:break-all}"
          + ".sub{font-size:13px;color:#7c8fa3}"
          + "code{font-family:ui-monospace,Menlo,monospace;font-size:12.5px;"
          + "background:rgba(46,230,168,.08);color:#2ee6a8;padding:1px 5px;border-radius:4px}"
          + "nav{margin-top:22px;display:flex;gap:18px}"
          + "nav a{color:#4c9aff;text-decoration:none;font-size:13px}"
          + "nav a:hover{text-decoration:underline}"
          + "label{display:block;margin-bottom:12px;font-size:13px;color:#7c8fa3}"
          + "label.row{display:flex;align-items:center;gap:8px}"
          + "input[type=text],input[name=username],input[name=password],input:not([type])"
          + "{display:block;width:100%;margin-top:6px;padding:9px 11px;background:#0c1219;"
          + "border:1px solid #223040;border-radius:6px;color:#dbe6f2;font-size:14px;"
          + "font-family:ui-monospace,Menlo,monospace}"
          + "input[type=checkbox]{width:auto;margin:0}"
          + "button{margin-top:6px;padding:9px 20px;background:#2ee6a8;border:0;"
          + "border-radius:6px;color:#06221a;font-weight:600;font-size:13px;cursor:pointer}"
          + ".err{color:#ff7b72;font-size:13px;margin-bottom:10px}";

    private static String page(String title, String body) {
        return "<!DOCTYPE html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\">"
                + "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
                + "<title>" + title + " · Shiro Lab</title><style>" + CSS + "</style></head>"
                + "<body><div class=\"wrap\">" + body + "</div></body></html>";
    }
}
