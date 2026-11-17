package lab;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.realm.SimpleAccountRealm;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Shiro 的接线板。
 *
 * 这里刻意没有用 shiro-spring-boot-web-starter —— 那个 starter 是 1.4 以后
 * 才有的，1.2.4 时代的人就是这么手写 ShiroFilterFactoryBean 的。
 * 用同一套配置跑六个版本，"版本差异"才只体现在漏洞本身，而不是配置写法。
 */
@Configuration
public class ShiroConfig {

    @Value("${lab.mode:550}")
    private String mode;

    /**
     * 调试开关：把 rememberMe 的 AES 密钥打到日志里。
     *
     * 只在 --lab.debug=true 时生效，正常起靶场不会输出。
     * 它的用途是"绕过 oracle 直接验证 payload 本身"——用真 key 加密一份
     * 伪造身份，看服务端认不认。如果不认，说明问题在 payload / 明文构造；
     * 如果认，说明问题在攻击侧的 D 值推算。二分定位，比盲猜快。
     */
    @Value("${lab.debug:false}")
    private boolean debugKey;

    @Bean
    public Realm realm() {
        SimpleAccountRealm realm = new SimpleAccountRealm();
        // 两个账号，长度不同是故意的：root(4) 比 guest(5) 短一个字节，
        // 721 伪造身份时没法靠"等长 XOR"偷懒，必须真的重排密文块。
        realm.addAccount("root", "root123");
        realm.addAccount("guest", "guest123");
        return realm;
    }

    @Bean
    public DefaultWebSecurityManager securityManager(Realm realm) {
        DefaultWebSecurityManager sm = new DefaultWebSecurityManager();
        sm.setRealm(realm);
        // 关键：换成带记账的 rememberMe 实现
        sm.setRememberMeManager(new LabRememberMeManager());

        // 没有 web 环境（比如单元测试）时也让它能取到 SecurityManager
        SecurityUtils.setSecurityManager(sm);

        if (debugKey) {
            dumpKey(sm.getRememberMeManager());
        }
        return sm;
    }

    /**
     * 反射读密钥。用反射而不是直接调 getEncryptionCipherKey()，
     * 是因为这个方法在 1.7 之后改过名，同一份源码要能编译六个版本。
     */
    private static void dumpKey(Object rememberMeManager) {
        String[] candidates = {"getEncryptionCipherKey", "getCipherKey"};
        for (String name : candidates) {
            try {
                java.lang.reflect.Method m =
                        rememberMeManager.getClass().getMethod(name);
                m.setAccessible(true);
                Object v = m.invoke(rememberMeManager);
                if (v instanceof byte[]) {
                    System.out.println("[lab] rememberMe AES key = "
                            + java.util.Base64.getEncoder().encodeToString((byte[]) v));
                    return;
                }
            } catch (Exception ignored) {
                // 换下一个候选名
            }
        }
        System.out.println("[lab] 读不到 rememberMe 密钥（这个版本的方法名不一样）");
    }

    @Bean
    public ShiroFilterFactoryBean shiroFilter(DefaultWebSecurityManager securityManager) {
        ShiroFilterFactoryBean bean = new ShiroFilterFactoryBean();
        bean.setSecurityManager(securityManager);

        Map<String, String> chain = new LinkedHashMap<String, String>();
        chain.put("/login", "anon");
        chain.put("/__oracle", "anon");
        chain.put("/payloads/**", "anon");
        chain.put("/out/**", "anon");

        // 三种模式在 /admin 上的差别，就是这个靶场想让你看见的东西：
        //
        //   bypass  → authc：只认"当前会话登录过"。未登录直接 302 到 /login，
        //             于是"路径能不能绕过 Shiro 的过滤器"一目了然。
        //   550/721 → user ：authc + rememberMe 都放行。因为这两个洞的
        //             攻击结果本来就是"我拿着一个伪造的 rememberMe 身份"，
        //             用 authc 的话攻击成功了也进不去，演示不出来。
        chain.put("/admin/**", "bypass".equals(mode) ? "authc" : "user");
        chain.put("/**", "anon");

        bean.setFilterChainDefinitionMap(chain);
        bean.setLoginUrl("/login");
        return bean;
    }
}
