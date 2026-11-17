package lab;

/**
 * 一次请求内 rememberMe cookie 的解析结果。
 *
 * 为什么需要这个类：
 *   Shiro 解析 rememberMe 时，失败有两种完全不同的原因——
 *     1. 解密后 PKCS5 填充非法（key 不对 / 密文被乱改）
 *     2. 填充合法，但里面的字节不是合法的 Java 序列化流
 *   这两件事在默认实现里都被 onRememberedPrincipalFailure() 吞掉，
 *   客户端看不出区别。而 Shiro-721 的 padding oracle 攻击恰恰
 *   要的就是这个区别：只要能把「填充错了」和「填充对了」分开，
 *   就能一个字节一个字节地把整段明文推出来，全程不需要知道 key。
 *
 *   所以这里把结果丢进 ThreadLocal，由 OracleFilter 写进响应头。
 *   真实环境里没有这个头，攻击者只能靠状态码 / 响应体长度 / 耗时
 *   去猜——那也是 Shiro-721 在实战里经常"跑得很慢很玄学"的原因。
 *
 * oracle 的四种取值：
 *   clean  没带 rememberMe cookie
 *   ok     解密 + 反序列化都通过（身份被成功还原）
 *   pad    解密失败 / 填充非法
 *   deser  填充合法，但反序列化失败
 */
public final class LabState {

    public static final String CLEAN = "clean";
    public static final String OK    = "ok";
    public static final String PAD   = "pad";
    public static final String DESER = "deser";

    private static final ThreadLocal<String> RESULT = new ThreadLocal<String>();

    private LabState() {
    }

    public static void clear() {
        RESULT.remove();
    }

    public static void set(String value) {
        RESULT.set(value);
    }

    public static String get() {
        return RESULT.get();
    }

    /**
     * 由 LabRememberMeManager 在捕获异常时调用。
     *
     * 判断方式是顺着 cause 链找 BadPaddingException / CryptoException：
     *   - shiro 的 JcaCipherService 会把 JCE 抛出的 BadPaddingException
     *     包成 CryptoException，所以见到它基本等于"填充错"
     *   - 反序列化失败抛的是 SerializationException / StreamCorruptedException
     * 用类名字符串匹配而不是 instanceof，是为了让同一份源码在
     * shiro 1.2.4 到 1.7.1 之间都能编译过（中间改过包名）。
     */
    public static void fail(RuntimeException e) {
        boolean paddingError = false;
        Throwable t = e;
        int guard = 0;
        while (t != null && guard++ < 12) {
            String n = t.getClass().getName();
            if (n.endsWith("BadPaddingException")
                    || n.endsWith("CryptoException")
                    || n.endsWith("CodecException")
                    || n.endsWith("IllegalBlockSizeException")) {
                paddingError = true;
                break;
            }
            t = t.getCause();
        }

        // 前二十次失败把异常链打出来。调试 oracle 时最怕"判反了"却看不出来，
        // 有这几行日志就能立刻知道服务端到底抛的是什么。
        if (DEBUG.getAndIncrement() < 20) {
            System.err.println("[lab] rememberMe 失败 -> " + (paddingError ? "PAD" : "DESER")
                    + "  " + e.getClass().getName() + ": " + e.getMessage());
            Throwable c = e.getCause();
            for (int i = 0; c != null && i < 4; i++) {
                System.err.println("        cause: " + c.getClass().getName()
                        + ": " + c.getMessage());
                c = c.getCause();
            }
        }

        RESULT.set(paddingError ? PAD : DESER);
    }

    private static final java.util.concurrent.atomic.AtomicInteger DEBUG =
            new java.util.concurrent.atomic.AtomicInteger();
}
