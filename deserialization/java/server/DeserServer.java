import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.concurrent.Executors;

/**
 * Java 反序列化靶场服务端。
 *
 * POST /api/import   —— 请求体是裸的 Java 序列化字节流，直接 readObject()
 * GET  /static/xxx   —— 读取 /tmp/out/xxx，给你一个看命令执行结果的地方
 *
 * 这里没有任何 gadget 代码，危险的是 readObject() 本身：
 * 只要 classpath 上有能被串成链的库（本靶场是 commons-collections 3.1），
 * 攻击者构造的对象图就会在 readObject 过程中自动跑完。
 */
public class DeserServer {

    private static final String OUT_DIR = "/tmp/out";

    public static void main(String[] args) throws Exception {
        Files.createDirectories(Paths.get(OUT_DIR));

        int port = Integer.parseInt(System.getProperty("port", "8080"));
        HttpServer server = HttpServer.create(new InetSocketAddress("0.0.0.0", port), 0);

        // ---- 反序列化入口 ----
        server.createContext("/api/import", ex -> {
            byte[] body = readAll(ex.getRequestBody());
            String resp;
            try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(body))) {
                Object obj = ois.readObject();
                resp = "OK  deserialized: " + obj.getClass().getName() + "\n";
            } catch (Throwable t) {
                resp = "ERR " + t.getClass().getName() + ": " + t.getMessage() + "\n";
            }
            send(ex, 200, resp);
        });

        // ---- 命令执行结果落地处 ----
        server.createContext("/static/", ex -> {
            String name = ex.getRequestURI().getPath().substring("/static/".length());
            Path target = Paths.get(OUT_DIR).resolve(name).normalize();
            if (!target.startsWith(OUT_DIR) || !Files.isRegularFile(target)) {
                send(ex, 404, "not found\n");
                return;
            }
            send(ex, 200, new String(Files.readAllBytes(target), StandardCharsets.UTF_8));
        });

        server.createContext("/", ex ->
                send(ex, 200, "Java deserialization lab\n  POST /api/import  (raw serialized bytes)\n  GET  /static/<file>\n"));

        server.setExecutor(Executors.newFixedThreadPool(4));
        server.start();
        System.out.println("listening on " + port);
    }

    private static byte[] readAll(InputStream in) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int n;
        while ((n = in.read(buf)) > 0) {
            bos.write(buf, 0, n);
        }
        return bos.toByteArray();
    }

    private static void send(HttpExchange ex, int code, String text) throws IOException {
        byte[] out = text.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
        ex.sendResponseHeaders(code, out.length);
        ex.getResponseBody().write(out);
        ex.close();
    }
}
