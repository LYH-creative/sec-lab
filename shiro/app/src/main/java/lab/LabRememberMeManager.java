package lab;

import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.SubjectContext;
import org.apache.shiro.web.mgt.CookieRememberMeManager;

/**
 * 只做一件事：把 rememberMe 解析失败的异常类型记账，供 oracle 使用。
 *
 * 父类 CookieRememberMeManager 是 Shiro 真实的 rememberMe 实现：
 *   - 登录成功且 token.setRememberMe(true) 时，把 principal 序列化
 *     → AES/CBC/PKCS5 加密 → Base64 → 写进 rememberMe cookie
 *   - 后续请求带着 cookie 来，反向解一次，还原成 PrincipalCollection
 * 加密密钥藏在 AbstractRememberMeManager 里：
 *   - 1.2.4 及以前：硬编码常量 kPH+bIxk5D2deZiIxcaaaA==（CVE-2016-4437）
 *   - 1.2.5 起：构造时随机生成 128 位密钥（这就是 550 的官方修复）
 * 我们一行 key 都不写，直接吃版本默认值，行为才和真实环境一致。
 *
 * 为什么不覆写 onRememberedPrincipalFailure()：
 *   那个方法在 1.2.x 返回 PrincipalCollection，到 1.6/1.7 变成了 void，
 *   同一份源码没法同时 override 六个版本。而 getRememberedPrincipals()
 *   的签名从 1.2 到 1.7 一直没动，所以在这里自己 catch、自己 forgetIdentity。
 *   等价于父类行为，只是多记了一笔账。
 */
public class LabRememberMeManager extends CookieRememberMeManager {

    @Override
    public PrincipalCollection getRememberedPrincipals(SubjectContext subjectContext) {
        try {
            byte[] bytes = getRememberedSerializedIdentity(subjectContext);
            if (bytes == null || bytes.length == 0) {
                return null;
            }
            return convertBytesToPrincipals(bytes, subjectContext);
        } catch (RuntimeException e) {
            // 走到这里说明 cookie 不可用：要么填充错（key 不对/密文被改），
            // 要么填充对但字节不是合法序列化流。721 就靠这个差别。
            LabState.fail(e);
            // 父类原本会在这里清掉 cookie（回一个 rememberMe=deleteMe）
            forgetIdentity(subjectContext);
        }
        return null;
    }
}
