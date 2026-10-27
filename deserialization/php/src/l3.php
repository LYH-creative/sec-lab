<?php
/**
 * L3 —— private 属性 + 自证清白的校验
 *
 * 开发者做了两层"防护"：
 *   - $cmd 是 private，外部改不了
 *   - __wakeup 校验 token，来源不可信就把命令重置掉
 *
 * 两层都是纸糊的：
 *   1. 序列化串里的属性名不是标识符，而是字节串 —— private 属性就是
 *      "\0Gate\0cmd"（NUL + 类名 + NUL + 属性名），照写就行
 *   2. token 的期望值是源码里的常量，读一眼就知道
 *
 * 顺便：网上流传的"属性数写大绕过 __wakeup"（CVE-2016-7124）
 * 在现代 PHP 上已经失效，实测结果见页面底部。
 */
require __DIR__ . '/inc/classes.php';

$data = $_GET['data'] ?? '';
?><!doctype html>
<meta charset="utf-8">
<title>L3 · private 属性与假校验</title>
<style>body{font:14px/1.7 -apple-system,Menlo,monospace;max-width:880px;margin:40px auto;padding:0 20px;color:#222}
pre{background:#f5f5f7;padding:12px;border-radius:6px;overflow:auto;white-space:pre-wrap;word-break:break-all}
code{background:#f0f0f3;padding:1px 5px;border-radius:3px}
.hint{color:#666;border-left:3px solid #ddd;padding-left:12px;margin:18px 0}
.warn{background:#fff4e5;border-left:3px solid #f0a020;padding:10px 14px;margin:14px 0}</style>

<h2>L3 · private 属性 + 自证清白的校验</h2>
<div class="hint">
  <b>业务逻辑</b>：内网命令下发器。<code>$cmd</code> 是 private，<code>__wakeup()</code> 会校验来源。<br>
  <b>你的目标</b>：让 <code>system()</code> 执行 <code>cat /flag</code>，而不是 <code>echo blocked</code>。<br>
  <b>难点</b>：属性名要在序列化串里写成字节串，长度必须按字节算。
</div>

<div class="warn">
  <b>输入方式</b>：输入框里敲的 <code>\0</code> 是<b>反斜杠 + 0 两个字符</b>，不是 NUL 字节，直接提交必然
  <code>unserialize()</code> 失败。真正的 <code>0x00</code> 要么在 URL 里写 <code>%00</code>，要么交给
  <code>serialize()</code> 生成（<code>php/poc/gen_l3.php</code>）。<br>
  注意页面回显会把真 NUL 显示成 <code>\0</code>，所以「看起来一样」的两种输入，字节层面完全不同。
</div>

<form method="get">
  <input name="data" value="<?= htmlspecialchars($data) ?>" style="width:100%;padding:8px;font-family:Menlo,monospace">
  <button style="margin-top:8px;padding:6px 16px">unserialize</button>
</form>

<?php if ($data !== ''): ?>
  <h3>输入（NUL 字节显示为 \0）</h3>
  <pre><?= htmlspecialchars(str_replace("\0", '\\0', $data)) ?></pre>

  <h3>反序列化结果</h3>
  <pre><?php
    $obj = @unserialize($data);
    if ($obj === false && $data !== 'b:0;') {
        echo 'unserialize() 失败';
    } else {
        var_dump($obj);
    }
  ?></pre>
<?php endif; ?>

<div class="warn">
  <b>实测备忘（PHP 8.1.34）</b><br>
  · 属性数写大（<code>O:4:"Gate":99:{...}</code>）→ <code>unserialize()</code> 直接返回 false，对象不创建，魔术方法全不触发<br>
  · 属性数写小（<code>O:4:"Gate":1:{...}</code>，实际给了 2 个）→ __wakeup 照常执行，重置生效<br>
  · <code>C:</code> 格式 → 类没实现 Serializable，还原出的对象属性全丢<br>
  · 让 __wakeup 内部抛异常 → 对象被 PHP 丢弃，<b>__destruct 不会执行</b><br>
  所以别背老 payload，现代 PHP 上这几条都不好使。
</div>
