<?php
require __DIR__ . '/inc/classes.php';
?><!doctype html>
<meta charset="utf-8">
<title>PHP 反序列化靶场</title>
<style>
body{font:14px/1.8 -apple-system,Menlo,monospace;max-width:820px;margin:48px auto;padding:0 24px;color:#222;background:#fff}
h1{font-size:22px;margin-bottom:4px}
.sub{color:#888;margin-bottom:28px}
a.card{display:block;padding:16px 18px;margin:12px 0;border:1px solid #e3e3e8;border-radius:8px;text-decoration:none;color:#222;transition:.15s}
a.card:hover{border-color:#6b8afd;background:#f8f9ff}
a.card b{color:#2b4bdd}
a.card span{display:block;color:#777;font-size:13px;margin-top:3px}
code{background:#f0f0f3;padding:1px 5px;border-radius:3px}
</style>

<h1>PHP 反序列化靶场</h1>
<div class="sub">PHP <?= PHP_VERSION ?> · 由浅入深 4 关 · flag 在容器 <code>/flag</code></div>

<a class="card" href="l1.php">
  <b>L1 · 魔术方法触发</b>
  <span>unserialize() → 属性可控 → __destruct 里的 system()</span>
</a>
<a class="card" href="l2.php">
  <b>L2 · POP 链</b>
  <span>没有任何一个类直接读文件，但三个类串起来就能读</span>
</a>
<a class="card" href="l3.php">
  <b>L3 · 绕过 __wakeup</b>
  <span>开发者加了"安全重置"，但序列化格式本身有缝</span>
</a>
<a class="card" href="l4.php">
  <b>L4 · phar 反序列化</b>
  <span>全站没有 unserialize()，靠 phar:// 流触发</span>
</a>

<p style="margin-top:32px;color:#999;font-size:12px">
练习方式：先读 <code>inc/classes.php</code> 和对应页面的源码，自己手算序列化串，再对照 <code>poc/</code> 里的脚本。
</p>
