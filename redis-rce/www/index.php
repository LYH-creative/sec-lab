<?php
// 靶场首页。只负责告诉你「这里有个 web，uploads 目录可写」，
// 不提供任何正常功能 —— 正常业务是障眼法，真正的入口在 6379。
?>
<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <title>TaskQueue · 内部任务队列控制台</title>
  <style>
    body { font-family: -apple-system, "Helvetica Neue", Arial, sans-serif;
           background: #f5f6f8; color: #222; margin: 0; padding: 48px 20px; }
    .wrap { max-width: 720px; margin: 0 auto; }
    h1 { font-size: 22px; margin: 0 0 6px; }
    .sub { color: #777; font-size: 13px; margin-bottom: 28px; }
    .card { background: #fff; border: 1px solid #e3e6ea; border-radius: 8px;
            padding: 18px 22px; margin-bottom: 16px; }
    code { background: #f0f2f5; padding: 1px 5px; border-radius: 3px; font-size: 13px; }
    li { margin: 6px 0; font-size: 14px; line-height: 1.7; }
    .tag { display: inline-block; font-size: 11px; padding: 2px 7px; border-radius: 10px;
           background: #eef3ff; color: #3355cc; margin-right: 6px; }
  </style>
</head>
<body>
<div class="wrap">
  <h1>TaskQueue 内部任务队列控制台</h1>
  <div class="sub">v0.3.1 · 队列后端 Redis · 上传目录 <code>/uploads/</code></div>

  <div class="card">
    <div><span class="tag">L1</span>未授权访问</div>
    <li>6379 端口没有任何认证。先 <code>INFO</code>，再看看库里有什么。</li>
  </div>

  <div class="card">
    <div><span class="tag">L2</span>写 webshell</div>
    <li>redis 有 <code>SAVE</code>，web 有可写目录，两件事凑一起就是任意文件写。</li>
  </div>

  <div class="card">
    <div><span class="tag">L3</span>计划任务反弹 shell</div>
    <li>写进 web 目录只是拿到 www-data；写进 cron 目录，才是容器里的 root。</li>
  </div>

  <div class="card">
    <div>提示</div>
    <li>所有关卡脚本都在靶场目录的 <code>poc/</code> 下，卡住了再去对答案。</li>
    <li>flag 形如 <code>flag{...}</code>，三关各一个。</li>
  </div>
</div>
</body>
</html>
