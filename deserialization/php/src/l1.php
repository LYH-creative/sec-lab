<?php
/**
 * L1 —— 一个魔术方法就够了
 *
 * 目标：控制 Cache 的属性，让 __destruct 里的 system() 执行你的命令。
 * 关卡设计：入口只有一个 unchecked unserialize()，类就在 inc/classes.php。
 */
require __DIR__ . '/inc/classes.php';

$data = $_GET['data'] ?? '';
?><!doctype html>
<meta charset="utf-8">
<title>L1 · 魔术方法触发</title>
<style>body{font:14px/1.7 -apple-system,Menlo,monospace;max-width:860px;margin:40px auto;padding:0 20px;color:#222}
pre{background:#f5f5f7;padding:12px;border-radius:6px;overflow:auto;white-space:pre-wrap;word-break:break-all}
code{background:#f0f0f3;padding:1px 5px;border-radius:3px}
.hint{color:#666;border-left:3px solid #ddd;padding-left:12px;margin:18px 0}</style>

<h2>L1 · 魔术方法触发</h2>
<div class="hint">
  <b>业务逻辑</b>：缓存清理接口。传入的序列化字符串会被直接 <code>unserialize()</code>。<br>
  <b>你的目标</b>：让对象销毁时执行一条能读到 <code>/flag</code> 的命令。<br>
  <b>提示</b>：<code>Cache</code> 的 <code>$key</code> 会拼进 shell 命令，而且没有转义。
</div>

<form method="get">
  <input name="data" value="<?= htmlspecialchars($data) ?>" style="width:100%;padding:8px;font-family:Menlo,monospace" placeholder="O:5...">
  <button style="margin-top:8px;padding:6px 16px">unserialize</button>
</form>

<?php if ($data !== ''): ?>
  <h3>输入</h3>
  <pre><?= htmlspecialchars($data) ?></pre>

  <h3>反序列化结果</h3>
  <pre><?php
    $obj = @unserialize($data);
    if ($obj === false && $data !== 'b:0;') {
        echo 'unserialize() 失败 —— 检查格式：长度必须精确等于实际字节数，引号类型必须匹配。';
    } else {
        var_dump($obj);
    }
  ?></pre>

  <h3>命令输出（__destruct 在脚本结束时才跑，输出可能在最下方）</h3>
  <pre><?php /* 对象在脚本结束销毁，输出被 PHP 输出缓冲捕获后追加 */ ?></pre>
<?php endif; ?>
