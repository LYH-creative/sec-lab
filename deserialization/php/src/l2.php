<?php
/**
 * L2 —— POP 链：一个 __destruct 不够，就串三个
 *
 * 目标：把 flag 读出来。
 * 关卡设计：入口仍然是 unserialize()，但没有任何一个类直接读文件。
 * 你需要把 Page / Renderer / Engine 三个对象按调用顺序串成一条链。
 *
 * 调用顺序（自己跟着代码走一遍）：
 *   Page::__destruct  →  调 $renderer->render()  →  Renderer::__call
 *   Renderer::__call  →  echo $this->engine     →  Engine::__toString
 *   Engine::__toString→  file_get_contents($tpl)  ← sink
 */
require __DIR__ . '/inc/classes.php';

$data = $_GET['data'] ?? '';
?><!doctype html>
<meta charset="utf-8">
<title>L2 · POP 链</title>
<style>body{font:14px/1.7 -apple-system,Menlo,monospace;max-width:860px;margin:40px auto;padding:0 20px;color:#222}
pre{background:#f5f5f7;padding:12px;border-radius:6px;overflow:auto;white-space:pre-wrap;word-break:break-all}
code{background:#f0f0f3;padding:1px 5px;border-radius:3px}
.hint{color:#666;border-left:3px solid #ddd;padding-left:12px;margin:18px 0}</style>

<h2>L2 · POP 链（三跳）</h2>
<div class="hint">
  <b>业务逻辑</b>：页面渲染接口，<code>Page</code> 对象反序列化后会在析构时渲染。<br>
  <b>你的目标</b>：不写一行 PHP 代码，只靠一串序列化字符串读出 <code>/flag</code>。<br>
  <b>本题没有哪个类直接读 flag</b> —— 危险的是三个类的<b>组合</b>。
</div>

<form method="get">
  <input name="data" value="<?= htmlspecialchars($data) ?>" style="width:100%;padding:8px;font-family:Menlo,monospace">
  <button style="margin-top:8px;padding:6px 16px">unserialize</button>
</form>

<?php if ($data !== ''): ?>
  <h3>输入</h3>
  <pre><?= htmlspecialchars($data) ?></pre>

  <h3>反序列化结果</h3>
  <pre><?php
    $obj = @unserialize($data);
    if ($obj === false && $data !== 'b:0;') {
        echo 'unserialize() 失败 —— 长度 / 类名 / 属性可见性有一个不对。';
    } else {
        var_dump($obj);
    }
  ?></pre>

  <h3>渲染输出（__destruct 在脚本结束时才跑，往下翻）</h3>
  <pre><?php
    // 手动提前触发析构，让输出位置稳定；真实场景不这么做
    unset($obj);
    gc_collect_cycles();
  ?></pre>
<?php endif; ?>
