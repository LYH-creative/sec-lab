<?php
/**
 * 业务代码里"正常"的类 —— L1 / L2 共用
 *
 * 注意：这些类本身没有任何漏洞代码，它们只是"恰好"在魔术方法里
 * 调用了危险函数。反序列化的威力就在于：攻击者不需要执行任何代码，
 * 只要对象属性在 unserialize() 之后变成他想要的值，魔术方法就会
 * 替他跑完剩下的路。
 */

/* ============ L1：单一魔术方法 ============ */

/**
 * 缓存清理器。
 * __destruct：对象被销毁时执行，典型场景是"脚本结束顺手清临时文件"。
 */
class Cache
{
    public $key = 'default';
    public $ttl = 3600;

    public function __destruct()
    {
        // 拼接进 shell，且没有转义 —— 这就是 sink
        if ($this->ttl > 0) {
            system('rm -rf /tmp/cache/' . $this->key . ' 2>/dev/null');
        }
    }
}

/* ============ L2：POP 链（三跳） ============ */

/**
 * 第一跳：页面对象，脚本结束时输出"渲染结果"。
 * __destruct 里调用了 $this->renderer->render()，
 * 而 Renderer 并没有 render() 方法 → 触发 Renderer::__call()
 */
class Page
{
    public $title = 'home';
    public $renderer = null;

    public function __destruct()
    {
        if ($this->renderer instanceof Renderer) {
            echo '<!-- render: ' . $this->renderer->render() . " -->\n";
        }
    }
}

/**
 * 第二跳：渲染器。__call 是"调用不存在的方法"时的兜底，
 * 这里把 engine 当字符串用 → 触发 Engine::__toString()
 */
class Renderer
{
    public $engine = null;

    public function __call($name, $args)
    {
        echo $this->engine;
        return '';
    }
}

/**
 * 第三跳：模板引擎。__toString 在对象被当字符串使用（echo / 拼接）时触发，
 * 这里把 tpl 当路径读文件 —— sink
 */
class Engine
{
    public $tpl = '/etc/hostname';
    public $vars = [];

    public function __toString()
    {
        return (string) @file_get_contents($this->tpl);
    }
}

/* ============ L3：private 属性 + 假校验 ============ */

/**
 * 门禁对象。
 *
 * 开发者做了两件"看起来安全"的事：
 *   1. 把 $cmd 声明成 private —— 以为外部动不了
 *   2. 加 __wakeup 校验 token —— 以为来源不可信就重置命令
 *
 * 但序列化串里 private 属性名是可以精确写出来的（\0Gate\0cmd），
 * 而 token 的期望值就明明白白写在源码里。
 */
class Gate
{
    const TRUST = 'internal-node-v1';   // 内网节点令牌

    private $cmd = 'id';
    public $token = '';

    public function __wakeup()
    {
        // 只信任持有内网令牌的节点
        if ($this->token !== self::TRUST) {
            $this->cmd = 'echo blocked';
        }
    }

    public function __destruct()
    {
        system($this->cmd);
    }
}

/* ============ L4：phar 元数据里藏的对象 ============ */

/**
 * 缩略图生成器。__destruct 里做"清理临时文件"的动作。
 * L4 里根本没有 unserialize()，靠 phar:// 流在解析元数据时触发。
 */
class Thumb
{
    public $src = '';   // 源图路径
    public $dst = '';   // 缩略图输出路径

    public function __destruct()
    {
        // 收尾：把源文件复制一份当缩略图
        if ($this->src !== '' && $this->dst !== '') {
            @copy($this->src, $this->dst);
        }
    }
}
