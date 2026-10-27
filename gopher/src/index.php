<?php
require __DIR__ . '/common.php';

$levels = levels();
$cards = '';
foreach ($levels as $k => $v) {
    $cards .= sprintf(
        '<a class="card" href="%s.php"><h3>%s<span class="tag">%s</span></h3><p>%s</p></a>',
        $k, h($v['name']), h($v['tag']), h($v['desc'])
    );
}

$topo = <<<'TXT'
        宿主机浏览器
             │  8896
      ┌──────▼───────┐
      │   web (PHP)  │  ← 六关的 SSRF 入口都在这台
      └──┬───┬───┬───┘
         │   │   │
    ┌────▼┐ ┌▼───┐ ┌▼────┐
    │redis│ │ db │ │ fpm │      L3/L4   L5   L6
    │6379 │ │3306│ │9000 │
    └─────┘ └────┘ └─────┘
         │
    ┌────▼─────────────┐
    │ legacy-internal  │  gopher:70 + http:8081   L2
    └──────────────────┘
    ┌──────────────────┐
    │ legacy-public    │  gopher:70（宿主机 7070） L1
    └──────────────────┘
TXT;

$body = '<h1>Gopher 靶场</h1>'
      . '<p class="sub">六关，从「协议本体」一路打到「用 gopher 完成 RCE」。'
      . '每关只需要交出 flag{...}。</p>'
      . '<pre class="cmd">' . h($topo) . '</pre>'
      . '<h2>关卡</h2>' . $cards
      . '<h2>约定</h2>'
      . '<ul class="hint">'
      . '<li>所有 flag 形如 <code>flag{...}</code>，读到即通关，没有提交框。</li>'
      . '<li>L1 用宿主机 <code>curl</code> 直接打 <code>127.0.0.1:7070</code>；L2 起全部走页面里的 SSRF。</li>'
      . '<li>内网服务（redis / db / fpm / legacy-internal）都不映射端口，宿主机连不到 —— 必须借 web 这台机器的手。</li>'
      . '<li><code>poc/</code> 下有参考脚本，先自己调通再看。</li>'
      . '</ul>';

page('index', 'Gopher 靶场', $body);
