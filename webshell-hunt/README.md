# webshell-hunt

一个「已经被入侵」的 PHP 站点，用来练习应急响应里最核心的那一步：**在一台服务器上把后门全找出来。**

站点是 WordPress 结构（裁剪版），有正常访客流量、有管理员登录记录、有攻击者留下的日志。web 根目录下埋了 9 处后门，按难度分四层。

想先搞清楚背景、设计思路和每类线索能覆盖哪些后门，看 `OVERVIEW.md`。本文件只讲怎么跑起来。

## 启动

```bash
./reset.sh
```

首次构建约 1 分钟。跑起来后：

- 站点：http://127.0.0.1:8899/
- 进容器（把它当服务器）：`docker exec -it webshell-hunt bash`

## 怎么练

1. 先别开浏览器乱点，那会污染 access.log。
2. 进容器，`cd /var/www/html`，用 `ls`、`find`、`grep` 自己找一遍。
3. 建议顺序：时间线 → 关键词 → 元数据 → 非 php 文件 → 日志 → www 之外。具体命令在 `answer/ANSWERS.md` 第三节。
4. 找完对答案：`answer/ANSWERS.md`。目标 9 处后门 + 1 处诱饵，诱饵别报。

## 自动化对照

宿主机上跑（通过 docker exec 读容器现场，权限和时间戳都保留）：

```bash
python3 hunt.py --docker webshell-hunt
```

它按 13 条规则过一遍，输出按 HIGH / MED / LOW 分级，每条带文件、行号、证据片段和判定理由。
正常结果：`命中文件 9 / 25，HIGH 9 项`。

把它当成「自查清单 + 复盘工具」，别当答案——规则只负责少漏，定案还是要读代码。

## 重置

```bash
./reset.sh      # 重新构建镜像，所有权限/时间戳回到初始状态
```

练习过程中会新增 `/tmp/.wpc-*.php`、往 access.log 追加记录，重置即可清掉。

## 目录

```
OVERVIEW.md         总览：这是什么、为什么难查、九处后门与线索的对应关系
compose.yml         端口映射 127.0.0.1:8899 → 容器 80
Dockerfile          后门的权限位、属主、mtime 都在这里固定
reset.sh            重建 + 拉起
php/                站点源码（挂进 /var/www/html）
access.log          预置的攻击历史日志
hunt.py             检测脚本（纯标准库）
answer/ANSWERS.md   答案与排查手册
```

## 环境说明

- 镜像 `php:8.1-apache`，开了 `AllowOverride All`（真实被黑站点常见配置）。
- access.log / error.log 改成真实文件（官方镜像是软链到 stdout），这样可以在容器里 grep。
- 容器时区 UTC，日志和文件 mtime 都是 UTC，和你本地时间差 8 小时。
- 所有后门都在本地 127.0.0.1，不对外暴露，仅供练习。
