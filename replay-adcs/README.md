# Replay / AD CS · 五关协议级练习靶场

**端口 8910 · 一个容器 · 纯 Python 标准库**

从「抓包报文原样重放」一路打到「中继 DC 的 NTLM 认证 → 向 AD CS 申请域管证书 →
PKINIT 换 TGT → 域管页面」。五关串成一条链，每关一个 flag。

> **这不是 Windows 域。** 本机 Docker 是 `linux/aarch64`，跑不了 Windows 容器，
> 真·AD CS 需要 Windows Server + AD DS + 企业 CA。本靶场是协议级模拟，
> 哪些是真的、哪些是替身，见下面「实现边界」——别把模拟当成复现成功。

---

## 启动

```bash
# 方式一：接进 SecLab（推荐，跟其他九个靶场一起）
cd .. && ./lab.sh up

# 方式二：单独起这一个
./setup.sh                      # 等价于 docker compose up -d --build

# 方式三：不开 Docker，本地直跑（本机 Python 3.9+ 即可，零依赖）
LAB_PORT=8910 python3 server.py
```

验证脚本会自动探测 `8910`（Docker / 本地）和 `8080`，也能用
`--base http://127.0.0.1:8910` 显式指定。

```bash
python3 ntlm.py                 # 协议层自测：MD4 向量 + Type1/2/3 往返验签
python3 poc/exp.py              # 五关全跑 + 修复对照
python3 poc/exp.py --only L4    # 只跑 ESC8 中继
./lab.sh answer replay          # 答案速查
```

服务状态全在内存里，**重启容器即复位**（重放计数、nonce、CA 会话、证书全部清空）。

---

## 关卡索引

| 关 | 入口 | 目标 | flag 文件 |
|---|---|---|---|
| L1 | `GET /bank/sample?level=1` → `POST /bank/l1/transfer` | 一条合法报文重放 5 次，签名不用破 | `flags/l1.flag` |
| L2 | `GET /bank/sample?level=2` → `POST /bank/l2/transfer` | 服务端有 nonce 去重，但签名没覆盖 nonce | `flags/l2.flag` |
| L3 | `POST /ntlm/l3/type1` → `type3` | 用 `LAB\alice / Passw0rd!` 手算 NTLMv2 Type3 | `flags/l3.flag` |
| L4 | `/victim/negotiate` → `/certsrv/certfnsh.asp` → `/victim/authenticate` | 只搬 Type1/2/3 字节，让 CA 认证成 `LAB\DC$` | `flags/l4.flag` |
| L5 | `/certsrv/templates` → 申请证书 → `/kdc/asktgt` → `/admin` | SAN 填域管 UPN，换 TGT 进域管页 | `flags/l5.flag` |

`/safe`、`/safe/check` 是修复对照；`GET /state`、`GET /bank/state` 看当前状态。

L3 的 challenge 用后即删，同一个 Type3 交第二次会被拒 —— challenge 本身就是
一次性 nonce，这一点跟 L1/L2 的缺失形成对照。

---

## 实现边界（重要）

| 部分 | 状态 | 说明 |
|---|---|---|
| MD4 / NT hash | **真** | 手写 RFC 1320，四个标准向量可自测；系统 OpenSSL 3 禁了 md4 |
| NTLM Type1/2/3 报文 | **真** | MS-NLMP 的 security buffer 布局，AV pair、version、flags 齐全 |
| NTLMv2 响应 | **真** | NTOWFv2 + NTProofStr(HMAC-MD5)，challenge 是服务端真随机 |
| 验签 | **真** | 服务端从 Type3 解析身份、按目录里的 NT hash 重算比对 |
| relay 不需要密码 | **真** | `/victim/authenticate` 只吐 Type3 字节，密钥不出服务端 |
| 证书 | 模拟 | JSON + HMAC 代替 CA 私钥签的 X.509，没有 CSR / 模板 ACL 的真实存储 |
| TGT / PAC | 模拟 | JSON + HMAC 代替 krbtgt 签的 PAC，没有 Kerberos 协议 |
| LDAP / RPC / TLS / EPA | 无 | 没有 Windows 域、没有 PetitPotam 的 EFSRPC，也没有通道绑定 |

`/safe/check` 返回 7 项：前 5 项标注 `measured`，是真的调用
`bank_safe_validate()` 跑出来的（包括「重放第二次」真的连打两次）；
后 2 项标注 `explanation`，是 TLS / LDAP 相关的**真机加固清单**，
本靶场没有对应实现，没做实测，不要当成验证过的结论。

---

## 真机对照

| 本靶场 | 真实 AD 环境 |
|---|---|
| `/victim/negotiate` | PetitPotam (MS-EFSR, CVE-2021-36942) / PrinterBug (MS-RPRN) 强制 DC 认证 |
| 转发 Type1/2/3 | `ntlmrelayx.py -t http://ca/certsrv/certfnsh.asp --adcs --template DomainController` |
| `/certsrv/certfnsh.asp` | AD CS Web Enrollment，ESC8（NTLM 可用、未开 EPA） |
| `VulnWebServer` 模板 | ESC1：`msPKI-Certificate-Name-Flag` 带 `ENROLLEE_SUPPLIES_SUBJECT` |
| `/kdc/asktgt` | `Rubeus asktgt /user:dc$ /certificate:x.pfx /ptt`（PKINIT） |
| `/admin` | Pass-the-Ticket 后 DCSync |

加固侧：CA 禁用 NTLM / 开 EPA 通道绑定、全网 SMB & LDAP signing、
模板关 `ENROLLEE_SUPPLIES_SUBJECT` + 开审批 + 收窄 Enroll ACL、
打 KB5014754 切强证书映射（证书带 SID 扩展）。`/kdc/safe/asktgt` 演示最后一条：
同一张没有 SID 扩展的证书会被 403 拒下。

---

## 目录结构

```
replay-adcs/
├── server.py          # 靶场服务：五个关卡 + 修复对照 + HTML 页面
├── ntlm.py            # MD4 / NTLMv2 / Type1·2·3 编解码（可单独跑自测）
├── poc/exp.py         # 零依赖端到端验证脚本
├── flags/l1~l5.flag   # 五个 flag
├── Dockerfile
├── compose.yml        # 独立启动
├── setup.sh
└── README.md
```

---

## 踩坑记录

- **`hashlib.new('md4')` 直接抛错。** macOS 的 Python 3.12 链接 OpenSSL 3，
  MD4 在 legacy provider 里默认不加载。`ntlm.py` 手写了一份，别试着
  `pip install pycryptodome` 绕过去 —— 会破坏「零依赖」这个前提。
- **8080 常被本机别的服务占着。** 所以集成编排和独立 compose 都映射
  `8910:8080`，本地直跑也建议 `LAB_PORT=8910`。
- **子目录 compose 和根编排用了同一个容器名 `replay-adcs`。**
  同时起会报 `container name is already in use`，先 `../lab.sh down`。
- **`do_POST` 只能读一次 body。** 早期版本在 `/certsrv` 里又读了一遍 rfile，
  结果证书请求体是空的；现在 body 由 `do_POST` 统一读、往下传。
- **exp.py 里 `--only L5` 会自动先跑一遍 relay**，因为申请证书需要
  `X-CA-Session`；`--only L4` 则只打印 L4 的 flag。
