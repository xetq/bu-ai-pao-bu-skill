# 不爱跑步-SKILL

> 把「每天去操场跑两公里」压缩成一条 HTTP 请求。
> 面向**青岛科技大学（崂山校区）**在校生，需要你自己的学号账号。

---

你可以对你的Agent说:"安装https://github.com/xetq/bu-ai-pao-bu-skill这个skill,并协助我配置前置要素,然后帮我打卡一天"


也可以继续查看README




---

## 先说清楚这是什么

这套东西**不修改小程序、不模拟定位、不用 root、不用装模块**。

它的原理是：把你手机上一次真实跑步时**本该发出去的请求**，用同样的加密方式在电脑上重建一遍，然后直接发给学校后端。后端看不出区别——因为协议、字段、加密都是真的，只是轨迹是算出来的。

代价是：你需要的不是技术，而是**一次抓包**。

---

## 你需要准备什么

| 项 | 说明 |
|---|---|
| 你的 token | 一次性抓包拿到，长期有效（JWT 没有 `exp` 字段） |
| Python 3.10+ | 建议建个虚拟环境 |
| `pycryptodome` | `pip install pycryptodome` |
| 能直连 `www.aitiyuplus.cn` | 挂梯子会失败，详见下文「网络」 |

**不需要**：手机连着电脑、微信开着、管理员权限。

---

## 第一步：拿你自己的 token

token 是这套东西唯一的凭证，它决定了「你是谁」。**每个人必须用自己的。**

### 方法 A：PC 微信 + mitmproxy（推荐）

1. 电脑装 mitmproxy：`pip install mitmproxy`
2. 装它的 CA 证书（只需一次）：
   ```powershell
   certutil -addstore -user -f Root "$env:USERPROFILE\.mitmproxy\mitmproxy-ca-cert.cer"
   ```
3. 起抓包，把所有流量转发到你现有的代理（如果你有梯子的话，没有就省掉 `--mode`）：
   ```powershell
   mitmdump -p 8888 --mode upstream:http://127.0.0.1:7897 -w flows.mitm
   ```
4. 系统代理改成 `127.0.0.1:8888`
5. PC 微信里打开「爱跑步 Run」小程序，进跑步页晃几下
6. 抓完按 `Ctrl+C`，系统代理改回去

### 从抓包文件里取 token

打开 `flows.mitm`，找任意一条发往 `www.aitiyuplus.cn` 的请求，请求头里有两行：

```
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJsb2dpblR5cGUi...
token: eyJhbGciOiJIUzI1NiJ9.eyJsb2dpblR5cGUi...
```

**两个值一样，`Bearer ` 后面那一长串就是 token。**

把它存成脚本同目录的 `token.txt`（一行，不要带引号和换行）。

不想落盘也行：四个脚本都支持 `--flow <抓包文件>`，直接从 `flows.mitm` 里提 `Authorization: Bearer`，优先级高于 `token.txt`。

### 怎么确认 token 是你的

token 是一段 Base64，中间那截解开就是明文 JSON：

```python
import base64, json
tok = open("token.txt").read().strip()
p = tok.split(".")[1]
p += "=" * (-len(p) % 4)
print(json.dumps(json.loads(base64.urlsafe_b64decode(p)), ensure_ascii=False, indent=2))
```

会看到 `stuNo`（学号）、`nickName`（姓名）、`userId`、`deptId`、`openId`。

**如果不是你，说明抓的是别人的包，换一个。**

### 方法 B：手机抓包

Android 7 以上系统证书不被 App 信任，需要 root 或装进系统证书区，比较折腾。**建议用方法 A。**

---

## 第二步：先看，不动手

```powershell
python scripts\check.py
```

它会告诉你：

- token 属于谁（姓名、学号）
- 本学期有效次数 / 总里程 / 排名
- 本学期的规则（达标次数、里程区间、配速区间、打卡次数）
- 已有的记录日期

**这一步只读，不写任何东西。**

---

## 第三步：干跑，看它要发什么

```powershell
python scripts\batch.py --count 1 --dry
```

输出类似：

```
[1/1] lc=2.24 pace=6.61 @ 2026-11-14 10:18:25
  [dry] lc=2.24 sd=6.61 js=00:14:48 step=215 pts=97 punches=3
        2026-11-14 10:18:25 ~ 2026-11-14 10:33:13
        dt 取值 = [4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
        altitude 54.8~62.2 | accuracy==hAcc? True
```

自己核对几件事：

- `js` 是不是 ≈ `lc × sd × 60`（上面 2.24 × 6.61 × 60 = 888 秒，`00:14:48` = 888 秒 ✓）
- `startTime + js` 是不是等于结束时间
- `pts` 是不是 70~120 之间（真机 2km 大约 67 个点，太多说明采样过密）
- `punches` 是不是 3

**`--dry` 只构造、不提交。** 有 token 时会先做一次只读 `ownerList` 排期检查（今天已有 `ENABLE` 就打印警告）；没有 token 就完全本地运行，不联网。

---

## 第四步：提交

```powershell
python scripts\batch.py --count 1
```

脚本会自己拦两种情况，不会让你打重复卡：

- 今天已有 `status=ENABLE` 的记录 → 直接中止，一个请求都不发
- `--count` 大于 1 → 直接拒绝（`finishRun` 一天只算第一条）

提交成功后自动回读 `getTrajectory`，打印 `[verify] OK | 点数=… 间隔=… 秒`；出现 `[verify] 异常` 就说明轨迹结构有问题，需要排查。

token 也可以直接从抓包文件取，不必先粘到 `token.txt`：

```powershell
python scripts\batch.py --count 1 --flow ..\cap\flows.mitm
```

---

## 两条通路，别用错

| | 方案 A `finishRun` | 方案 B 直写记录 |
|---|---|---|
| 脚本 | `batch.py` | `direct_batch.py` |
| 日期 | **只能今天** | 任意历史日期 |
| 打卡明细 | 自动写入 | **永远为空** |
| 适合 | 日常打卡 | 学期末补历史 |
| 风险 | 低（和真机无差别） | 中（管理端能看到 `insertType`） |

**日常一律用 A。** 只有学期快结束、来不及一天天跑，才用 B 一次性补。

**两条绝对不能落在同一天。** 同一天有两条记录 → 第二条标 `REPEAT_ENABLE`，不计入有效次数，而且两条并排躺在后台列表里。

---

## 三条铁律

### 1. 一天只打一次

系统的规则是「一天内有效记录只算第一条」。同天提交第二次不会报错，但会在数据库里留一条 `REPEAT_ENABLE`。

**想一天多次，走补录通道（方案 B），不要重复提交跑步参数。**

### 2. 禁止日期冲突

写之前先查：

```powershell
python scripts\check.py
```

它会列出你已经有记录的日期。**已有 `ENABLE` 记录的日期，绝不能再写一次。**

`direct_batch.py` 内置了这个检查，会跳过已有日期。但你自己手动指定日期时要留神。

### 3. 每次写操作都会留日志

后端是 RuoYi-Vue-Plus，管理端的增删改接口基本都带 `@Log` 注解，会在 `sys_oper_log` 表里记一条：**谁、什么时间、调了哪个接口、请求体是什么**。

- 日志的署名是 **token 的所有者**，不是你从哪台机器发的
- `oper_param` 存的是**原样请求体**，事后改数据抹不掉当时那条
- 改错的代价是「日志多一条」，不是「数据改了就行」

所以：**一次写对，不要反复试参数。**

---

## 网络

脚本用 `urllib` + `ProxyHandler({})` 强制直连，绕开系统代理。

但如果你开了 **Clash 的 TUN 模式**，直连也会被劫持到境外节点，腾讯会拒绝，表现为：

```
Server TLS handshake failed / connection closed
```

**解决办法**：关掉 TUN，或者在 Clash 里给 `python.exe` 加直连规则。

---

## 出问题看这里

| 现象 | 原因 |
|---|---|
| `401` / `{"code":401,"msg":"认证失败"}` | token 过期或抓错了，重新抓一次 |
| `{"code":500,"msg":"跑步时间只能是当天"}` | 方案 A 传了非今天的日期，改用方案 B |
| `{"code":601,...,"本次运动无效"}` | 参数不满足规则（里程 <2km、配速越界、打卡次数 <3 等） |
| `{"code":403,"msg":"没有访问权限"}` | 缺 `clientId` 头，或这个接口你的角色调不了 |
| `{"code":500,"msg":"Required request parameter ... is not present"}` | 少了必填参数 |
| 提交成功但次数没变 | 看 `check.py` 里那天是不是已经有记录 |

完整的错误码对照见 `SKILL.md` 第五节。

---

## 这份文档给谁看

- **给人看** → 你现在读的这个 `README.md`
- **给 AI 看** → `SKILL.md`，里面是完整的协议还原、字段结构、反侦察清单

如果你想让它自动跑，把 `SKILL.md` 丢给任意支持 skill 的 AI 工具，说「按这个帮我打一次卡」。

---

## 最后

这套东西依赖的是**学校后端没有做服务端校验**——它只检查「数值是否在规则区间内」，不检查「这个数值是不是手机算出来的」。

如果哪天学校换了系统、加了签名、或者上了传感器校验，这套东西就失效了。到时候 `check.py` 会第一个告诉你。


**这是学习产物,仅供学习**
**当体育变为数值与判定,那么必然催生没有硝烟的博弈。**
