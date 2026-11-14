---
name: bu-ai-pao-bu
description: 不爱跑步 — 校园跑小程序「爱跑步Run / 爱体育」全自动打卡。当需要完成校园跑里程/次数、批量生成跑步记录、绕过小程序上报加密、或分析 aitiyuplus.cn 后端协议时使用。含 finishRun 双层加密还原、直写记录通路，以及反侦察清单（字段完整性 / 数值自洽 / 轨迹真实度）。
version: 1.1.1
tags: [校园跑, 逆向, 自动化, ruoyi, aes-rsa, 微信小程序, 反侦察]
---

# 不爱跑步 · 校园跑自动打卡

把「每周去操场跑两公里」这件事，压缩成一条 HTTP 请求。

**但一条能被系统收下、又不会被人工核查挑出来的记录，等于「字段齐全 + 数值自洽 + 轨迹像人」。三者任一不达标，前功尽弃。**

## 何时使用

- 需要完成小程序**校园跑**的次数/里程指标
- 需要分析 `www.aitiyuplus.cn/prod-api` 这套 RuoYi-Vue-Plus 后端
- 需要还原微信小程序的 RSA+AES 双层上报协议
- 同类「加密传输但不校验数据真实性」的系统，思路可平移

不适用：有传感器校验、人脸抽检、微信步数交叉验证的竞品（运动世界校园、步道乐跑）。

## 系统识别特征

| 特征 | 值 |
|---|---|
| 小程序 | 「爱跑步Run」，页面标题「爱体育」 |
| AppID | `wxfdec4683ede4b687` |
| API 根 | `https://www.aitiyuplus.cn/prod-api` |
| 框架 | RuoYi-Vue-Plus（`/v3/api-docs` 裸奔） |
| 客户 ID | `db308ad8185aa5ff3b66bf787f7cddbd`（请求头 `clientId`） |
| 学校 | 青岛科技大学（崂山/四方/高密/黄岛四校区） |

## 一、先认清这系统的性质

**加密 ≠ 反作弊。**

它做的是传输保密：保证请求在网络上不被偷看篡改。它没有、也无法验证「这条记录是不是真人跑出来的」。

服务端真正卡住的只有三件事：

1. 请求能不能被解开（RSA 包 AES key）
2. 字段在不在合法区间（里程/配速/时长/打卡次数）
3. 今天是不是已经记过一次

**没有**的：轨迹物理合理性、配速自洽、设备指纹、IP 绑定、传感器数据、微信步数联动、轨迹重复检测、打卡点顺序。

结论：只要构造出「能解开 + 参数合规 + 当天唯一」的请求，服务端照单全收。

**但「服务端照单全收」≠「人也看不出来」。这套系统所有的反作弊能力都集中在自动校验，而人工抽查只看三处：管理端列表、轨迹页、打卡记录页。第九节专门讲这个。**

## 二、加密层怎么破

### 陷阱接口

```
GET /encrypt/getPublicKeyPc?publicKey=<32字符随机串>
```

服务端逻辑（推测）：

```java
byte[] key = Base64.decode(publicKey);        // 32 字符 → 24 字节
return AES192_ECB_encrypt(rsaPublicKeyBase64, key);
```

**密钥是客户端自己传的**，所以等于没加密。关键点：

- `publicKey` 必须传 **32 个字符**，且这 32 字符按 Base64 解码后**正好 24 字节**
- 不是 UTF-8 raw32，不是 MD5/SHA256 派生 —— 只有 `b64decode + AES-192-ECB` 能解出 padding 正确的明文
- 解码后是 216 字符的 RSA-1024 公钥 Base64（X.509 DER）

```python
s = "".join(random.choices(string.ascii_letters+string.digits, k=32))
if len(base64.b64decode(s+"==")) != 24: 重新生成
j = GET("/encrypt/getPublicKeyPc?publicKey=" + quote(s))
d = AES.new(base64.b64decode(s+"=="), AES.MODE_ECB).decrypt(base64.b64decode(j["data"]))
pub = RSA.import_key(base64.b64decode(d[:-d[-1]].decode()))
```

### 请求封装

```python
aes_key = 32 位随机串          # 明文 32 字符 → 32 字节 → AES-**256**（不是 192）
enc_key = base64.b64encode(PKCS1_v1_5.new(pub).encrypt(base64.b64encode(aes_key.encode()))).decode()
ct      = base64.b64encode(AES.new(aes_key.encode(), AES.MODE_ECB).encrypt(pad(body, 16))).decode()

POST /system/runningCycle/finishRun
  header:
    Content-Type: application/json;charset=UTF-8
    Authorization: Bearer <JWT>                      ← 必带
    token: <JWT>                                     ← 必带，与 Authorization 同值
    clientId: db308ad8185aa5ff3b66bf787f7cddbd       ← 必带
    isEncrypt: "true"                                ← 字符串，不是布尔值
    encrypt-key: <enc_key>
  body  : <ct>                                       ← 密文 Base64 文本，不是 JSON
```

**两个 AES 别搞混**：`getPublicKeyPc` 那步的 key 是 24 字节（AES-192），`finishRun` body 的 key 是 32 字节（AES-256）。

拦截器行为实测：无 `encrypt-key` → `403 没有访问权限`；假 key → `HTTP 500`（RSA 解密崩）。**只看头存不存在，然后走解密链**。路径绕过（`//`、`./`、`;jsessionid`、URL 编码）全部失败 —— 它按 `getRequestURI()` 精确匹配。

### body 完整结构（10 个字段，一个都不能少）

```json
{
  "header": {
    "transactionCode": "finishRun",
    "transactionTime": "2026-11-14 20:00:00",
    "userId": "<从 JWT 的 userId 取>",
    "clientId": "db308ad8185aa5ff3b66bf787f7cddbd"
  },
  "body": {
    "runningRecord": {
      "lc": "2.10",
      "sd": "6.10",
      "js": "00:12:48",
      "stepNumber": 280,
      "startTime": "2026-11-14 19:00:00",
      "endTime": "2026-11-14 19:12:48",
      "coordinates": "[{\"points\":[...],\"colorList\":[...],\"arrowLine\":true,\"width\":6}]",
      "punches": [
        {"id":"1909440476098904065","longitude":"120.47813","latitude":"36.11868",
         "name":"南苑运动区打卡点1","showLocationId":0,"active":true}
      ]
    }
  }
}
```

| 字段 | 类型 | 说明 |
|---|---|---|
| `lc` | string 两位小数 | 里程 km，规则 2.00~15.00，**实际取 2.0~2.5** |
| `sd` | string 两位小数 | 配速 分/km，规则 3.00~9.00，**实际取 6.0~7.0** |
| `js` | `HH:MM:SS` | 时长，必须 ≈ `lc × sd × 60`，误差 ≤ 3 秒 |
| `stepNumber` | int | 步数，规则 20~2000，见 9.2 的两种模式 |
| `startTime` / `endTime` | `YYYY-MM-DD HH:MM:SS` | 必须是**今天**；`endTime - startTime = js` |
| `coordinates` | string(JSON) | 轨迹，**注意是字符串不是数组**，见 9.3 |
| `punches` | array | `active:true` 的个数 = 系统的"打卡次数"，规则 3~9 |

### 轨迹 point 单点结构（真机 15 个字段）

```json
{"altitude":61.88,"verticalAccuracy":0,"indoorLocationType":-1,"provider":"gps",
 "latitude":36.12158284505208,"accuracy":3.7900924682617188,
 "horizontalAccuracy":3.7900924682617188,"type":"gcj02","steps":0,
 "speed":0.46,"longitude":120.48232747395834,"direction":187.6,
 "time":1794459206005,"id":0,"color":"#007AFF"}
```

### 命中打卡点：正常情况不需要任何替换

打卡点判定是 **20 米范围**。

**体育场形轨迹本身就已经穿过三个打卡点**（实测三点距跑道 3.8m / 1.7m / 6.3m）—— 所以正常情况下**不需要任何坐标替换**。保留原始采样点更自然；强行替换会在打卡点处留下一个突兀的折角，反而是破绽。

代码里保留了兜底分支：只有最近的采样点离打卡点 **超过 12 米**时才替换成精确坐标。用当前几何参数（`CENTER=(36.117972,120.478233)`、`A=76m`、`B=42m`）时这个分支永远不会触发 —— 它是给换场地预留的保险。

## 三、两条通路

系统里能写跑步记录的路只有两条，**不是替代关系，是分工**。先看这张表，再决定用哪条：

| | 方案 A `finishRun` | 方案 B `POST /business/runningRecord` |
|---|---|---|
| 本质 | 小程序真实上报协议（RSA+AES 双层加密） | 管理端后台接口（明文 JSON） |
| 日期 | **只能当天** | 任意历史日期 |
| 每天次数 | 只有第一条算有效，第二条起 `REPEAT_ENABLE` | 无接口限制，但**同一天只能有一条 ENABLE** |
| 打卡明细 `punch_record` | 自动写入 | **永远为空**（无写接口） |
| `endTimeStr` | 服务端自动填 | **永远为空**（不在 Bo 里） |
| 轨迹 `running_trajectory` | 自动落 | 只要 `coordinates` 传了完整 block 也自动落 |
| `insertType` | 天然 `auto` | **必须手写 `auto`** |
| 管理端留痕 | 与真机无差别 | `insertType`、空打卡明细、空 `endTimeStr` |

**什么时候用谁：**

- **日常打卡 → 一律走方案 A。** 它就是真机协议，字节层面和真人跑完全一致，没有任何可挑之处。
- **只有一种情况走方案 B：学期快结束，缺的次数已经来不及用 A 一天天补。** 用它一次性把历史日期填满，这是它的唯一用途。
- **不要用方案 A 在同一天重复提交凑次数** —— 第二条起全是 `REPEAT_ENABLE`，同一天挂着好几条相近时刻的记录，痕迹极明显。
- **也不要用方案 B 写今天** —— 今天已经被 A 占了，会出现同一天两条 ENABLE。
- **两条绝对不能混在同一天**：一天 = 一条记录，这是唯一的硬规矩。

**方案 B 的固定代价（补不回来）：** 打卡明细与 `endTimeStr` 恒为空，点开记录只有轨迹线，没有三个红色打卡点标记。这是接口层的硬边界，接受它再用。

### 方案 A：`finishRun` 真实协议（推荐日常用）

```bash
python scripts/batch.py --count 1
python scripts/batch.py --count 1 --lc 2.3 --pace 6.4
python scripts/batch.py --count 1 --dry          # 只看不发（不需要 token）
python scripts/batch.py --count 1 --flow ..\cap\flows.mitm   # 直接从抓包取 token
```

- 走完整 RSA+AES 加密，字节层面和真机请求无差别
- **服务端限制「跑步时间只能是当天」**（传昨天会返回 `500 跑步时间只能是当天`）
- 同一天第二次 → `status=REPEAT_ENABLE`，不计入有效次数
- 所以：**每天跑一次，是这套系统设计的正常节奏**
- `--count` 只能是 1（代码里直接拒绝 >1）；脚本提交前会自动查 `ownerList`，今天已有 `ENABLE` 记录就中止，不会发请求
- 提交成功后会回读 `getTrajectory` 自检 block 四字段 / `colorList` / `id` / `dt`，不通过会打 `[verify] 异常`

### 方案 B：直写记录（补历史，慎用）

```bash
python scripts/direct_batch.py --count 8 --dry   # 先看会补哪些日期
python scripts/direct_batch.py --count 8         # 真写（自动按 --target 收口）
python scripts/direct_batch.py --target 30       # 女生目标；默认 35 = 本学期男生达标数
```

`--target` 默认 **35**（2026-2027 第一学期男生；女生传 30）。脚本会先读 `dataAnalysis.validTime`，只补到目标为止；日期从昨天往前挑，`existing_days` 已占用的日期自动跳过。

`POST /business/runningRecord` —— 管理端接口，**明文、无加密、无日期限制**。

**必传字段（缺一个就 500 或写出废数据）：**

| 字段 | 来源 | 不传的后果 |
|---|---|---|
| `openId` | JWT | `500 微信唯一用户标识不能为空` |
| `userId` / `deptId` / `stuNo` | JWT | 归属错误 |
| `semesterId` / `semesterName` | `/system/semester/list` | 静默归到错误学期，次数对不上 |
| `status` | 固定 `"ENABLE"` | 不传则该条不计入有效次数 |
| `insertType` | 固定 `"auto"` | 写 `manual` = 自曝（见下方风险 2） |
| `coordinates` | 轨迹 block | Bo 标为必填；**一次写全，不要留空串** |
| `lc` `sd` `js` `startTime` `endTime` `stepNumber` | 构造 | 同方案 A |

`recordId` 在 schema 里标了 required，但新增接口的校验分组不含它，**不要传**。

**轨迹必须在一次请求里写完**：`coordinates` 直接放 `[block]` 的 JSON 字符串（和方案 A 完全同构），服务端自己落 `running_trajectory`。**不要先写空串再单独 `PUT /business/runningTrajectory` 补** —— 多一次请求、多一次暴露，而且空串期间谁点开都是「无法查询到轨迹信息」。

**风险（两条，第二条更严重）：**

1. `createTime` 全部落在同一时刻 —— 但实测单条查询与管理端列表**都不返回 `createTime`**，这条痕迹 API 层面看不见
2. **`insertType` 必须写 `auto`，绝不要写 `manual`** —— 管理端列表 `/business/runningRecord/list` 的返回字段里**直接带 `insertType`**，正常学生跑步永远是 `auto`，`manual` 是管理员后台补录的标记。写 `manual` 等于在自己那一行插个旗子

### 验证

```bash
python scripts/check.py     # 打印 dataAnalysis + 最近记录
```

## 四、参数速查

### 运动规则（`GET /system/regular/list`，无鉴权）

| 项 | 男生 | 女生 |
|---|---|---|
| 达标次数 | **35.00** | 30.00 |
| 单次里程 | 2.00 ~ 15.00 km | 同 |
| 配速 | 3.00 ~ 9.00 分/km | 同 |
| 时长 | 2.00 ~ 20.00 分钟 | 同 |
| 打卡次数 | 3.00 ~ 9.00 | 同 |
| 打卡范围 | 20.00 米 | 同 |
| 步数 | 20 ~ 2000 | 同 |

> 达标次数**随学期调整**：2026-2027 第一学期是 35 / 30，早期学期出现过 45 / 40。`regular/list` 会把所有学期混在一起返回，务必按 `dataAnalysis.semesterName` 对应的那条读，不要写死。

### 打卡点（`GET /system/punchStore/list?pageSize=200`，无鉴权，共 67 个）

**南苑运动区（田径场）** —— 3 个点，正好卡在"打卡次数 ≥3"的及格线上：

| 名称 | id | 经度 | 纬度 |
|---|---|---|---|
| 打卡点1 | 1909440476098904065 | 120.47813 | 36.11868 |
| 打卡点2 | 1896446770667913217 | 120.4778 | 36.117573 |
| 打卡点3 | 1896446887273758722 | 120.47877 | 36.117664 |

轨迹几何（**体育场形，不是椭圆**）：中心 `36.117972, 120.478233`，南北半轴 `STADIUM_A=76m`、弯道半径 `STADIUM_B=42m`，单条直道 `L=68m`，一圈 `2L+2πB=399.9m`。参数化见 `scripts/batch.py` 的 `stadium_xy(s)`（按累计弧长取点）。

中心由 3 个打卡点反推而来（点1 在北弯道、点2/点3 是南弯道两端），这样生成的三点距跑道仅 3.8m / 1.7m / 6.3m，**天然落在 20m 打卡范围内，不需要任何坐标吸附**。

早期用椭圆（半轴 lat 0.00060 / lng 0.00055）会圈住整个足球场、形状太圆，已废弃。

其他路线：北苑生活区 4 个、北苑教学区 4 个、四方教学区 4 个、四方运动场 3 个、高密 16 个、黄岛 5 个。

### 其他裸奔接口

```
GET /v3/api-docs                          573 个接口全量 OpenAPI（559KB）
GET /system/semester/list                 7 个学期
GET /system/profit/dataAnalysis           有效次数/里程/排名
GET /system/profit/curveGraph             里程曲线
GET /business/runningRecord/ownerList     自己的全部记录
GET /business/runningRecord/getTrajectory/{recordId}
GET /business/runningRecord/list          管理端全量列表（96991 条）
GET /system/punchRecord/list              打卡明细（359 万条）
PUT /business/runningRecord               改记录（26 字段全可写）
PUT /business/runningTrajectory           改轨迹
```

## 五、错误码对照

| 返回 | 含义 | 处理 |
|---|---|---|
| `code:200` | 成功，计入次数 | — |
| `code:601` | 参数不满足规则（里程/配速/打卡数不够） | 记录已入库但无效，检查 lc/sd/js/punches |
| `code:403` | 没带 `encrypt-key` 头 | 补头 |
| `HTTP 500` | `encrypt-key` 是假的，RSA 解不开 | 重新取公钥 |
| `500 跑步时间只能是当天` | `startTime` 不是今天 | 方案 A 只能当天；要补历史走方案 B |
| `微信唯一用户标识不能为空` | 方案 B 缺 `openId` | 从 JWT payload 里取 |
| `AES秘钥长度要求为16位、24位、32位` | `publicKey` 参数长度不对 | 必须 32 字符且解出 24 字节 |

## 六、token 从哪来

抓一次包即可，token 无 `exp` 字段，长期有效：

1. PC 微信打开小程序，任意操作几下
2. mitmproxy 抓包，从请求头取 `Authorization: Bearer <JWT>`
3. JWT payload 里就有 `userId / stuNo / deptId / openId / tenantId`

**脚本不硬编码账号**：四个脚本都会从 JWT 自动解析 `userId / deptId / openId / stuNo`，换人换号只要换 token；也都支持 `--flow <抓包文件>` 直接取 token。

```powershell
$env:AITIYU_TOKEN = "<JWT>"
python scripts/check.py                        # 先确认是谁、现在几次
python scripts/batch.py --count 1 --dry        # 再干跑一次看构造
python scripts/batch.py --count 1              # 真要提交
```

token 查找顺序：环境变量 `AITIYU_TOKEN` → `--token` 参数 → `--flow` 指定的抓包文件 → 脚本同目录的 `token.txt`（一行 JWT 原文）→ 同目录 `flows.mitm`。

推荐用 `token.txt`：粘一次就长期有效，不用每次设环境变量。

### 学期规则要按 semesterId 过滤

`GET /system/regular/list` 返回的是**所有历史学期**混在一起（几十条），直接看会误读 —— 不同学期的「达标次数」不一样，早期是 45/40，**2026-2027 第一学期已调成 35/30**。**必须按 `dataAnalysis.semesterName` 或 `semesterId` 过滤**，`check.py` 已经做了这件事。

换学期、换学年后，先跑一次 `check.py` 看当前实际值，**不要凭印象**。

## 七、运行依赖与前置条件

**不需要打开微信，不需要连着手机。** token 就是全部凭证，脚本直接 HTTPS 打后端。

| 依赖 | 要求 |
|---|---|
| Python | 3.10+（任意环境，虚拟环境更好） |
| 三方库 | `pycryptodome`（`pip install pycryptodome`） |
| 网络 | 能**直连** `www.aitiyuplus.cn`。脚本用 `ProxyHandler({})` 绕开系统代理；**若 Clash 开的是 TUN 模式，直连也会被劫持**，这时要关 TUN 或加进程白名单 |
| token | 环境变量 `AITIYU_TOKEN` → `--token` → `--flow` 抓包文件 → 同目录 `token.txt` / `flows.mitm` |

**token 失效表现**：`401` / `{"code":401,"msg":"认证失败"}` / `{"code":500,"msg":"获取用户信息异常"}`。这时要重新抓一次包（那一步才需要 PC 微信）。

## 八、这套方法的边界

能复用的部分：**「加密传输 ≠ 数据可信」的判断**、**陷阱式密钥接口的识别思路**、**从 swagger 泄露反推全量接口**。

不能复用的部分：如果目标系统加了轨迹物理校验、传感器上报、或微信步数交叉验证，上面所有构造都会失效 —— 那时候要解决的是"证明人真的动了"，不是"把数据包做对"。

---

# 九、反侦察：什么会让一条记录看起来假

这一节是踩坑换来的。前面八节能让请求被服务端接受，这一节决定它能不能被人眼放过去。

## 9.1 传输层：字段缺失比字段错误更致命

服务端对 **类型错误** 的字段会直接报错（你能立刻发现），但对 **缺失字段** 往往静默接受 —— 因为它读 `Map.get(k)` 得到 `null` 就跳过了。**代价在你这边：等管理员点开时才暴露。**

| 缺什么 | 服务端反应 | 人眼反应 |
|---|---|---|
| `coordinates` 里的 `colorList` | **接受，正常入库** | 点开是一片蓝色，画不出线 |
| `coordinates` 里的 `arrowLine` / `width` | 接受 | 同上 |
| `punches` 全部 `active:false` | 601 参数不满足 | 打卡次数 0 |
| `openId`（方案 B） | 500 明确报错 | — |
| `semesterId`（方案 B） | 接受 | 归到错误学期，次数对不上 |

**结论：每次改完构造逻辑，必须用 `getTrajectory` + `ownerList` 回读一遍，把服务端实际存下来的东西和真机记录逐字段对齐。不要只看 `code:200`。**

## 9.2 数值层：自洽性检查清单

一条记录内部有 4 个数值互相约束，任何一个脱节都是破绽：

| 约束 | 公式 | 容差 |
|---|---|---|
| 时长 ↔ 里程 ↔ 配速 | `js_seconds ≈ lc × sd × 60` | ≤ 3 秒 |
| 轨迹长度 ↔ 里程 | 轨迹累计长度 ≥ `lc × 1000 × 0.85` | 直线段累加会偏短，别低于 85% |
| 步数 ↔ 里程 | 见下方两种模式 | — |
| 配速 ↔ 真机样本 | 与历史中位数偏差 ≤ 15% | — |

**推荐取值区间：**

| 参数 | 推荐 | 理由 |
|---|---|---|
| `lc` | **2.00 ~ 2.50 km** | 贴着规则下限 2.00，多跑无益；历史真人在 2.01~2.28 |
| `sd` | **6.00 ~ 7.00 分/km** | 中间偏慢，留出波动空间；规则 3.00~9.00 |
| `js` | 由 `lc × sd` 算出 | 2.1km × 6.5 = 819 秒 = `00:13:39` |
| `punches` | 3 或 4 个 | 规则要 ≥3，全勾 3 个最省事 |
| `stepNumber` | 见下 | |

**`stepNumber` 的两种模式，必须先做选择：**

| 模式 | 取值 | 优点 | 缺点 |
|---|---|---|---|
| `history`（推荐） | `lc × 100 ± 30` ≈ 180~250 | 和真机样本（152~331）同量级，**导出 Excel 横向对比看不出来** | 物理上不合理（2km 走 200 步），但没人会去算 |
| `physical` | `lc × 780 ± 100` ≈ 1500~1900 | 物理上站得住 | 和真机样本差 8~10 倍，后台一排序就跳出来 |

**这里有个系统设计的死结**：规则要求步数 **20~2000**，而人正常走 2km 约 2400 步 —— 也就是说**真实物理值一提交就会撞破上限**。所以任何一次合规提交的步数都不可能物理正确。这反过来证明：`stepNumber` 这个字段在系统里**不是用来做物理校验的**，它只是被落库展示。

**脚本用 `--steps history|physical` 切换，默认 `history`。理由：人工核查只会横向对比同一个人，不会拿计算器算步幅。**

## 9.3 轨迹层：真机结构必须完整

小程序地图组件把 `coordinates` 直接喂给 polyline 渲染。**block 顶层四个字段，缺一个就画不出来：**

```json
[{
  "points":     [ ...N 个采样点... ],
  "colorList":  ["#007AFF", "#007AFF", ... ],   // 长度必须等于 points 长度
  "arrowLine":  true,
  "width":      6
}]
```

**这四项之外，还要对齐真机的随机性特征：**

| 特征 | 真机 | 常见错误写法 | 后果 |
|---|---|---|---|
| `points[i].id` | 0,1,2…N **递增** | 全写 0 | 渲染异常/动画错乱 |
| 相邻 `time` 差 | **4~15 秒不规则**（真机实测 4.2~15.1 秒，毫秒值 4199~15102） | 固定 4000 | 采样分布太完美 |
| `accuracy` vs `horizontalAccuracy` | **两者相等**（同一个小数） | 一个随机一个固定 4.0 | 字段间互相矛盾 |
| `altitude` | **有漂移**（54~62 米随机游走） | 固定 68.9 | 一路恒定，GPS 不可能 |
| `speed` | 0.46~5.25 **真实波动** | 恒等 2.6 | 没有加速减速 |
| 首末点坐标 | **不同**（绕圈回不到原点） | 完全相同 | 完美闭合，一看就是画的 |
| 点数 | **60~120**（2km 约 12~15 分钟，真机 67 点） | 200+ 个 / 每 4 秒一个 | 密度是真人 3 倍，一眼可辨 |

**生成轨迹的正确做法：**

1. 沿**体育场形跑道**按弧长取点：`stadium_xy(s)`，`s = frac * laps * 399.9`，中心 `36.117972, 120.478233`，`A=76m / B=42m`
2. 每个点叠 **高斯噪声**：`lat += gauss(0, 1.2e-6)`、`lng += gauss(0, 1.2e-6)`（约 0.13 米，模拟 GPS 抖动）
3. 半径再乘一个 `1 ± 0.03` 的随机因子（每圈不完全重合）
4. 时间轴用 **4~15 秒随机间隔**（`DT_MIN=4` / `DT_MAX=15`）累加到总时长；2km 自然落到 70~100 个点，与真机 67 点同量级
5. `altitude` 用随机游走：`alt += gauss(0, 0.8)`
6. `accuracy` 单点随机 3.2~6.5，`horizontalAccuracy` 直接等于它
7. 打卡点通常已被轨迹自然穿过（距跑道 3.8/1.7/6.3m），**默认不做任何替换**；仅当最近采样点 >12m 时才兜底替换成精确坐标
8. 补齐 `colorList` / `arrowLine` / `width`

## 9.4 时间层与天数规则

| 规则 | 说明 |
|---|---|
| **只能当天** | `startTime` 不是今天 → `500 跑步时间只能是当天`。只有方案 B 能补历史 |
| **一天一次，这是硬规则** | 同天第二条 → `status=REPEAT_ENABLE`，不计入 `validTime` |
| **一天内如果要多打卡，走补录通道** | **不要用 `finishRun` 重复提交不同参数来凑次数** —— 同一天会出现多条 `startTime` 相同或相近的跑步记录，且第二条开始全被标 `REPEAT_ENABLE`，痕迹明显。要补就一次性走方案 B 直写，且写不同日期 |
| **禁止日期冲突** | 一条记录 = 一天。同一天不能出现两条 ENABLE 的跑步记录。构造前必须先查 `ownerList` 把已有日期列出来，跳过去 |
| 起始时刻 | 落在 **6:00 ~ 22:00** 之间，别出现凌晨 3 点跑步 |
| 秒数 | **不要整分整秒**。真机是 `12:53:23`、`09:50:02`，全 0 秒太假 |

**排期检查脚本（构造前先跑）：**

```python
import json
from batch import get
j = json.loads(get("/business/runningRecord/ownerList?pageNum=1&pageSize=100&orderByColumn=startTime&isAsc=desc"))
used = {}
for r in j.get("rows") or []:
    d = (r.get("startTime") or "")[:10]
    used.setdefault(d, []).append((r.get("status"), r.get("lc")))
for d in sorted(used, reverse=True)[:20]:
    print(d, used[d])
```

**输出里每个日期只该有一条 `ENABLE`。已有 ENABLE 的日期，绝不能再写第二条。**

## 9.5 痕迹层：改完之后能查到什么

| 数据 | API 可见性 | 能不能补 |
|---|---|---|
| `runningRecord` 主表 | 管理端 list 返回 27 字段（含 `insertType`、`stepNumber`、`sd`） | ✅ `PUT /business/runningRecord`，26 字段全可写 |
| `createTime` / `updateTime` | **单条查询与管理端列表都返回 `None`** | 改记录不留 API 可见痕迹 |
| `runningTrajectory` 轨迹 | `getTrajectory` 返回 `coordinates` | ✅ `PUT /business/runningTrajectory` |
| `punchRecord` 打卡明细 | `/system/punchRecord/list?recordId=xxx` 可查 | ❌ **只有 GET / DELETE，没有 POST/PUT，补不了** |

**最后一行是硬边界**：方案 B 直写的记录，打卡明细永远是空数组。这意味着走方案 B 的记录，**"跑步打卡记录"页面点开是空的**，这是补不回来的。

**所以：方案 B 只在真的需要补历史时用，且必须接受这个永久缺陷。日常只走方案 A。**

### 操作日志：比字段痕迹更高一级

数据层的字段都能改（`insertType`、`stepNumber`、`coordinates`），但**每次改动动作本身会另存一份记录**，那份在 `sys_oper_log` 表里，管理员可查（`GET /monitor/operlog/list`，学生 token 一律 403）。

**一、日志的署名是 token 的所有者，不是请求来源。**

`oper_name` 不是从请求参数里读的，是 `@Log` 切面从 token 解出来的登录身份：

```
Authorization: Bearer <JWT> → Sa-Token 解析 loginId → LoginHelper.getLoginUser() → oper_name
```

服务端不关心是谁在发这个 HTTP 请求，它只看到这张 token 属于谁。**用谁的 JWT 调接口，日志就署谁的名。** 想不挂名只有「用管理员账号」和「不调接口」两条路，中间没有第三条。

**二、每一次写操作大概率都会进 `sys_oper_log`。**

`/business/runningRecord` 的增删改是 RuoYi 代码生成器产出的标准 CRUD，**几乎必然带 `@Log(title="跑步记录", businessType=INSERT/UPDATE/DELETE)`**。而 `oper_param` 记录的是**原样请求体** —— 包括当时传的 `"insertType":"manual"`、`"stepNumber":1250` 这些值。

**事后把数据改成 `auto` 不会抹掉当时那条日志。** 「先写错、再改对」在数据层是干净的，在日志层是**两条记录**：一条带着错误值，一条记录着修改动作。

**三、所以每一次写入都必须一次到位。**

不要用「先传个大概、再慢慢调」的方式试探：

| 做法 | 数据层结果 | 日志层结果 |
|---|---|---|
| 一次写对 | 1 条正确记录 | 1 条日志 |
| 写错再改 | 1 条正确记录 | **2 条日志**，其中一条暴露原始错误值 |
| 反复试参数 | 1 条记录 + N 条 REPEAT/DISABLE | **N+1 条日志**，全部署名同一人 |

**同一天反复提交尤其显眼**：`REPEAT_ENABLE`、`DISABLE` 这些状态本身已经留在数据里，再加一串连续的操作日志，等于把「这个人在调参数」写在脸上。

**四、哪些路径会产生日志**

| 路径 | 是否管理端 CRUD | 日志风险 |
|---|---|---|
| `POST /system/runningCycle/finishRun` | 否（业务自定义方法） | 取决于该方法有没有 `@Log`，大概率没有 |
| `POST /business/runningRecord` | **是** | **有** |
| `PUT /business/runningRecord` | **是** | **有** |
| `PUT /business/runningTrajectory` | **是** | **有** |

**结论：除了普通跑步（`finishRun`），其余记录形式一律慎用。** 补录只在「学期快结束、来不及一天天补」时启用，且必须一次写对。

## 9.6 提交后必做的回读验证

```bash
# 1. 看统计有没有 +1
python scripts/check.py

# 2. 看轨迹结构对不对（重点：有没有 colorList）
python -c "
import json,sys
sys.path.insert(0,'scripts')
from batch import *
rid='<刚提交的 recordId>'
r=json.loads(get('/business/runningRecord/getTrajectory/'+rid))
arr=json.loads(r['data']['coordinates'])
print('block keys:',list(arr[0].keys()))
print('points:',len(arr[0]['points']))
print('id 序列:',[p['id'] for p in arr[0]['points'][:5]])
print('dt:',[arr[0]['points'][i+1]['time']-arr[0]['points'][i]['time'] for i in range(4)])
"
```

**只要 `block keys` 里没有 `colorList`，这条记录的轨迹在小程序里就是一片蓝色 —— 立刻用 `PUT /business/runningTrajectory` 重写。**

## 9.7 一句话总结

> 服务端只问你「参数合不合规、今天跑没跑过」，
> 人只问你「这条像不像我平时跑的那样」。
> 前者可以硬碰，后者只能模仿。

模仿的四个字：**齐全、自洽、随机、一致**。
