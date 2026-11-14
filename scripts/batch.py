# -*- coding: utf-8 -*-
"""
校园跑批量上报（本地测试/自有账号）

- 复用 /encrypt/getPublicKeyPc 取 RSA1024 公钥
  （陷阱：publicKey 参数是 32 字符，服务端 Base64 解码成 24 字节作 AES-192-ECB key）
- finishRun body: AES-256-ECB-Pkcs7(JSON)，key = 32 字节（明文 32 字符）
  header encrypt-key: RSA_PKCS1v15(base64(32字符AESkey))
  注意 AES-192 只出现在 getPublicKeyPc 那步（24 字节 key），别和这里混

轨迹部分按真机特征生成：block 四字段齐全、id 递增、时间间隔 1~8 秒不规则、
altitude 随机游走、accuracy == horizontalAccuracy、坐标叠高斯噪声。

用法:
  python batch.py --count 1                  # 提交一次（今天）
  python batch.py --count 1 --dry            # 只打印不提交（无 token 也能跑）
  python batch.py --count 1 --lc 2.3 --pace 6.4
  python batch.py --count 1 --steps physical # 步数用物理合理值
  python batch.py --count 1 --flow ..\\cap\\flows.mitm   # 直接从抓包文件取 token

硬规则（代码内置，不再依赖人工记忆）:
  - --count 只能为 1：finishRun 只接受当天，一天只算第一条，count>1 必然产出 REPEAT_ENABLE
  - 提交前自动查 ownerList：今天已有 ENABLE 记录则直接中止
  - 提交后自动回读 getTrajectory，核对 block 四字段 / colorList / id / dt（SKILL 9.6）
"""
import argparse, base64, datetime, json, math, os, random, re, ssl, string, sys, time
import urllib.error, urllib.parse, urllib.request

from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad

BASE = "https://www.aitiyuplus.cn/prod-api"
CID = "db308ad8185aa5ff3b66bf787f7cddbd"
# 账号身份一律从 JWT 解析（见 jwt_claims），这里不保留任何默认值：
# 拿不到 token 或 JWT 里缺字段就直接抛错，避免"用了别人的号还以为是自己"的情况。
USER_ID = ""
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/120.0.0.0 Safari/537.36 MicroMessenger/7.0.20.1781(0x6700143B) "
      "MiniProgramEnv/Windows WindowsWechat/WMPF WindowsWechat(0x63090a13) "
      "UnifiedPCWindowsWechat(0xf254200d) XWEB/26073")

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE

# 南苑运动区（田径场）三个打卡点 —— 正好满足「打卡次数 3~9」
PUNCH_RING = [
    {"id": "1909440476098904065", "longitude": "120.47813", "latitude": "36.11868", "name": "南苑运动区打卡点1"},
    {"id": "1896446770667913217", "longitude": "120.4778", "latitude": "36.117573", "name": "南苑运动区打卡点2"},
    {"id": "1896446887273758722", "longitude": "120.47877", "latitude": "36.117664", "name": "南苑运动区打卡点3"},
]
CENTER = (36.117972, 120.478233)   # 田径场几何中心（由 3 个打卡点反推：北端=点1，南弯道两端=点2/点3）
# ---- 标准 400m 跑道几何（体育场形：两条直道 + 两个半圆弯道，不是椭圆）----
# 纬度 36.118 处：1 度纬度 = 111320m，1 度经度 = 89925m
# a = 南北半轴(含弯道) 76m，b = 弯道半径 42m → 单条直道 L = 68m
# 周长 = 2L + 2πb = 136 + 263.9 = 399.9m ≈ 400m
# 选 76/42 而非标准内圈 78.7/36.5，是为了能罩住外道上的 3 个打卡点（点2/3 东西偏移 43.6m）
STADIUM_A = 76.0
STADIUM_B = 42.0
M_PER_DEG_LAT = 111320.0
M_PER_DEG_LNG = 89925.0
# ---- 采样间隔（秒）----
# 真机 11-12 实测 dt（毫秒）= 15102, 7014, 10030, 4199, 7790, 6953 → 4.2~15.1 秒，
# 67 个点覆盖 12 分钟，平均 11 秒/点。采样过密（如 1~8 秒）会生成 200+ 点，
# 是真人密度的 3 倍，属于一看就假的特征。
DT_MIN = 4
DT_MAX = 15


def stadium_xy(s):
    """按累计弧长 s(m) 求跑道上的 (dx_east, dy_north)，单位米，原点为场地中心。
    起点在东南角直道起点，逆时针（与田径场跑步方向一致）。"""
    a, b = STADIUM_A, STADIUM_B
    L = 2.0 * (a - b)                 # 单条直道长 68m
    P = 2.0 * L + 2.0 * math.pi * b   # 一圈 399.9m
    s = s % P
    if s < L:                         # 东直道：由南向北
        return (b, -L / 2.0 + s)
    s -= L
    if s < math.pi * b:               # 北弯道：由东向西
        th = s / b
        return (b * math.cos(th), L / 2.0 + b * math.sin(th))
    s -= math.pi * b
    if s < L:                         # 西直道：由北向南
        return (-b, L / 2.0 - s)
    s -= L
    th = s / b                        # 南弯道：由西向东
    return (-b * math.cos(th), -L / 2.0 - b * math.sin(th))


def stadium_perimeter():
    return 2.0 * 2.0 * (STADIUM_A - STADIUM_B) + 2.0 * math.pi * STADIUM_B


def sample_offsets(dur, rnd=random):
    """把总时长切成每段 4~15 秒的随机采样间隔，末点严格落在 dur 上。

    旧实现 `min(last + randint(4,15), dur)` 会在收尾时截出 1~3 秒的尾巴
    （300 次压测里 92 次命中，30.7%），与真机实测 4.2~15.1 秒不符 —— 那正是
    「补点」的典型特征。这里改成先定段数，再等分 + 抖动 + 夹逼收敛。
    """
    dur = max(1, int(dur))
    n = max(1, int(round(dur / 9.5)))
    while n > 1 and n * DT_MIN > dur:
        n -= 1
    while n * DT_MAX < dur:
        n += 1
    if n * DT_MIN > dur:          # 总时长本身不足一个采样下限
        return [0, dur]

    segs = [dur / float(n)] * n
    segs = [s * rnd.uniform(0.6, 1.4) for s in segs]
    scale = dur / sum(segs)
    segs = [s * scale for s in segs]
    for _ in range(400):
        segs = [min(float(DT_MAX), max(float(DT_MIN), s)) for s in segs]
        diff = dur - sum(segs)
        if abs(diff) < 1e-9:
            break
        idx = [i for i, s in enumerate(segs) if (s < DT_MAX if diff > 0 else s > DT_MIN)]
        if not idx:
            break
        share = diff / len(idx)
        for i in idx:
            segs[i] = min(float(DT_MAX), max(float(DT_MIN), segs[i] + share))

    ints = [int(round(s)) for s in segs]
    residual = dur - sum(ints)
    order = list(range(n))
    guard = 0
    while residual and guard < 10000:
        rnd.shuffle(order)
        for i in order:
            if residual > 0 and ints[i] < DT_MAX:
                ints[i] += 1
                residual -= 1
            elif residual < 0 and ints[i] > DT_MIN:
                ints[i] -= 1
                residual += 1
            if not residual:
                break
        guard += 1
    if residual:                  # 理论不可达（2.0~2.5km 全落在可行区间内）
        return [0, dur]

    offs = [0]
    for s in ints:
        offs.append(offs[-1] + s)
    return offs

# 真机对照常量（用于让构造数据贴近真实分布）
REAL_STEPS_PER_KM_HISTORY = 100     # 真机样本: 2.0km → 约 150~330 步（计步器几乎没工作）
REAL_STEPS_PER_KM_PHYSICAL = 780    # 物理合理但受规则上限 2000 约束: 2.0km → 约 1560 步
                                    # 注意 2.0km 真实步行约 2400 步，会撞破规则上限 2000 导致 601 无效
ALT_BASE = 58.0                     # 青岛崂山一带地面海拔约 55~62 米


def load_token(flow_path=None):
    """优先级: 环境变量 AITIYU_TOKEN > --token 参数 > --flow 指定抓包 > 同目录 token.txt > flows.mitm"""
    t = os.environ.get("AITIYU_TOKEN")
    if t:
        return t.strip()
    for p in (flow_path, "token.txt", "flows.mitm"):
        if p and os.path.exists(p):
            if p.endswith(".txt"):
                s = open(p, encoding="utf-8").read().strip()
                if s:
                    return s.splitlines()[0].strip()
                continue
            for line in open(p, "rb").read().split(b"\n"):
                if b"authorization" in line.lower() and b"bearer" in line.lower():
                    m = re.search(rb"Bearer ([A-Za-z0-9_\-\.]+)", line)
                    if m:
                        return m.group(1).decode()
    raise SystemExit("token 未找到：设置 AITIYU_TOKEN、用 --token 传入、或用 --flow 指向 flows.mitm")


def jwt_claims(tok):
    """从 JWT payload 取 userId / deptId / openId / stuNo，换号时无需改代码。"""
    try:
        seg = tok.split(".")[1]
        seg += "=" * (-len(seg) % 4)
        return json.loads(base64.urlsafe_b64decode(seg))
    except Exception:
        return {}


HEAD = {}


def get(path):
    req = urllib.request.Request(BASE + path, headers=HEAD)
    with urllib.request.urlopen(req, context=CTX, timeout=30) as x:
        return x.read().decode("utf-8", "replace")


def post(path, body, extra=None):
    h = dict(HEAD)
    h["Content-Type"] = "application/json;charset=UTF-8"
    if extra:
        h.update(extra)
    req = urllib.request.Request(BASE + path, data=body, headers=h, method="POST")
    try:
        with urllib.request.urlopen(req, context=CTX, timeout=40) as x:
            return x.status, x.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def put_json(path, obj):
    body = json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode()
    h = dict(HEAD)
    h["Content-Type"] = "application/json;charset=UTF-8"
    req = urllib.request.Request(BASE + path, data=body, headers=h, method="PUT")
    try:
        with urllib.request.urlopen(req, context=CTX, timeout=40) as x:
            return x.status, x.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def fetch_pub():
    """陷阱核心：publicKey 传 32 字符随机串（必须能被 Base64 解成 24 字节），返回的 data 用它做 AES-192-ECB 解。"""
    s = None
    for _ in range(60):
        cand = "".join(random.choices(string.ascii_letters + string.digits, k=32))
        try:
            if len(base64.b64decode(cand + "==")) == 24:
                s = cand
                break
        except Exception:
            pass
    if not s:
        raise SystemExit("生成 32 字符 base64 失败")
    j = json.loads(get("/encrypt/getPublicKeyPc?publicKey=" + urllib.parse.quote(s)))
    if not j.get("data"):
        raise SystemExit("取公钥失败: %s" % j)
    d = AES.new(base64.b64decode(s + "=="), AES.MODE_ECB).decrypt(base64.b64decode(j["data"]))
    der = d[: -d[-1]].decode()
    return RSA.import_key(base64.b64decode(der))


def build_track(pace, lc, start_dt, punch_pool, rnd=None):
    """
    生成 GCJ02 体育场形轨迹，按真机特征注入随机性：
    - 时间轴 4~15 秒不规则间隔（真机实测 4.2~15.1 秒）
    - id 递增
    - 坐标叠高斯噪声 + 每圈半径微变
    - altitude 随机游走、speed 抖动
    - accuracy == horizontalAccuracy
    返回 (dur, block_dict) —— block 已含 points/colorList/arrowLine/width
    """
    rnd = rnd or random
    dur = int(round(lc * pace * 60))
    clat, clng = CENTER
    perim = stadium_perimeter()                       # 399.9m
    laps = max(3.0, lc * 1000.0 / perim)              # 2.10km → 5.25 圈
    t0 = int(start_dt.timestamp() * 1000)
    base_speed = lc * 1000.0 / dur

    # 1) 时间轴：4~15 秒随机间隔（对齐真机实测 dt=4.2~15.1 秒，平均约 11 秒/点），
    #    这样 2km 约 70~110 个点，与真机 67 点同量级；若用 1~8 秒会生成 200+ 点，
    #    采样密度是真人 3 倍，属于一眼可辨的统计差异。
    #    注意：收尾必须由 sample_offsets 处理，直接 min(..., dur) 会截出 1~3 秒尾巴。
    offsets = sample_offsets(dur, rnd)

    # 2) 每圈半径微变的相位扰动
    laps_r = [1.0 + rnd.uniform(-0.03, 0.03) for _ in range(int(math.ceil(laps)) + 2)]

    alt = ALT_BASE + rnd.uniform(-2, 2)
    pts = []
    prev_lat = prev_lng = None
    for i, tt in enumerate(offsets):
        frac = tt / float(dur) if dur else 0.0
        lap_idx = int(frac * laps)
        rr = laps_r[min(lap_idx, len(laps_r) - 1)]
        dx, dy = stadium_xy(frac * laps * perim)      # 沿跑道弧长推进
        lat = clat + (dy * rr) / M_PER_DEG_LAT
        lng = clng + (dx * rr) / M_PER_DEG_LNG
        # GPS 抖动 ~0.13 米
        lat += rnd.gauss(0, 1.2e-6)
        lng += rnd.gauss(0, 1.2e-6)
        # 行进方向：由上一点差分算方位角（0=正北，顺时针）
        if prev_lat is None:
            direc = round(rnd.uniform(0, 360), 1)
        else:
            dlat = (lat - prev_lat) * M_PER_DEG_LAT
            dlng = (lng - prev_lng) * M_PER_DEG_LNG
            direc = round((math.degrees(math.atan2(dlng, dlat)) + 360.0) % 360.0, 1)
        prev_lat, prev_lng = lat, lng
        # 海拔均值回归随机游走（不是纯游走，否则会一路漂到边界）
        alt = alt + 0.08 * (ALT_BASE - alt) + rnd.gauss(0, 0.6)
        alt = max(52.0, min(68.0, alt))
        acc = round(rnd.uniform(3.2, 6.5), 6)
        sp = max(0.3, base_speed + rnd.gauss(0, 0.85))
        pts.append({
            "altitude": round(alt, 6),
            "verticalAccuracy": 0,
            "indoorLocationType": -1,
            "provider": "gps",
            "latitude": round(lat, 7),
            "accuracy": acc,
            "horizontalAccuracy": acc,          # 真机两值相等
            "type": "gcj02",
            "steps": 0,
            "speed": round(sp, 4),
            "longitude": round(lng, 7),
            "direction": direc,
            "time": t0 + tt * 1000,
            "id": i,                             # 递增
            "color": "#007AFF",
        })

    # 3) 打卡点吸附：只有最近的采样点离打卡点 >12m 时才强行替换成精确坐标。
    #    体育场轨迹本身就会经过打卡点附近时，保留原采样点更自然，
    #    避免轨迹在打卡点处出现一个突兀的折角。
    for p in punch_pool:
        plat, plng = float(p["latitude"]), float(p["longitude"])
        k = min(range(len(pts)),
                key=lambda z: (pts[z]["latitude"] - plat) ** 2 + (pts[z]["longitude"] - plng) ** 2)
        dist = math.hypot((pts[k]["latitude"] - plat) * 111320.0,
                          (pts[k]["longitude"] - plng) * 89925.0)
        if dist > 12.0:
            pts[k]["latitude"] = plat
            pts[k]["longitude"] = plng

    block = {
        "points": pts,
        "colorList": ["#007AFF"] * len(pts),   # 缺这行 → 小程序画不出线，一片蓝色
        "arrowLine": True,
        "width": 6,
    }
    return dur, block


def today_enable_record():
    """今天是否已有 ENABLE 记录（只读）。返回记录 dict，没有则 None。

    这是 SKILL 9.4 的排期铁律：一条记录 = 一天。今天已有 ENABLE 时再走 finishRun，
    不会报错，但只会产生一条 REPEAT_ENABLE —— 不加次数，还多一行痕迹。
    查询失败时返回 None 并告警（宁可人工确认，也不要静默跳过）。
    """
    today = datetime.date.today().strftime("%Y-%m-%d")
    try:
        j = json.loads(get("/business/runningRecord/ownerList?pageNum=1&pageSize=100"
                           "&orderByColumn=startTime&isAsc=desc"))
    except Exception as e:
        print("  [warn] 当日排期检查失败，请人工确认今天是否已打卡: %s" % e)
        return None
    for r in j.get("rows") or []:
        if str(r.get("startTime") or "")[:10] == today and r.get("status") == "ENABLE":
            return r
    return None


def verify_record(rid):
    """提交后回读轨迹（SKILL 9.6）：block 四字段、colorList 长度、id 递增、采样间隔。

    只看 code:200 是不够的 —— 少传 colorList 服务端照样入库，只是小程序里画不出线。
    """
    try:
        j = json.loads(get("/business/runningRecord/getTrajectory/" + str(rid)))
        arr = json.loads(((j.get("data") or {}).get("coordinates")) or "[]")
    except Exception as e:
        print("      [verify] 回读失败: %s" % e)
        return False
    if not arr:
        print("      [verify] 轨迹为空：小程序点开会是「无法查询到轨迹信息」")
        return False
    b = arr[0] if isinstance(arr, list) else {}
    pts = b.get("points") or []
    dts = ([(pts[i + 1]["time"] - pts[i]["time"]) / 1000.0 for i in range(len(pts) - 1)]
           if len(pts) > 1 else [])
    checks = [
        ("block 四字段", set(b.keys()) == {"points", "colorList", "arrowLine", "width"}),
        ("points 非空", len(pts) > 0),
        ("colorList 长度", len(b.get("colorList") or []) == len(pts)),
        ("id 递增", [p.get("id") for p in pts] == list(range(len(pts)))),
        ("acc==hAcc", all(p.get("accuracy") == p.get("horizontalAccuracy") for p in pts)),
        ("dt 4~15s", bool(dts) and all(4 <= d <= 15 for d in dts)),
    ]
    bad = [n for n, good in checks if not good]
    print("      [verify] %s | 点数=%d 间隔=%.0f~%.0f 秒" % (
        "OK" if not bad else "异常: " + ",".join(bad),
        len(pts), min(dts) if dts else 0, max(dts) if dts else 0))
    return not bad


def one_run(pub, lc, pace, when, steps_mode="history", dry=False, rnd=None):
    rnd = rnd or random
    k = min(rnd.choice([3, 3, 3, 4]), len(PUNCH_RING))
    punches = [dict(p, showLocationId=0, active=True) for p in rnd.sample(PUNCH_RING, k)]
    dur, block = build_track(pace, lc, when, punches, rnd)

    st = when.strftime("%Y-%m-%d %H:%M:%S")
    et = (when + datetime.timedelta(seconds=dur)).strftime("%Y-%m-%d %H:%M:%S")

    per_km = REAL_STEPS_PER_KM_PHYSICAL if steps_mode == "physical" else REAL_STEPS_PER_KM_HISTORY
    steps = max(20, min(2000, int(lc * per_km * rnd.uniform(0.85, 1.15))))

    rec = {
        "lc": "%.2f" % lc,
        "sd": "%.2f" % pace,
        "js": "%02d:%02d:%02d" % (dur // 3600, (dur % 3600) // 60, dur % 60),
        "stepNumber": steps,
        "startTime": st,
        "endTime": et,
        "coordinates": json.dumps([block], separators=(",", ":"), ensure_ascii=False),
        "punches": punches,
    }
    payload = {
        "header": {
            "transactionCode": "finishRun",
            "transactionTime": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "userId": USER_ID,
            "clientId": CID,
        },
        "body": {"runningRecord": rec},
    }
    body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)

    if dry:
        ts = [p["time"] for p in block["points"]]
        dts = sorted({(ts[i + 1] - ts[i]) // 1000 for i in range(len(ts) - 1)})
        print("  [dry] lc=%s sd=%s js=%s step=%d pts=%d punches=%d" %
              (rec["lc"], rec["sd"], rec["js"], steps, len(block["points"]), len(punches)))
        print("        %s ~ %s" % (st, et))
        print("        block keys = %s" % list(block.keys()))
        print("        id 前 6 = %s | dt 取值 = %s" % ([p["id"] for p in block["points"][:6]], dts))
        print("        altitude 范围 = %.1f~%.1f | accuracy==hAcc? %s" % (
            min(p["altitude"] for p in block["points"]),
            max(p["altitude"] for p in block["points"]),
            all(p["accuracy"] == p["horizontalAccuracy"] for p in block["points"])))
        return {"code": "dry"}

    aes_key = "".join(rnd.choices(string.ascii_letters + string.digits, k=32))
    enc_key = base64.b64encode(PKCS1_v1_5.new(pub).encrypt(base64.b64encode(aes_key.encode()))).decode()
    ct = base64.b64encode(AES.new(aes_key.encode(), AES.MODE_ECB).encrypt(pad(body.encode(), 16))).decode()
    st_code, raw = post("/system/runningCycle/finishRun", ct.encode(),
                        {"isEncrypt": "true", "encrypt-key": enc_key})
    try:
        j = json.loads(raw)
    except Exception:
        j = {"code": -1, "raw": raw}
    return j


def stats():
    try:
        j = json.loads(get("/system/profit/dataAnalysis"))
        d = j.get("data") or {}
        return d.get("validTime"), d.get("sumLc"), d.get("runRank")
    except Exception as e:
        return ("?", "?", str(e))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--count", type=int, default=1, help="必须是 1：finishRun 一天只算第一条")
    ap.add_argument("--lc", type=float, default=None, help="里程 km，不传则随机 2.00~2.50")
    ap.add_argument("--pace", type=float, default=None, help="配速 分/km，不传则随机 6.0~7.0")
    ap.add_argument("--gap", type=int, default=30, help="多份构造时的间隔秒（仅 --dry 有意义）")
    ap.add_argument("--backdate", type=int, default=0, help="预留；finishRun 只能用当天")
    ap.add_argument("--days-ago", type=int, default=None, help="预留；补历史请用 direct_batch.py")
    ap.add_argument("--steps", choices=["history", "physical"], default="history",
                    help="步数口径：history=与真机样本同量级(默认)；physical=物理合理(2km约2400步)")
    ap.add_argument("--seed", type=int, default=None, help="固定随机种子，便于复现")
    ap.add_argument("--dry", action="store_true", help="只构造不提交；无 token 也可运行")
    ap.add_argument("--token", default=None, help="JWT，不传则读 AITIYU_TOKEN / token.txt / --flow")
    ap.add_argument("--flow", default=None, help="mitmproxy 抓包文件路径，从中提取 Bearer token")
    a = ap.parse_args()

    if a.days_ago is not None or a.backdate:
        raise SystemExit("finishRun 只接受当天（服务端会返回「跑步时间只能是当天」）；补历史请用 direct_batch.py")
    if a.count > 1 and not a.dry:
        raise SystemExit("finishRun 一天只算第一条：--count 必须为 1。"
                         "同一天重复提交只会产出 REPEAT_ENABLE（不加次数，多一行痕迹）")

    rnd = random.Random(a.seed) if a.seed is not None else random

    global HEAD, USER_ID
    tok = None
    try:
        tok = a.token or load_token(a.flow)
    except SystemExit:
        if not a.dry:
            raise
    if tok:
        claims = jwt_claims(tok)
        USER_ID = str(claims.get("userId") or USER_ID)
        HEAD = {"User-Agent": UA, "Accept": "application/json", "clientId": CID,
                "Authorization": "Bearer " + tok, "token": tok}
        print("用户: %s (userId=%s)" % (claims.get("nickName") or "?", USER_ID))
    else:
        claims = {}
        HEAD = {"User-Agent": UA, "Accept": "application/json", "clientId": CID}
        print("用户: <dry-匿名>（未提供 token，仅本地构造，不发请求）")

    # 排期铁律（SKILL 9.4）：一天 = 一条记录。今天已有 ENABLE 就直接中止。
    dup = today_enable_record() if tok else None
    if dup:
        line = "recordId=%s lc=%s startTime=%s" % (
            dup.get("recordId"), dup.get("lc"), dup.get("startTime"))
        if a.dry:
            print("  [dry] 警告: 今天已有 ENABLE 记录（%s）；真提交会被标 REPEAT_ENABLE" % line)
        else:
            raise SystemExit("今天已有有效记录：%s\n"
                             "一天只算第一条，再提交只会产出 REPEAT_ENABLE。已中止，未发送任何请求。" % line)

    v, s, r = stats() if tok else ("?", "?", "dry-匿名（未联网）")
    print("BEFORE: 有效次数=%s 总里程=%s 排名=%s" % (v, s, r))

    ok = 0
    for i in range(a.count):
        pub = None if a.dry else fetch_pub()
        pace = a.pace if a.pace else round(rnd.uniform(6.0, 7.0), 2)
        base_lc = a.lc if a.lc else rnd.uniform(2.00, 2.50)
        lc = round(base_lc, 2)
        day = datetime.date.today()          # finishRun 只接受当天；count>1 已在上方拒绝
        when = datetime.datetime(day.year, day.month, day.day,
                                 rnd.randint(6, 21), rnd.randint(0, 59), rnd.randint(0, 59))
        print("[%d/%d] lc=%.2f pace=%.2f @ %s" % (i + 1, a.count, lc, pace, when))
        res = one_run(pub, lc, pace, when, a.steps, a.dry, rnd)
        code = res.get("code")
        msg = str(res.get("msg", ""))[:180]
        print("   -> code=%s %s" % (code, msg))
        if code == 200:
            ok += 1
            rid = (res.get("data") or {}).get("recordId")
            if rid:
                print("      recordId=%s" % rid)
                verify_record(rid)
        elif code == 601:
            print("   (601=参数不满足规则，记录已建但无效)")
        if i < a.count - 1 and not a.dry:
            time.sleep(a.gap)

    v, s, r = stats() if tok else ("?", "?", "dry-匿名（未联网）")
    print("AFTER : 有效次数=%s 总里程=%s 排名=%s" % (v, s, r))
    print("成功 %d/%d" % (ok, a.count))


if __name__ == "__main__":
    main()
