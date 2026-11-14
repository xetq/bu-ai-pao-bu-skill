# -*- coding: utf-8 -*-
"""
直接写跑步记录（管理端 /business/runningRecord POST）
—— 绕过 finishRun 的「跑步时间只能是当天」校验，可补任意历史日期
—— 需要 openId / deptId / semesterId，均来自 JWT
用法: python direct_batch.py --count 8 [--lc 2.10] [--pace 6.1] [--dry]
"""
import argparse, base64, datetime, hashlib, json, os, random, re, ssl, time
import urllib.request, urllib.error

# 复用 batch.py 的体育场形轨迹生成器，保证两条通路产出的 coordinates 完全同构
import batch


BASE = "https://www.aitiyuplus.cn/prod-api"
CID = "db308ad8185aa5ff3b66bf787f7cddbd"
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/120.0.0.0 Safari/537.36 MicroMessenger/7.0.20.1781(0x6700143B) "
      "MiniProgramEnv/Windows WindowsWechat/WMPF XWEB/26073")
# TLS 证书校验默认开启；只有显式设置 AITIYU_INSECURE=1 才关闭（应急用，不要常态化）
CTX = ssl.create_default_context()
if os.environ.get("AITIYU_INSECURE") == "1":
    CTX.check_hostname = False
    CTX.verify_mode = ssl.CERT_NONE

# 账号身份一律从 JWT 解析（见 jwt_claims），不保留默认值：
# 缺字段就直接中止，避免"用了别人的号还以为是自己"。
UID = 0
DEPT = 0
OPENID = ""
STUNO = ""
# 学期 id 与名称从 /system/semester/list 的 current 标记取，这里只作未取到时的兜底
SEM = 0
SEMNAME = ""


def load_token(p=None):
    """优先级: 环境变量 AITIYU_TOKEN > --token > --flow 抓包 > 同目录 token.txt > flows.mitm"""
    t = os.environ.get("AITIYU_TOKEN")
    if t:
        return t.strip()
    for path in ([p] if p else []) + ["token.txt", "flows.mitm"]:
        if path and os.path.exists(path):
            if path.endswith(".txt"):
                s = open(path, encoding="utf-8").read().strip()
                if s:
                    return s.splitlines()[0].strip()
                continue
            for line in open(path, "rb").read().split(b"\n"):
                if b"authorization" in line.lower() and b"bearer" in line.lower():
                    m = re.search(rb"Bearer ([A-Za-z0-9_\-\.]+)", line)
                    if m:
                        return m.group(1).decode()
    raise SystemExit("token 未找到：设置 AITIYU_TOKEN、用 --token 传入、或用 --flow 指向 flows.mitm")


def jwt_claims(tok):
    try:
        seg = tok.split(".")[1]
        seg += "=" * (-len(seg) % 4)
        return json.loads(base64.urlsafe_b64decode(seg))
    except Exception:
        return {}


def current_semester(h):
    """自动找当前学期 id/name；接口结构变化时静默回退到常量。"""
    try:
        j = json.loads(get(h, "/system/semester/list?pageNum=1&pageSize=50"))
        rows = j.get("rows") or j.get("data") or []
        today = datetime.date.today().isoformat()
        for r in rows:
            s = str(r.get("startTime") or "")[:10]
            e = str(r.get("endTime") or "")[:10]
            if s and e and s <= today <= e:
                return r.get("id"), r.get("semesterName") or r.get("name")
    except Exception:
        pass
    return None, None


def mk_head(tok):
    return {"User-Agent": UA, "Accept": "application/json", "clientId": CID,
            "Authorization": "Bearer " + tok, "token": tok,
            "Content-Type": "application/json;charset=UTF-8"}


def get(h, path):
    r = urllib.request.Request(BASE + path, headers=h)
    with urllib.request.urlopen(r, context=CTX, timeout=30) as x:
        return x.read().decode("utf-8", "replace")


def post(h, path, obj):
    r = urllib.request.Request(BASE + path, data=json.dumps(obj, ensure_ascii=False).encode(),
                               headers=h, method="POST")
    try:
        with urllib.request.urlopen(r, context=CTX, timeout=30) as x:
            return x.status, x.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def existing_days(h):
    """已存在的记录日期集合，避免同一天重复。"""
    days = set()
    page = 1
    while True:
        j = json.loads(get(h, "/business/runningRecord/ownerList?pageNum=%d&pageSize=100" % page))
        rows = j.get("rows") or []
        for r in rows:
            st = r.get("startTime") or ""
            if len(st) >= 10:
                days.add(st[:10])
        if len(rows) < 100:
            break
        page += 1
    return days


def build(day, lc, pace, hh=None):
    hh = hh if hh is not None else random.randint(6, 21)
    start = datetime.datetime(day.year, day.month, day.day, hh, random.randint(0, 59), random.randint(0, 59))
    # 轨迹与 finishRun 通路完全同构：体育场形 + block 四字段，一次写全，不需要事后 PUT trajectory
    dur, block = batch.build_track(pace, lc, start, batch.PUNCH_RING)
    end = start + datetime.timedelta(seconds=dur)
    return {
        "userId": UID, "stuNo": STUNO, "openId": OPENID, "deptId": DEPT,
        "lc": round(lc, 2), "sd": round(pace, 2),
        "js": "%02d:%02d:%02d" % (dur // 3600, (dur // 60) % 60, dur % 60),
        "startTime": start.strftime("%Y-%m-%d %H:%M:%S"),
        "endTime": end.strftime("%Y-%m-%d %H:%M:%S"),
        "status": "ENABLE",
        "coordinates": json.dumps([block], separators=(",", ":"), ensure_ascii=False),
        # 步数口径对齐 batch.py 的 history 模式：与真机样本（152~331）同量级，不再用 600~700 系数
        "stepNumber": max(20, min(2000, int(lc * batch.REAL_STEPS_PER_KM_HISTORY * random.uniform(0.85, 1.15)))),
        # insertType 必须是 auto：管理端 list 直接返回该字段，manual 是后台补录标记
        "insertType": "auto",
        "semesterId": SEM, "semesterName": SEMNAME,
    }


def stats(h):
    j = json.loads(get(h, "/system/profit/dataAnalysis"))["data"]
    return j.get("validTime"), j.get("sumLc"), j.get("runRank")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--count", type=int, default=8)
    ap.add_argument("--lc", type=float, default=2.10)
    ap.add_argument("--pace", type=float, default=6.10)
    ap.add_argument("--target", type=int, default=35,
                    help="目标有效次数（2026-2027 第一学期规则：男生 35 / 女生 30，以 /system/regular/list 为准）")
    ap.add_argument("--dry", action="store_true")
    ap.add_argument("--token", default=None, help="JWT；不传则读 AITIYU_TOKEN / token.txt / --flow")
    ap.add_argument("--flow", default=None, help="mitmproxy 抓包文件路径（自动提取 Bearer）")
    ap.add_argument("--sem", type=int, default=None, help="手动指定学期 id")
    a = ap.parse_args()

    global UID, DEPT, OPENID, STUNO, SEM, SEMNAME
    tok = a.token or load_token(a.flow)
    cl = jwt_claims(tok)
    UID = int(cl.get("userId") or 0)
    DEPT = int(cl.get("deptId") or 0)
    OPENID = cl.get("openId") or ""
    STUNO = cl.get("stuNo") or ""
    print("用户: %s (userId=%s deptId=%s)" % (cl.get("nickName") or "?", UID, DEPT))
    missing = [k for k, v in (("userId", UID), ("deptId", DEPT),
                              ("openId", OPENID), ("stuNo", STUNO)) if not v]
    if missing:
        raise SystemExit("JWT 里缺少必要字段 %s，无法定位到具体学生，已中止（避免写出脏数据）"
                         % ", ".join(missing))

    h = mk_head(tok)
    sid, sname = current_semester(h)
    if a.sem:
        SEM = a.sem
    elif sid:
        SEM = int(sid)
    if sname:
        SEMNAME = sname
    print("学期: %s (id=%s)" % (SEMNAME, SEM))

    v, s, r = stats(h)
    print("BEFORE: 有效次数=%s 总里程=%s 排名=%s" % (v, s, r))
    try:
        have = int(v)
    except (TypeError, ValueError):
        have = None
        print("  [warn] 读不到有效次数，跳过目标判定，按 --count 处理")
    if a.target and have is not None and have >= a.target:
        print("已达目标 %d 次，无需补录" % a.target)
        return
    need = min(a.count, a.target - have) if (a.target and have is not None) else a.count

    used = existing_days(h)
    print("已有记录的日期 %d 个" % len(used))

    # 从昨天往前挑空闲日期
    day = datetime.date.today() - datetime.timedelta(days=1)
    done = 0
    while done < need:
        if day.isoformat() in used:
            day -= datetime.timedelta(days=1)
            continue
        rec = build(day, a.lc + random.uniform(-0.03, 0.30), a.pace + random.uniform(-0.4, 0.5))
        tag = " ".join("%s=%s" % (k, rec[k]) for k in ("lc", "sd", "js", "startTime"))
        if a.dry:
            print("  [dry] %s" % tag)
        else:
            code, raw = post(h, "/business/runningRecord", rec)
            ok = '"code":200' in raw
            print("  %-10s %s -> %s" % (day.isoformat(), tag, "OK" if ok else raw[:160]))
            if ok:
                done += 1
                time.sleep(1.0)
            else:
                print("    (跳过该日期)")
        day -= datetime.timedelta(days=1)
        if a.dry:
            done += 1
        if len(used) + done > 400:
            break

    v, s, r = stats(h)
    print("AFTER : 有效次数=%s 总里程=%s 排名=%s" % (v, s, r))


if __name__ == "__main__":
    main()
