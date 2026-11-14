# -*- coding: utf-8 -*-
"""打印当前账号的跑步统计与最近记录（只读，不写任何数据）

用法:
    set AITIYU_TOKEN=<JWT>          # Windows PowerShell: $env:AITIYU_TOKEN="<JWT>"
    python check.py
    python check.py --token <JWT> --recent 10
"""
import argparse, base64, json, os, re, ssl, urllib.request

BASE = "https://www.aitiyuplus.cn/prod-api"
CID = "db308ad8185aa5ff3b66bf787f7cddbd"
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/120.0.0.0 Safari/537.36 MicroMessenger/7.0.20.1781 MiniProgramEnv/Windows")
# TLS 证书校验默认开启；只有显式设置 AITIYU_INSECURE=1 才关闭（应急用，不要常态化）
CTX = ssl.create_default_context()
if os.environ.get("AITIYU_INSECURE") == "1":
    CTX.check_hostname = False
    CTX.verify_mode = ssl.CERT_NONE


def load_token(p=None):
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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--token", default=None)
    ap.add_argument("--flow", default=None, help="mitmproxy 抓包文件路径（自动提取 Bearer）")
    ap.add_argument("--recent", type=int, default=6)
    a = ap.parse_args()

    tok = a.token or load_token(a.flow)
    cl = jwt_claims(tok)
    h = {"User-Agent": UA, "Accept": "application/json", "clientId": CID,
         "Authorization": "Bearer " + tok, "token": tok}

    def get(path):
        r = urllib.request.Request(BASE + path, headers=h)
        with urllib.request.urlopen(r, context=CTX, timeout=30) as x:
            return x.read().decode("utf-8", "replace")

    print("用户: %s  学号: %s  userId=%s" % (cl.get("nickName", "?"), cl.get("stuNo", "?"), cl.get("userId", "?")))

    d = json.loads(get("/system/profit/dataAnalysis"))["data"]
    print("\n=== 本学期统计 ===")
    print("  学期     : %s" % d.get("semesterName"))
    print("  有效次数 : %s" % d.get("validTime"))
    print("  总里程   : %s km" % d.get("sumLc"))
    print("  最长单次 : %s km" % d.get("maxLc"))
    print("  校排名   : %s" % d.get("runRank"))

    try:
        j = json.loads(get("/business/runningRecord/ownerList?pageNum=1&pageSize=%d"
                           "&orderByColumn=startTime&isAsc=desc" % a.recent))
        rows = j.get("rows") or []
        print("\n=== 最近 %d 条记录 ===" % len(rows))
        for r in rows:
            print("  %s ~ %s | lc=%-5s sd=%-5s js=%-10s | %-14s %s" % (
                str(r.get("startTime"))[5:16], str(r.get("endTime"))[11:19],
                r.get("lc"), r.get("sd"), r.get("js"),
                r.get("status"), r.get("insertType") or ""))
    except Exception as e:
        print("记录列表读取失败: %s" % e)

    try:
        sname = str(d.get("semesterName") or "")
        j = json.loads(get("/system/regular/list?pageNum=1&pageSize=200"))
        rows = [r for r in (j.get("rows") or []) if str(r.get("semesterName")) == sname]
        print("\n=== 本学期规则 (%s) ===" % sname)
        for r in rows:
            print("  %-10s %s ~ %s %s" % (r.get("name"), r.get("minParams"),
                                          r.get("maxParams"), r.get("unit") or ""))
    except Exception as e:
        print("规则读取失败: %s" % e)


if __name__ == "__main__":
    main()
