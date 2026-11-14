#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
repair.py —— 修复历史遗留的 insertType / stepNumber

用法:
    python scripts/repair.py           # 只扫描,列出需要修的记录
    python scripts/repair.py --apply   # 真修

修什么:
    - insertType != "auto"  ->  "auto"       (manual 等于自曝是补录的)
    - stepNumber 不在 20~400 -> lc*100*0.85~1.15  (与真机样本 143~331 同量级)

为什么必须 GET 全量再 PUT:
    PUT /business/runningRecord 在执行更新前会先跑 RunningRecordBo 的全部
    @NotNull 校验(lc/sd/js/startTime/endTime/coordinates 等),只传增量字段
    会被 "速度不能为空" / "里程不能为空" / "跑步结束时间不能为空" 依次拦下,
    而且返回的是 HTTP 200 + body 里的 code:500,不看 body 会以为成功。

副作用(不可避免):
    coordinates 从 None 变成 "" —— Bo 里 coordinates 是必填,只能传空串。
    真实轨迹在 running_trajectory 表里由 trajectoryId 关联,不受影响。
"""
import argparse
import json
import random
import sys

sys.path.insert(0, ".")
import batch  # noqa: E402

# stepNumber 的"异常"判据来自 30 条真实记录的实测分布:
#   0,0,0,0,0,0,0,0,2,22,33,71,128,152,158,170,331,343,400,409,411,416,428,594
# 也就是说**真机大量记录就是 0**（小程序未采到步数），所以 0 绝对不能当异常去"修"。
# 只有明显越界的才动，上限取 700（真机最大值 594 之上留余量）。
STEP_LO = 0
STEP_HI = 700


def api_get(path):
    return json.loads(batch.get(path))


def fetch_all(page_size=100, max_pages=20):
    """翻页拿全 ownerList。"""
    out, page = [], 1
    while page <= max_pages:
        j = api_get("/business/runningRecord/ownerList?pageNum=%d&pageSize=%d"
                    "&orderByColumn=startTime&isAsc=desc" % (page, page_size))
        rows = j.get("rows") or []
        out.extend(rows)
        if len(rows) < page_size:
            break
        page += 1
    return out


def need_fix(row):
    """返回 (原因列表, 目标 stepNumber)。"""
    reasons = []
    ins = row.get("insertType")
    if ins != "auto":
        reasons.append("insertType=%s" % ins)

    try:
        lc = float(row.get("lc") or 0)
    except (TypeError, ValueError):
        lc = 0.0
    step = row.get("stepNumber")
    step = int(step) if isinstance(step, (int, float)) else 0

    target = step
    if not (STEP_LO <= step <= STEP_HI):
        reasons.append("stepNumber=%s 越界" % step)
        target = max(STEP_LO, min(2000, int(lc * 100 * random.uniform(0.85, 1.15))))

    return reasons, target


def build_full_bo(rid, target_step):
    """GET 单条 -> 组装完整 Bo -> 覆盖 insertType/stepNumber。"""
    d = api_get("/business/runningRecord/" + str(rid)).get("data") or {}
    body = {
        "recordId": d["recordId"],
        "userId": d["userId"],
        "userName": d.get("userName"),
        "openId": d["openId"],
        "lc": d["lc"],
        "sd": d["sd"],
        "js": d["js"],
        "startTime": d["startTime"],
        "endTime": d["endTime"],
        "status": d.get("status"),
        "stuNo": d.get("stuNo"),
        "coordinates": d.get("coordinates") or "",
        "stepNumber": target_step,
        "insertType": "auto",
        "deptId": d.get("deptId"),
        "semesterId": d.get("semesterId"),
        "semesterName": d.get("semesterName"),
    }
    return body


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true", help="真改,不加只扫描")
    ap.add_argument("--flow", default=None, help="mitmproxy 抓包文件路径（自动提取 Bearer）")
    ap.add_argument("--seed", type=int, default=None)
    args = ap.parse_args()

    if args.seed is not None:
        random.seed(args.seed)

    tok = batch.load_token(a.flow)
    batch.HEAD = {
        "User-Agent": batch.UA,
        "Accept": "application/json",
        "clientId": batch.CID,
        "Authorization": "Bearer " + tok,
        "token": tok,
    }

    rows = fetch_all()
    print("共 %d 条记录" % len(rows))

    todo = []
    for r in rows:
        reasons, target = need_fix(r)
        if reasons:
            todo.append((r, reasons, target))

    if not todo:
        print("没有需要修的记录 ✓")
        return

    print("\n需要修 %d 条:" % len(todo))
    for r, reasons, target in todo:
        print("  %s | %s | lc=%s | %s -> step=%s" % (
            r.get("recordId"), r.get("startTime"), r.get("lc"),
            " / ".join(reasons), target))

    if not args.apply:
        print("\n这是预览。确认无误后加 --apply 真改。")
        return

    print("\n=== 开始修改 ===")
    ok = 0
    for r, reasons, target in todo:
        rid = r.get("recordId")
        body = build_full_bo(rid, target)
        code, raw = batch.put_json("/business/runningRecord", body)
        if '"code":200' in raw:
            ok += 1
            print("  %s -> 成功 (step=%s)" % (rid, target))
        else:
            print("  %s -> 失败 %s" % (rid, raw[:120]))

    print("\n=== 回读验证 ===")
    for r, _, _ in todo:
        rid = r.get("recordId")
        d = api_get("/business/runningRecord/" + str(rid)).get("data") or {}
        print("  %s | step=%-4s | insertType=%s | endTimeStr=%s" % (
            rid, d.get("stepNumber"), d.get("insertType"), d.get("endTimeStr")))

    j = api_get("/system/profit/dataAnalysis").get("data") or {}
    print("\n统计: 有效次数=%s 总里程=%s 排名=%s" % (
        j.get("validTime"), j.get("sumLc"), j.get("runRank")))
    print("成功修改 %d / %d 条" % (ok, len(todo)))


if __name__ == "__main__":
    main()
