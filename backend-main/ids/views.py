import csv
import json

import pandas as pd
import os
import os.path
import random
import numpy as np

import subprocess
import tempfile
import threading
import time
import uuid
from typing import Any, Dict, List, Optional

from django.conf import settings
from django.http import JsonResponse
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt


# Create your views here.

# ---------------- Real-time monitoring (polling) ----------------
_monitor_sessions: Dict[str, Dict[str, Any]] = {}
_monitor_sessions_lock = threading.Lock()


def _append_session_alert(session_id: str, alert: Dict[str, Any]) -> None:
    with _monitor_sessions_lock:
        sess = _monitor_sessions.get(session_id)
        if not sess:
            return
        sess["alerts"].append(alert)


def _set_session_done(session_id: str, *, done: bool = True, error: Optional[str] = None) -> None:
    with _monitor_sessions_lock:
        sess = _monitor_sessions.get(session_id)
        if not sess:
            return
        sess["done"] = done
        if error:
            sess["error"] = error


def _set_session_progress(session_id: str, progress: Dict[str, Any]) -> None:
    """
    将后端执行阶段/统计信息写入 session，供前端轮询展示。
    """
    with _monitor_sessions_lock:
        sess = _monitor_sessions.get(session_id)
        if not sess:
            return
        sess["progress"] = progress


def _get_session_snapshot(session_id: str) -> Optional[Dict[str, Any]]:
    with _monitor_sessions_lock:
        sess = _monitor_sessions.get(session_id)
        if not sess:
            return None
        # shallow copy for safety
        return {k: v for k, v in sess.items()}
def read_csv(request):
    # 返回响应
    data = read_csv_fun()
    json_data = data_to_json(data)
    # return JsonResponse({"data": json.loads(json_data)})
    return JsonResponse(json.loads(json_data),safe=False)


def dashboard(request):
    """
    前端可视化界面：/ids/dashboard
    使用 start_monitor + poll_monitor 做实时预警展示。
    """
    return render(request, "dashboard.html")

def test_read_csv(request):
    data = read_csv_fun()
    json_data = data_to_json(data)
    return render(request, "test.html", json.loads(json_data)[0])

def get_total_lines(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        total_lines = sum(1 for line in f)
    return total_lines
def read_csv_fun():
    """
    读取速度快，格式为行列，缺失数据为NaN
    """

    num_lines = 100
    file = os.path.join(os.getcwd(), r'ids\data\data.csv')
    total_lines = get_total_lines(file)
    print(f"Total lines in file: {total_lines}")

    # 检查文件是否存在
    if not os.path.exists(file):
        raise FileNotFoundError(f"The file {file} does not exist")

    # 检查文件是否为空
    if os.path.getsize(file) == 0:
        raise ValueError("The file is empty")

    # 检查文件总行数
    with open(file, 'r', encoding='utf-8') as f:
        total_lines = sum(1 for line in f)

    # 尝试读取文件
    try:
        data = pd.read_csv(file, nrows=num_lines, dtype=str, header=None, encoding='utf-8')
    except pd.errors.EmptyDataError:
        raise ValueError("No columns to parse from file")
    except Exception as e:
        raise ValueError(f"An error occurred while reading the file: {e}")

    print(data)
    return data


def data_to_json(data):
    df = None
    try:
        df = data.apply(move_last_valid_to_first, axis=1)
    except ValueError:
        print(f"ValueError{df}")
    json_data = df.to_json(orient='records')
    return json_data


def move_last_valid_to_first(row):
    new_column_index = 11
    last_valid_idx = row.last_valid_index()  # 获取最后一个非NaN值的列索引
    if last_valid_idx is not None:
        last_valid_value = row[last_valid_idx]  # 获取最后一个非NaN值
        row = row.drop(labels=[last_valid_idx])  # 删除最后一个非NaN值所在的列
        if new_column_index in row.index:
            row = row.drop(labels = [new_column_index])
        row = pd.concat([pd.Series([last_valid_value], index=[11]), row])  # 将最后一个非NaN值添加到第一列
    return row


def _read_uploaded_json(request) -> Any:
    """
    支持两种上传方式：
    1) multipart/form-data: file=...
    2) raw body: application/json
    """
    if request.method != "POST":
        raise ValueError("Only POST is supported.")

    if request.FILES:
        f = request.FILES.get("file")
        if not f:
            raise ValueError("Missing uploaded file field: `file`.")
        content = f.read().decode("utf-8", errors="ignore")
        return json.loads(content)

    if request.body:
        content_type = request.headers.get("Content-Type", "")
        if "application/json" in content_type:
            return json.loads(request.body.decode("utf-8", errors="ignore"))

    raise ValueError("No JSON payload found.")


@csrf_exempt
def classify_attack_json(request):
    """
    接收 ClockIDS.cpp 生成的 attack_packets.json，并输出：
      - 预测的攻击类型 attack_type
      - 置信度 confidence
      - 攻击详细 detail（原始 packet）
    """
    try:
        uploaded_json = _read_uploaded_json(request)
        classifier = __build_classifier_service()
        from .ml_attack_classifier import classify_uploaded_attack_packets_json

        results = classify_uploaded_attack_packets_json(
            classifier=classifier,
            uploaded_json=uploaded_json,
            training_if_missing=True,
        )
        return JsonResponse({"results": results}, safe=False)
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=400)


def __build_classifier_service():
    from .ml_attack_classifier import AttackClassifierService

    return AttackClassifierService(
        clockids_bin_path=settings.CLOCKIDS_BIN_PATH,
        normal_data_path=settings.CLOCKIDS_NORMAL_DATA_PATH,
        baselines_csv_path=settings.CLOCKIDS_BASELINES_CSV_PATH,
        model_path=settings.CLOCKIDS_ATTACK_CLASSIFIER_MODEL_PATH,
    )


@csrf_exempt
def simulate_attack_and_predict(request):
    """
    后端生成“检测数据流”-> 调用 ClockIDS.cpp detect(stream) -> 得到 attack_packets.json
    -> 使用 ML 分类器输出攻击类型预警。

    request body 示例：
      {
        "attack_kind": "DoS"
      }
    """
    try:
        body = {}
        if request.body:
            body = json.loads(request.body.decode("utf-8", errors="ignore"))

        # 默认：mixed 模式（不由用户指定攻击类型），生成器内部随机选择攻击段
        mode = body.get("mode", None)
        attack_kind = body.get("attack_kind", None)

        if mode is None:
            # 兼容旧调用：如果传了 attack_kind，就走单段模式，否则 mixed
            mode = "single" if attack_kind else "mixed"

        classifier = __build_classifier_service()

        # 需要 baselines.csv，否则 detect 无法运行
        # ensure_trained 内部已保证 baselines 存在，这里再读一次拿到 cycle/id
        from .attack_generator import (
            load_baselines_csv,
            pick_valid_id_by_ecu,
            generate_attack_stream_csv,
            generate_mixed_attack_stream_csv,
            build_stream_text,
        )

        baselines = load_baselines_csv(settings.CLOCKIDS_BASELINES_CSV_PATH)
        target = pick_valid_id_by_ecu(baselines, body.get("ecu_id"))
        if not target:
            return JsonResponse({"error": "No valid baseline id found."}, status=400)

        ecu_id = target["id"]
        cycle = target["cycle"]

        pre_frames = int(body.get("pre_frames", 240))
        attack_frames = int(body.get("attack_frames", 220))
        post_frames = int(body.get("post_frames", 240))
        num_attacks = int(body.get("num_attacks", 4))
        seed = body.get("seed", None)

        classifier.ensure_trained(
            pre_frames=pre_frames,
            attack_frames=attack_frames,
            post_frames=post_frames,
        )

        results_true_sequence = None
        if mode == "single":
            # 单次攻击：用户指定 attack_kind
            attack_kind = attack_kind or "DoS"
            stream_iter = generate_attack_stream_csv(
                ecu_id,
                cycle,
                attack_kind,
                start_ts=0.0,
                pre_frames=pre_frames,
                attack_frames=attack_frames,
                post_frames=post_frames,
                seed=seed,
            )
        elif mode == "mixed":
            attack_kinds = body.get("attack_kinds", ["DoS", "Fuzzy", "gear", "RPM"])
            stream_iter, chosen_seq = generate_mixed_attack_stream_csv(
                ecu_id,
                cycle,
                attack_kinds=attack_kinds,
                num_attacks=num_attacks,
                start_ts=0.0,
                pre_frames=pre_frames,
                attack_frames=attack_frames,
                post_frames=post_frames,
                seed=seed,
            )
            # 可选：把生成器内部真实攻击序列也返回给你排查（前端不展示也行）
            results_true_sequence = chosen_seq
        else:
            return JsonResponse({"error": "Invalid mode. Use mode='single' or 'mixed'."}, status=400)

        stream_text = build_stream_text(stream_iter)

        with tempfile.NamedTemporaryFile(mode="w+b", suffix=".json", delete=False) as tmp:
            out_json_path = tmp.name

        try:
            cmd = [
                settings.CLOCKIDS_BIN_PATH,
                "detect",
                "--baseline",
                settings.CLOCKIDS_BASELINES_CSV_PATH,
                "--out",
                out_json_path,
            ]
            proc = subprocess.run(
                cmd,
                input=stream_text.encode("utf-8"),
                capture_output=True,
                cwd=None,
            )
            if proc.returncode != 0:
                raise RuntimeError(proc.stderr.decode("utf-8", errors="ignore"))

            with open(out_json_path, "r", encoding="utf-8") as f:
                packets = json.load(f)

            from .ml_attack_classifier import AttackClassifierService

            # classifier 里已经有模型，无需再加载
            results = classifier.predict_packets(packets)
            payload = {"results": results}
            if mode == "single":
                payload["attack_kind_generated"] = attack_kind
            if results_true_sequence is not None:
                payload["attack_kinds_chosen_by_generator"] = results_true_sequence
            return JsonResponse(payload, safe=False)
        finally:
            try:
                os.remove(out_json_path)
            except Exception:
                pass
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=400)


@csrf_exempt
def start_monitor(request):
    """
    实时监测 + 分类（后台线程跑 ClockIDS detect(ndjson)）+ 前端轮询。

    POST body（可选字段）：
      {
        "mode": "mixed" | "single",
        "attack_kind": "DoS",              // mode=single
        "attack_kinds": ["DoS","Fuzzy"],  // mode=mixed
        "num_attacks": 8,
        "pre_frames": 800,
        "attack_frames": 600,
        "post_frames": 800,
        "sleep_ms": 2,
        "multi_id": true,                  // 多 CAN ID 交错（按时间戳合并为一条流）
        "num_ids": 5,                      // multi_id 时选取的 ID 数量
        "ecu_ids": ["0690","0329"],        // 可选，显式指定多个 ID
        "ecu_id": "0690",                  // 单 ID 模式或 multi_id=false
        "batch_ml_size": 12                // 攒够 N 条 C++ 告警后一次性 predict_packets
      }
    """
    try:
        body = {}
        if request.body:
            body = json.loads(request.body.decode("utf-8", errors="ignore"))

        mode = body.get("mode", "mixed")
        attack_kind = body.get("attack_kind", None)
        attack_kinds = body.get("attack_kinds", ["DoS", "Fuzzy", "gear", "RPM"])
        num_attacks = int(body.get("num_attacks", 8))
        pre_frames = int(body.get("pre_frames", 800))
        attack_frames = int(body.get("attack_frames", 600))
        post_frames = int(body.get("post_frames", 800))
        sleep_ms = float(body.get("sleep_ms", 2.0))
        multi_id = bool(body.get("multi_id", True))
        num_ids = int(body.get("num_ids", 5))
        batch_ml_size = max(1, int(body.get("batch_ml_size", 12)))
        seed = body.get("seed", None)

        from .attack_generator import (
            load_baselines_csv,
            pick_valid_id_by_ecu,
            generate_attack_stream_csv,
            generate_mixed_attack_stream_csv,
            pick_multiple_baselines,
            generate_multi_id_mixed_stream,
        )

        baselines = load_baselines_csv(settings.CLOCKIDS_BASELINES_CSV_PATH)

        ecu_ids_param = body.get("ecu_ids")
        if isinstance(ecu_ids_param, str) and ecu_ids_param.strip():
            ecu_ids_param = [x.strip() for x in ecu_ids_param.split(",") if x.strip()]
        elif isinstance(ecu_ids_param, list):
            ecu_ids_param = [str(x).strip() for x in ecu_ids_param if str(x).strip()]
            if not ecu_ids_param:
                ecu_ids_param = None
        else:
            ecu_ids_param = None

        stream_iter = None
        chosen_attack_kinds = None
        chosen_per_id = None
        ecu_id = None
        cycle = None
        ecu_ids_list: List[str] = []
        cycles_map: Dict[str, float] = {}

        if multi_id and num_ids >= 2:
            rows = pick_multiple_baselines(
                baselines,
                ecu_ids=ecu_ids_param,
                num_ids=num_ids,
            )
            if len(rows) < 2:
                return JsonResponse(
                    {"error": "multi_id 需要至少 2 条有效 baselines，请检查 clockids_baselines.csv"},
                    status=400,
                )
            stream_iter, chosen_per_id = generate_multi_id_mixed_stream(
                rows,
                attack_kinds=attack_kinds,
                num_attacks=num_attacks,
                pre_frames=pre_frames,
                attack_frames=attack_frames,
                post_frames=post_frames,
                seed=seed,
            )
            ecu_ids_list = [str(r["id"]) for r in rows]
            cycles_map = {str(r["id"]): float(r["cycle"]) for r in rows}
            ecu_id = ecu_ids_list[0]
            cycle = cycles_map.get(ecu_id)
        else:
            target = pick_valid_id_by_ecu(baselines, body.get("ecu_id"))
            if not target:
                return JsonResponse({"error": "No valid baseline id found."}, status=400)
            ecu_id = target["id"]
            cycle = float(target["cycle"])
            ecu_ids_list = [str(ecu_id)]
            cycles_map = {str(ecu_id): cycle}

            if mode == "single":
                kind = attack_kind or "DoS"
                stream_iter = generate_attack_stream_csv(
                    ecu_id,
                    cycle,
                    kind,
                    start_ts=0.0,
                    pre_frames=pre_frames,
                    attack_frames=attack_frames,
                    post_frames=post_frames,
                    seed=seed,
                )
                chosen_attack_kinds = [kind]
            elif mode == "mixed":
                stream_iter, chosen_seq = generate_mixed_attack_stream_csv(
                    ecu_id,
                    cycle,
                    attack_kinds=attack_kinds,
                    num_attacks=num_attacks,
                    start_ts=0.0,
                    pre_frames=pre_frames,
                    attack_frames=attack_frames,
                    post_frames=post_frames,
                    seed=seed,
                )
                chosen_attack_kinds = chosen_seq
            else:
                return JsonResponse({"error": "Invalid mode. Use mode='single' or 'mixed'."}, status=400)
            chosen_per_id = [{"id": str(ecu_id), "chosen_attack_kinds": chosen_attack_kinds}]

        session_id = uuid.uuid4().hex
        with _monitor_sessions_lock:
            _monitor_sessions[session_id] = {
                "alerts": [],
                "done": False,
                "error": None,
                "created_at": time.time(),
                "ecu_id": ecu_id,
                "cycle": cycle,
                "ecu_ids": ecu_ids_list,
                "cycles": cycles_map,
                "mode": mode,
                "chosen_attack_kinds": chosen_attack_kinds,
                "chosen_per_id": chosen_per_id,
                "batch_ml_size": batch_ml_size,
                "progress": {
                    "stage": "init",
                    "message": "等待启动 C++ 检测与分类器...",
                    "stats": {
                        "cpp_packets_seen": 0,
                        "classified_packets": 0,
                        "buf_len": 0,
                    },
                },
            }

        def worker():
            try:
                from .ml_attack_classifier import AttackClassifierService

                classifier = AttackClassifierService(
                    clockids_bin_path=settings.CLOCKIDS_BIN_PATH,
                    normal_data_path=settings.CLOCKIDS_NORMAL_DATA_PATH,
                    baselines_csv_path=settings.CLOCKIDS_BASELINES_CSV_PATH,
                    model_path=settings.CLOCKIDS_ATTACK_CLASSIFIER_MODEL_PATH,
                )
                _set_session_progress(
                    session_id,
                    {
                        "stage": "training",
                        "message": "分类器训练/加载中（可能需要较长时间）...",
                        "stats": {
                            "cpp_packets_seen": 0,
                            "classified_packets": 0,
                            "buf_len": 0,
                        },
                    },
                )
                classifier.ensure_trained(
                    pre_frames=pre_frames,
                    attack_frames=attack_frames,
                    post_frames=post_frames,
                )
                _set_session_progress(
                    session_id,
                    {
                        "stage": "detect_start",
                        "message": "分类器就绪，启动 ClockIDS detect...",
                        "stats": {
                            "cpp_packets_seen": 0,
                            "classified_packets": 0,
                            "buf_len": 0,
                        },
                    },
                )

                ndjson_stdout = "-"
                cmd = [
                    settings.CLOCKIDS_BIN_PATH,
                    "detect",
                    "--baseline",
                    settings.CLOCKIDS_BASELINES_CSV_PATH,
                    "--out",
                    ndjson_stdout,
                    "--ndjson",
                ]

                proc = subprocess.Popen(
                    cmd,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1,
                )

                # 避免 C++ 向 stderr 大量输出时管道塞满导致子进程阻塞（Windows 上常见）
                def _drain_stderr() -> None:
                    try:
                        if proc.stderr:
                            proc.stderr.read()
                    except Exception:
                        pass

                threading.Thread(target=_drain_stderr, daemon=True).start()

                stats: Dict[str, int] = {"cpp_packets_seen": 0, "classified_packets": 0}

                def reader():
                    assert proc.stdout is not None
                    buf: List[Dict[str, Any]] = []
                    for line in proc.stdout:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            pkt = json.loads(line)
                        except Exception:
                            continue
                        buf.append(pkt)
                        stats["cpp_packets_seen"] += 1
                        if stats["cpp_packets_seen"] % 50 == 0:
                            _set_session_progress(
                                session_id,
                                {
                                    "stage": "detecting",
                                    "message": "已从 C++ 收到数据流，等待分类缓冲..." ,
                                    "stats": {
                                        "cpp_packets_seen": stats["cpp_packets_seen"],
                                        "classified_packets": stats["classified_packets"],
                                        "buf_len": len(buf),
                                    },
                                },
                            )

                        if len(buf) >= batch_ml_size:
                            _set_session_progress(
                                session_id,
                                {
                                    "stage": "classifying",
                                    "message": f"缓冲满（{len(buf)}），正在分类预测...",
                                    "stats": {
                                        "cpp_packets_seen": stats["cpp_packets_seen"],
                                        "classified_packets": stats["classified_packets"],
                                        "buf_len": len(buf),
                                    },
                                },
                            )
                            preds = classifier.predict_packets(buf)
                            buf.clear()
                            stats["classified_packets"] += len(preds)
                            for p in preds:
                                _append_session_alert(session_id, p)
                            _set_session_progress(
                                session_id,
                                {
                                    "stage": "classifying_done",
                                    "message": f"已输出 {len(preds)} 条告警，继续等待下一批...",
                                    "stats": {
                                        "cpp_packets_seen": stats["cpp_packets_seen"],
                                        "classified_packets": stats["classified_packets"],
                                        "buf_len": len(buf),
                                    },
                                },
                            )
                    if buf:
                        preds = classifier.predict_packets(buf)
                        stats["classified_packets"] += len(preds)
                        buf.clear()
                        for p in preds:
                            _append_session_alert(session_id, p)

                        _set_session_progress(
                            session_id,
                            {
                                "stage": "classifying_done",
                                "message": f"输入结束，补输出 {len(preds)} 条告警...",
                                "stats": {
                                    "cpp_packets_seen": stats["cpp_packets_seen"],
                                    "classified_packets": stats["classified_packets"],
                                    "buf_len": 0,
                                },
                            },
                        )

                t_reader = threading.Thread(target=reader, daemon=True)
                t_reader.start()
                _set_session_progress(
                    session_id,
                    {
                        "stage": "injecting",
                        "message": "开始向 C++ 注入模拟数据流...",
                        "stats": {
                            "cpp_packets_seen": 0,
                            "classified_packets": 0,
                            "buf_len": 0,
                        },
                    },
                )

                assert proc.stdin is not None
                assert stream_iter is not None
                for one_line in stream_iter:
                    proc.stdin.write(one_line + "\n")
                    proc.stdin.flush()
                    if sleep_ms > 0:
                        time.sleep(sleep_ms / 1000.0)
                proc.stdin.close()

                t_reader.join(timeout=3600)
                rc = proc.wait(timeout=60)
                err_msg = None
                if rc != 0:
                    err_msg = f"ClockIDS.exe 退出码 {rc}"
                _set_session_progress(
                    session_id,
                    {
                        "stage": "done",
                        "message": "检测结束，准备返回前端展示...",
                        "stats": {
                            "cpp_packets_seen": stats["cpp_packets_seen"],
                            "classified_packets": stats["classified_packets"],
                            "buf_len": 0,
                        },
                    },
                )
                _set_session_done(session_id, done=True, error=err_msg)
            except Exception as e:
                _set_session_progress(
                    session_id,
                    {
                        "stage": "error",
                        "message": "检测流程异常退出",
                        "stats": {
                            "cpp_packets_seen": 0,
                            "classified_packets": 0,
                            "buf_len": 0,
                        },
                    },
                )
                _set_session_done(session_id, done=True, error=str(e))

        threading.Thread(target=worker, daemon=True).start()
        return JsonResponse({"session_id": session_id}, safe=False)
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=400)


@csrf_exempt
def poll_monitor(request):
    """
    轮询拉取实时告警。
    query:
      session_id=...
      since=0  （可选，表示从 alerts[since] 开始返回）
    """
    try:
        session_id = request.GET.get("session_id", None)
        if not session_id:
            return JsonResponse({"error": "Missing session_id"}, status=400)
        since_str = request.GET.get("since", "0")
        try:
            since = int(since_str)
        except Exception:
            since = 0

        snap = _get_session_snapshot(session_id)
        if not snap:
            return JsonResponse({"error": "Session not found"}, status=404)

        alerts = snap.get("alerts", [])
        done = bool(snap.get("done", False))
        error = snap.get("error", None)
        if since < 0:
            since = 0
        new_alerts = alerts[since:]

        return JsonResponse(
            {
                "session_id": session_id,
                "done": done,
                "error": error,
                "since": since,
                "total": len(alerts),
                "new": new_alerts,
                "ecu_id": snap.get("ecu_id"),
                "cycle": snap.get("cycle"),
                "ecu_ids": snap.get("ecu_ids"),
                "cycles": snap.get("cycles"),
                "chosen_attack_kinds": snap.get("chosen_attack_kinds"),
                "chosen_per_id": snap.get("chosen_per_id"),
                "batch_ml_size": snap.get("batch_ml_size"),
                "progress": snap.get("progress"),
            },
            safe=False,
        )
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=400)
