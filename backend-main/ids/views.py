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
        classifier.ensure_trained()

        # 需要 baselines.csv，否则 detect 无法运行
        # ensure_trained 内部已保证 baselines 存在，这里再读一次拿到 cycle/id
        from .attack_generator import (
            load_baselines_csv,
            pick_first_valid_id,
            generate_attack_stream_csv,
            generate_mixed_attack_stream_csv,
            build_stream_text,
        )

        baselines = load_baselines_csv(settings.CLOCKIDS_BASELINES_CSV_PATH)
        target = pick_first_valid_id(baselines)
        if not target:
            return JsonResponse({"error": "No valid baseline id found."}, status=400)

        ecu_id = target["id"]
        cycle = target["cycle"]

        pre_frames = int(body.get("pre_frames", 240))
        attack_frames = int(body.get("attack_frames", 220))
        post_frames = int(body.get("post_frames", 240))
        num_attacks = int(body.get("num_attacks", 4))
        seed = body.get("seed", None)

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
        "num_attacks": 4,
        "pre_frames": 240,
        "attack_frames": 220,
        "post_frames": 240,
        "sleep_ms": 1                      // 每发送一行到stdin的延迟，用于模拟实时
      }
    """
    try:
        body = {}
        if request.body:
            body = json.loads(request.body.decode("utf-8", errors="ignore"))

        mode = body.get("mode", "mixed")
        attack_kind = body.get("attack_kind", None)
        attack_kinds = body.get("attack_kinds", ["DoS", "Fuzzy", "gear", "RPM"])
        num_attacks = int(body.get("num_attacks", 4))
        pre_frames = int(body.get("pre_frames", 240))
        attack_frames = int(body.get("attack_frames", 220))
        post_frames = int(body.get("post_frames", 240))
        sleep_ms = float(body.get("sleep_ms", 1.0))

        from .attack_generator import (
            load_baselines_csv,
            pick_first_valid_id,
            generate_attack_stream_csv,
            generate_mixed_attack_stream_csv,
        )

        # 先选一个可用 ID / cycle（供生成器使用）
        baselines = load_baselines_csv(settings.CLOCKIDS_BASELINES_CSV_PATH)
        target = pick_first_valid_id(baselines)
        if not target:
            return JsonResponse({"error": "No valid baseline id found."}, status=400)
        ecu_id = target["id"]
        cycle = float(target["cycle"])

        session_id = uuid.uuid4().hex
        with _monitor_sessions_lock:
            _monitor_sessions[session_id] = {
                "alerts": [],
                "done": False,
                "error": None,
                "created_at": time.time(),
                "ecu_id": ecu_id,
                "cycle": cycle,
                "mode": mode,
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
                classifier.ensure_trained()

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

                # 生成器产生数据流（逐行写入 stdin）
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
                    )
                elif mode == "mixed":
                    stream_iter, _chosen = generate_mixed_attack_stream_csv(
                        ecu_id,
                        cycle,
                        attack_kinds=attack_kinds,
                        num_attacks=num_attacks,
                        start_ts=0.0,
                        pre_frames=pre_frames,
                        attack_frames=attack_frames,
                        post_frames=post_frames,
                    )
                else:
                    raise ValueError("Invalid mode, use mode='single' or 'mixed'.")

                proc = subprocess.Popen(
                    cmd,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1,
                )

                def reader():
                    assert proc.stdout is not None
                    for line in proc.stdout:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            pkt = json.loads(line)
                        except Exception:
                            # 忽略非 JSON 行（理论上 NDJSON 模式下 stdout 应只包含对象）
                            continue
                        pred = classifier.predict_packet(pkt)
                        _append_session_alert(session_id, pred)

                t_reader = threading.Thread(target=reader, daemon=True)
                t_reader.start()

                assert proc.stdin is not None
                for one_line in stream_iter:
                    proc.stdin.write(one_line + "\n")
                    proc.stdin.flush()
                    if sleep_ms > 0:
                        time.sleep(sleep_ms / 1000.0)
                proc.stdin.close()

                t_reader.join(timeout=1200)
                _set_session_done(session_id, done=True)

                # 读取 stderr，避免子进程残留管道导致异常
                try:
                    err_txt = proc.stderr.read().decode("utf-8", errors="ignore") if proc.stderr else ""
                    # stderr 已经读完但不用返回，留作排查
                except Exception:
                    pass
            except Exception as e:
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
            },
            safe=False,
        )
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=400)
