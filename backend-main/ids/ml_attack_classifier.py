import json
import os
import subprocess
import tempfile
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import joblib
from sklearn.ensemble import RandomForestClassifier

from .attack_generator import (
    DEFAULT_ATTACK_KINDS,
    build_stream_text,
    generate_attack_stream_csv,
    generate_ethernet_chain_stream_csv,
    generate_multi_id_mixed_stream,
    generate_mixed_attack_stream_csv,
    load_baselines_csv,
    pick_multiple_baselines,
    pick_valid_id_by_ecu,
)

FEATURE_VERSION = 5

# 低置信度时不要硬输出某个攻击类型（0 表示关闭；需要时再打开）
MIN_CONFIDENCE_FOR_LABEL = 0.0


def extract_features(packet: Dict[str, Any]) -> List[float]:
    """
    从 ClockIDS.cpp 的 attack_packets.json 单条告警提取特征。
    """
    import math

    mean_skew = float(packet.get("mean_skew", 0.0))
    stddev_skew = float(packet.get("stddev_skew", 0.0))
    duration = float(packet.get("duration", 0.0))
    frame_count = float(packet.get("frame_count", 0.0))
    cycle = float(packet.get("cycle", 0.0) or 0.0)
    residual_min = float(packet.get("residual_min", 0.0))
    residual_max = float(packet.get("residual_max", 0.0))

    # 可选：序列特征（ClockIDS.cpp 输出 ts_series / residual_series）
    # 注意：views.py 可能会截断 series，所以这里只取稳健统计量。
    residual_series = packet.get("residual_series") or packet.get("attack_residual_series") or []
    ts_series = packet.get("ts_series") or packet.get("attack_ts_series") or []
    try:
        residual_series = [float(x) for x in residual_series]
    except Exception:
        residual_series = []
    try:
        ts_series = [float(x) for x in ts_series]
    except Exception:
        ts_series = []

    abs_mean = abs(mean_skew)
    abs_std = abs(stddev_skew)
    eps = 1e-9

    # 直觉：
    # - DoS 更像“周期整体偏移”：mean_skew / duration / rate 有明显特征
    # - RPM/gear 更像“随时间变化”：std 与 mean 的比值、每帧平均间隔等更有区分度
    # - Fuzzy 更像“高方差噪声”：abs_std、std/mean 更突出
    rate = frame_count / max(eps, duration)
    dur_per_frame = duration / max(1.0, frame_count)
    mean_over_std = mean_skew / max(eps, abs_std)
    std_over_abs_mean = abs_std / max(eps, abs_mean)
    mean_norm = mean_skew / max(eps, cycle) if cycle > 0 else 0.0
    std_norm = stddev_skew / max(eps, cycle) if cycle > 0 else 0.0

    def _quantile(xs: List[float], q: float) -> float:
        if not xs:
            return 0.0
        ys = sorted(xs)
        if len(ys) == 1:
            return float(ys[0])
        pos = q * (len(ys) - 1)
        lo = int(pos)
        hi = min(len(ys) - 1, lo + 1)
        frac = pos - lo
        return float(ys[lo] * (1.0 - frac) + ys[hi] * frac)

    # residual 的稳健统计：分位数、幅度、均值/方差、线性趋势
    res_p25 = _quantile(residual_series, 0.25)
    res_p50 = _quantile(residual_series, 0.50)
    res_p75 = _quantile(residual_series, 0.75)
    res_iqr = res_p75 - res_p25
    res_range = residual_max - residual_min
    if residual_series:
        res_mean = float(sum(residual_series) / len(residual_series))
        res_var = float(sum((x - res_mean) ** 2 for x in residual_series) / max(1, len(residual_series)))
        res_std = float(math.sqrt(max(0.0, res_var)))
        res_abs_mean = float(sum(abs(x) for x in residual_series) / len(residual_series))
    else:
        res_mean = 0.0
        res_std = 0.0
        res_abs_mean = 0.0

    # 线性趋势：residual ~ a * t + b（用最小二乘的闭式解）
    # 仅当序列长度足够且时间单调时才计算，否则置 0。
    slope = 0.0
    if len(residual_series) >= 6 and len(ts_series) == len(residual_series):
        t0 = ts_series[0]
        ts = [t - t0 for t in ts_series]
        t_mean = float(sum(ts) / len(ts))
        y_mean = float(sum(residual_series) / len(residual_series))
        s_tt = float(sum((t - t_mean) ** 2 for t in ts))
        if s_tt > eps:
            s_ty = float(sum((ts[i] - t_mean) * (residual_series[i] - y_mean) for i in range(len(ts))))
            slope = float(s_ty / s_tt)

    # 时间间隔特征：直接反映 DoS/Fuzzy/gear/RPM 的“间隔模式”
    dt_mean = 0.0
    dt_std = 0.0
    dt_p25 = 0.0
    dt_p50 = 0.0
    dt_p75 = 0.0
    dt_range = 0.0
    dt_norm_mean = 0.0
    dt_norm_std = 0.0
    if len(ts_series) >= 3:
        dts = [ts_series[i] - ts_series[i - 1] for i in range(1, len(ts_series))]
        dts = [float(x) for x in dts if x > 0]
        if dts:
            dt_mean = float(sum(dts) / len(dts))
            dt_var = float(sum((x - dt_mean) ** 2 for x in dts) / max(1, len(dts)))
            dt_std = float(math.sqrt(max(0.0, dt_var)))
            dt_p25 = _quantile(dts, 0.25)
            dt_p50 = _quantile(dts, 0.50)
            dt_p75 = _quantile(dts, 0.75)
            dt_range = float(max(dts) - min(dts))
            if cycle > 0:
                dt_norm_mean = float(dt_mean / max(eps, cycle))
                dt_norm_std = float(dt_std / max(eps, cycle))

    return [
        mean_skew,
        stddev_skew,
        duration,
        frame_count,
        abs_mean,
        abs_std,
        math.log1p(max(0.0, duration)),
        math.log1p(max(0.0, frame_count)),
        rate,
        dur_per_frame,
        mean_over_std,
        std_over_abs_mean,
        float(mean_skew >= 0.0),
        cycle,
        mean_norm,
        std_norm,
        residual_min,
        residual_max,
        res_range,
        res_p25,
        res_p50,
        res_p75,
        res_iqr,
        res_mean,
        res_std,
        res_abs_mean,
        slope,
        dt_mean,
        dt_std,
        dt_p25,
        dt_p50,
        dt_p75,
        dt_range,
        dt_norm_mean,
        dt_norm_std,
    ]


def _parse_stream_lines_timestamp_id(lines: List[str]) -> List[Tuple[float, str]]:
    """
    与 ClockIDS.cpp parse_csv_line 一致：每行 "<timestamp>,<ecu_id>"
    用于训练时定位“生成器定义的期望攻击段边界”，再从多段检测中选最佳样本。
    """
    out: List[Tuple[float, str]] = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        parts = line.split(",")
        if len(parts) < 2:
            continue
        ts_s = parts[0]
        id_s = parts[1]
        out.append((float(ts_s), id_s))
    return out


def _overlap_len(a_start: float, a_end: float, b_start: float, b_end: float) -> float:
    return max(0.0, min(a_end, b_end) - max(a_start, b_start))


def _ensure_baselines_exist(
    *,
    clockids_bin_path: str,
    normal_data_path: str,
    baselines_csv_path: str,
    force_retrain_baselines: bool = False,
) -> None:
    if (not force_retrain_baselines) and os.path.exists(baselines_csv_path):
        return

    os.makedirs(os.path.dirname(baselines_csv_path), exist_ok=True)
    cmd = [
        clockids_bin_path,
        "train",
        "--normal",
        normal_data_path,
        "--out-baselines",
        baselines_csv_path,
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(
            "ClockIDS train failed:\n"
            f"cmd={cmd}\n"
            f"stdout={proc.stdout}\n"
            f"stderr={proc.stderr}\n"
        )


def _run_clockids_detect_on_stream(
    *,
    clockids_bin_path: str,
    baselines_csv_path: str,
    stream_text: str,
    out_json_path: str,
    cwd: Optional[str] = None,
) -> None:
    cmd = [
        clockids_bin_path,
        "detect",
        "--baseline",
        baselines_csv_path,
        "--out",
        out_json_path,
    ]
    proc = subprocess.run(
        cmd,
        input=stream_text.encode("utf-8"),
        capture_output=True,
        cwd=cwd,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            "ClockIDS detect failed:\n"
            f"cmd={cmd}\n"
            f"stdout={proc.stdout.decode('utf-8', errors='ignore')}\n"
            f"stderr={proc.stderr.decode('utf-8', errors='ignore')}\n"
        )


def _load_attack_packets_json(uploaded: Any) -> List[Dict[str, Any]]:
    """
    C++ 输出格式：JSON 数组，元素是每个告警对象。
    """
    if isinstance(uploaded, list):
        return uploaded
    if isinstance(uploaded, dict) and "attack_packets" in uploaded:
        return uploaded["attack_packets"]
    raise ValueError("attack_packets.json format should be a JSON array.")


@dataclass
class AttackClassifierArtifacts:
    labels: List[str]
    model: Any
    pre_frames: Optional[int] = None
    attack_frames: Optional[int] = None
    post_frames: Optional[int] = None


class AttackClassifierService:
    def __init__(
        self,
        *,
        clockids_bin_path: str,
        normal_data_path: str,
        baselines_csv_path: str,
        model_path: str,
        labels: Optional[Sequence[str]] = None,
    ):
        self.clockids_bin_path = clockids_bin_path
        self.normal_data_path = normal_data_path
        self.baselines_csv_path = baselines_csv_path
        self.model_path = model_path
        self.labels = list(labels) if labels is not None else list(DEFAULT_ATTACK_KINDS)
        self._cached_artifacts: Optional[AttackClassifierArtifacts] = None

    def _load_artifacts(self) -> AttackClassifierArtifacts:
        if self._cached_artifacts is not None:
            return self._cached_artifacts
        data = joblib.load(self.model_path)
        self._cached_artifacts = AttackClassifierArtifacts(
            labels=data.get("labels", []),
            model=data.get("model"),
            pre_frames=data.get("pre_frames"),
            attack_frames=data.get("attack_frames"),
            post_frames=data.get("post_frames"),
        )
        return self._cached_artifacts

    def ensure_trained(
        self,
        *,
        pre_frames: int = 120,
        attack_frames: int = 180,
        post_frames: int = 120,
        samples_per_class: int = 80,
        max_total_samples: int = 1200,
        random_seed: int = 42,
        force_retrain: bool = False,
    ) -> None:
        if (not force_retrain) and os.path.exists(self.model_path):
            # 如果已有模型但其训练参数不匹配，就需要重训，避免特征分布漂移导致准确率下降
            try:
                existing = joblib.load(self.model_path)
                pre_ok = existing.get("pre_frames") == pre_frames
                attack_ok = existing.get("attack_frames") == attack_frames
                post_ok = existing.get("post_frames") == post_frames
                labels_ok = list(existing.get("labels", [])) == list(self.labels)
                feat_ok = int(existing.get("feature_version", 0)) == int(FEATURE_VERSION)
                if pre_ok and attack_ok and post_ok and labels_ok and feat_ok:
                    return
            except Exception:
                pass

        _ensure_baselines_exist(
            clockids_bin_path=self.clockids_bin_path,
            normal_data_path=self.normal_data_path,
            baselines_csv_path=self.baselines_csv_path,
            force_retrain_baselines=force_retrain,
        )

        baselines = load_baselines_csv(self.baselines_csv_path)
        target = pick_valid_id_by_ecu(baselines, None)
        if not target:
            raise RuntimeError("No valid baseline id found. Cannot train classifier.")

        ecu_id = target["id"]
        cycle = target["cycle"]

        X: List[List[float]] = []
        y: List[str] = []

        # 与 generate_mixed_attack_stream_csv 默认 gap_frames 逻辑一致
        gap_frames = max(20, int(attack_frames * 0.4))
        num_attacks_for_training = 6

        import random

        random.seed(random_seed)

        def _expected_segments_for_mixed(ts_only: List[float], chosen: Sequence[str]) -> List[Tuple[str, float, float]]:
            segs: List[Tuple[str, float, float]] = []
            for i, kind in enumerate(chosen):
                seg_start_idx = pre_frames + i * (attack_frames + gap_frames)
                seg_end_idx = seg_start_idx + attack_frames - 1
                if seg_end_idx >= len(ts_only):
                    break
                segs.append((str(kind), float(ts_only[seg_start_idx]), float(ts_only[seg_end_idx])))
            return segs

        def _expected_segments_for_ethernet_chain(ts_only: List[float], segments_meta: Sequence[Dict[str, Any]]) -> List[Tuple[str, float, float]]:
            # segments_meta 里有 actual_start_ts（进入攻击段前的 t），用 ts_only 找到对应帧索引再取 attack_frames 长度
            segs: List[Tuple[str, float, float]] = []
            for seg in segments_meta:
                kind = str(seg.get("kind", ""))
                start_hint = float(seg.get("actual_start_ts", 0.0))
                # 找到第一个 ts >= start_hint 的索引
                idx = 0
                while idx < len(ts_only) and ts_only[idx] < start_hint:
                    idx += 1
                seg_start_idx = min(max(0, idx), max(0, len(ts_only) - 1))
                seg_end_idx = seg_start_idx + attack_frames - 1
                if seg_end_idx >= len(ts_only):
                    break
                segs.append((kind, float(ts_only[seg_start_idx]), float(ts_only[seg_end_idx])))
            return segs

        # 训练数据来自“后端数据生成器 + C++ 检测输出”
        for label in self.labels:
            per_class = 0
            tries = 0
            while per_class < samples_per_class and tries < samples_per_class * 6:
                tries += 1
                with tempfile.NamedTemporaryFile(
                    mode="w+b",
                    suffix=".json",
                    delete=False,
                ) as tmp:
                    out_json_path = tmp.name

                try:
                    # 为了匹配线上分布：混合三类数据源
                    # 1) single：纯净样本（稳定）
                    # 2) mixed：带 gap 的连续多段（更接近你现在的 Mixed）
                    # 3) multi_id_mixed：多 ID 交错 + 多段（逼近线上 multi-id 分布）
                    # 4) ethernet_chain：按以太网异常/正常时间驱动（更接近你的“完整攻击链”）
                    mode_pick = random.random()
                    expected_segments: List[Tuple[float, float]] = []
                    multi_expected: List[Tuple[str, float, float, str]] = []

                    if mode_pick < 0.40:
                        stream_iter = generate_attack_stream_csv(
                            ecu_id=ecu_id,
                            cycle=cycle,
                            attack_kind=label,
                            start_ts=0.0,
                            pre_frames=pre_frames,
                            attack_frames=attack_frames,
                            post_frames=post_frames,
                            seed=random.randint(0, 10**9),
                        )
                        stream_lines = list(stream_iter)
                        parsed = _parse_stream_lines_timestamp_id(stream_lines)
                        ts_only = [ts for (ts, eid) in parsed if str(eid) == str(ecu_id)]
                        if len(ts_only) < pre_frames + attack_frames:
                            continue
                        expected_segments = [(ts_only[pre_frames], ts_only[pre_frames + attack_frames - 1])]

                    elif mode_pick < 0.75:
                        it, chosen = generate_mixed_attack_stream_csv(
                            ecu_id,
                            cycle,
                            attack_kinds=self.labels,
                            num_attacks=num_attacks_for_training,
                            start_ts=0.0,
                            pre_frames=pre_frames,
                            attack_frames=attack_frames,
                            gap_frames=gap_frames,
                            post_frames=post_frames,
                            seed=random.randint(0, 10**9),
                        )
                        stream_lines = list(it)
                        parsed = _parse_stream_lines_timestamp_id(stream_lines)
                        ts_only = [ts for (ts, eid) in parsed if str(eid) == str(ecu_id)]
                        if len(ts_only) < pre_frames + attack_frames:
                            continue
                        segs = _expected_segments_for_mixed(ts_only, chosen)
                        # 只取属于当前 label 的期望段
                        expected_segments = [(s, e) for (k, s, e) in segs if str(k) == str(label)]
                        if not expected_segments:
                            continue

                    elif mode_pick < 0.90:
                        # multi_id_mixed：从 baselines 里挑 3 个 ID，生成多 ID 交错 + 多段
                        rows = pick_multiple_baselines(baselines, ecu_ids=None, num_ids=3)
                        if len(rows) < 2:
                            continue
                        merged_iter, meta = generate_multi_id_mixed_stream(
                            baseline_rows=rows,
                            attack_kinds=self.labels,
                            num_attacks=num_attacks_for_training,
                            pre_frames=pre_frames,
                            attack_frames=attack_frames,
                            post_frames=post_frames,
                            seed=random.randint(0, 10**9),
                        )
                        stream_lines = list(merged_iter)
                        parsed = _parse_stream_lines_timestamp_id(stream_lines)

                        # per id 的 ts_only
                        id_to_ts: Dict[str, List[float]] = {str(r["id"]): [] for r in meta}
                        for ts, eid in parsed:
                            sid = str(eid)
                            if sid in id_to_ts:
                                id_to_ts[sid].append(float(ts))

                        meta_by_id: Dict[str, List[str]] = {str(m["id"]): list(m.get("chosen_attack_kinds", [])) for m in meta}
                        min_needed = pre_frames + num_attacks_for_training * attack_frames + (num_attacks_for_training - 1) * gap_frames + post_frames

                        # multi_expected: (sid, start, end, kind)
                        for row in rows:
                            sid = str(row["id"])
                            chosen = meta_by_id.get(sid, [])
                            ts_only = id_to_ts.get(sid, [])
                            if len(chosen) < num_attacks_for_training or len(ts_only) < min_needed:
                                continue
                            for i in range(num_attacks_for_training):
                                seg_start_idx = pre_frames + i * attack_frames + i * gap_frames
                                seg_end_idx = seg_start_idx + attack_frames - 1
                                if seg_end_idx >= len(ts_only):
                                    break
                                kind = str(chosen[i])
                                if kind != str(label):
                                    continue
                                multi_expected.append((sid, float(ts_only[seg_start_idx]), float(ts_only[seg_end_idx]), kind))
                        if not multi_expected:
                            continue

                    else:
                        # ethernet_chain：默认用 settings 里的 ETHERNET_DEFAULT_CSV_PATH；若不存在就退化为 mixed
                        try:
                            from django.conf import settings as dj_settings
                        except Exception:
                            dj_settings = None
                        eth_csv = ""
                        if dj_settings is not None:
                            eth_csv = str(getattr(dj_settings, "ETHERNET_DEFAULT_CSV_PATH", "")).strip()
                        if not eth_csv:
                            continue
                        it, seg_meta = generate_ethernet_chain_stream_csv(
                            ecu_id,
                            cycle,
                            ethernet_csv_path=eth_csv,
                            attack_kinds=self.labels,
                            num_attacks=num_attacks_for_training,
                            after_abnormal_ratio=0.6,
                            start_ts=0.0,
                            pre_frames=pre_frames,
                            attack_frames=attack_frames,
                            gap_frames=gap_frames,
                            post_frames=post_frames,
                            seed=random.randint(0, 10**9),
                        )
                        stream_lines = list(it)
                        parsed = _parse_stream_lines_timestamp_id(stream_lines)
                        ts_only = [ts for (ts, eid) in parsed if str(eid) == str(ecu_id)]
                        if len(ts_only) < pre_frames + attack_frames:
                            continue
                        segs = _expected_segments_for_ethernet_chain(ts_only, seg_meta)
                        expected_segments = [(s, e) for (k, s, e) in segs if str(k) == str(label)]
                        if not expected_segments:
                            continue

                    stream_text = build_stream_text(stream_lines)

                    _run_clockids_detect_on_stream(
                        clockids_bin_path=self.clockids_bin_path,
                        baselines_csv_path=self.baselines_csv_path,
                        stream_text=stream_text,
                        out_json_path=out_json_path,
                        cwd=None,
                    )

                    with open(out_json_path, "r", encoding="utf-8") as f:
                        packets = json.load(f)
                    if not isinstance(packets, list) or len(packets) == 0:
                        continue

                    # 训练：对每个期望攻击段（该流里真实属于当前 label 的段）
                    # 从多段检测告警中选“重叠最大”的那段加入训练。
                    used_indices = set()
                    # multi-id：按 sid 精确匹配
                    if multi_expected:
                        for sid, exp_start_ts, exp_end_ts, _k in multi_expected:
                            best_pkt = None
                            best_overlap = -1.0
                            best_i = -1
                            for i, pkt in enumerate(packets):
                                if str(pkt.get("attack_id", "")) != str(sid):
                                    continue
                                if i in used_indices:
                                    continue
                                start = float(pkt.get("start_time", 0.0))
                                end = float(pkt.get("end_time", 0.0))
                                overlap = _overlap_len(exp_start_ts, exp_end_ts, start, end)
                                if overlap > best_overlap:
                                    best_overlap = overlap
                                    best_pkt = pkt
                                    best_i = i
                            if best_pkt is None or best_overlap <= 0:
                                continue
                            used_indices.add(best_i)
                            X.append(extract_features(best_pkt))
                            y.append(label)
                            per_class += 1
                            if per_class >= samples_per_class:
                                break

                    for exp_start_ts, exp_end_ts in expected_segments:
                        best_pkt = None
                        best_overlap = -1.0
                        best_i = -1
                        for i, pkt in enumerate(packets):
                            if str(pkt.get("attack_id", "")) != str(ecu_id):
                                continue
                            if i in used_indices:
                                continue
                            start = float(pkt.get("start_time", 0.0))
                            end = float(pkt.get("end_time", 0.0))
                            overlap = _overlap_len(
                                exp_start_ts,
                                exp_end_ts,
                                start,
                                end,
                            )
                            if overlap > best_overlap:
                                best_overlap = overlap
                                best_pkt = pkt
                                best_i = i

                        if best_pkt is None or best_overlap <= 0:
                            continue
                        used_indices.add(best_i)
                        X.append(extract_features(best_pkt))
                        y.append(label)
                        per_class += 1
                        if per_class >= samples_per_class:
                            break

                    if per_class == 0:
                        continue

                    if len(X) >= max_total_samples:
                        break
                finally:
                    try:
                        os.remove(out_json_path)
                    except OSError:
                        pass

                if len(X) >= max_total_samples:
                    break

        if len(X) < max(10, len(self.labels) * 3):
            raise RuntimeError(
                f"Not enough training samples collected: {len(X)}."
            )

        # 随机森林起步简单、对非线性特征鲁棒
        model = RandomForestClassifier(
            n_estimators=600,
            random_state=random_seed,
            class_weight="balanced",
            min_samples_leaf=2,
            n_jobs=-1,
        )
        model.fit(X, y)

        artifacts = {
            "labels": list(self.model_labels()),
            "model": model,
            "pre_frames": pre_frames,
            "attack_frames": attack_frames,
            "post_frames": post_frames,
            "feature_version": int(FEATURE_VERSION),
        }
        joblib.dump(artifacts, self.model_path)

    def model_labels(self) -> Iterable[str]:
        # sklearn 会用 y 的唯一值作为 classes_，这里保持和 labels 对齐
        return self.labels

    def predict_packets(self, packets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        artifacts = self._load_artifacts()
        model = artifacts.model

        X = [extract_features(p) for p in packets]
        if not X:
            return []

        proba = model.predict_proba(X)
        preds = model.predict(X)

        classes = list(getattr(model, "classes_", []))
        results: List[Dict[str, Any]] = []
        for i, pkt in enumerate(packets):
            # 最高概率对应类别（置信度）
            idx = int(proba[i].argmax())
            conf = float(proba[i][idx])
            prob_by_class = {str(classes[j]): float(proba[i][j]) for j in range(len(classes))}
            pred_label = str(preds[i])
            if conf < MIN_CONFIDENCE_FOR_LABEL:
                pred_label = "unknown"
            results.append(
                {
                    "attack_type": pred_label,
                    "confidence": conf,
                    "probabilities": prob_by_class,
                    "features": {
                        "mean_skew": float(pkt.get("mean_skew", 0.0)),
                        "stddev_skew": float(pkt.get("stddev_skew", 0.0)),
                        "duration": float(pkt.get("duration", 0.0)),
                        "frame_count": int(pkt.get("frame_count", 0)),
                    },
                    "detail": pkt,
                }
            )
        return results

    def predict_packet(self, packet: Dict[str, Any]) -> Dict[str, Any]:
        """
        单条告警包预测：用于实时流式场景，避免反复处理列表。
        """
        artifacts = self._load_artifacts()
        model = artifacts.model

        X = [extract_features(packet)]
        proba = model.predict_proba(X)[0]
        pred = model.predict(X)[0]
        idx = int(proba.argmax())
        classes = list(getattr(model, "classes_", []))
        conf = float(proba[idx])
        prob_by_class = {str(classes[i]): float(proba[i]) for i in range(len(classes))}
        pred_label = str(pred)
        if conf < MIN_CONFIDENCE_FOR_LABEL:
            pred_label = "unknown"

        return {
            "attack_type": pred_label,
            "confidence": conf,
            "probabilities": prob_by_class,
            "features": {
                "mean_skew": float(packet.get("mean_skew", 0.0)),
                "stddev_skew": float(packet.get("stddev_skew", 0.0)),
                "duration": float(packet.get("duration", 0.0)),
                "frame_count": int(packet.get("frame_count", 0)),
            },
            "detail": packet,
        }


def classify_uploaded_attack_packets_json(
    *,
    classifier: AttackClassifierService,
    uploaded_json: Any,
    training_if_missing: bool = True,
) -> List[Dict[str, Any]]:
    packets = _load_attack_packets_json(uploaded_json)
    if training_if_missing:
        classifier.ensure_trained()
    return classifier.predict_packets(packets)

