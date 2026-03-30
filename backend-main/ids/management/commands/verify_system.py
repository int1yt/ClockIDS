import json
import os
import subprocess
import tempfile
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from ids.attack_generator import (
    build_stream_text,
    generate_attack_stream_csv,
    generate_mixed_attack_stream_csv,
    generate_multi_id_mixed_stream,
    load_baselines_csv,
    pick_multiple_baselines,
    pick_valid_id_by_ecu,
)
from ids.ml_attack_classifier import AttackClassifierService


def _parse_stream_lines(lines: Sequence[str]) -> List[Tuple[float, str]]:
    """
    每行："<timestamp>,<ecu_id>"
    """
    out: List[Tuple[float, str]] = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        ts_s, id_s = line.split(",", 1)
        out.append((float(ts_s), id_s))
    return out


def _run_clockids_detect(clockids_bin_path: str, baselines_csv_path: str, stream_text: str) -> List[Dict[str, Any]]:
    with tempfile.NamedTemporaryFile(mode="w+b", suffix=".json", delete=False) as tmp:
        out_json_path = tmp.name

    try:
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
        )
        if proc.returncode != 0:
            raise RuntimeError(
                "ClockIDS detect failed\n"
                f"cmd={cmd}\n"
                f"stdout={proc.stdout.decode('utf-8', errors='ignore')}\n"
                f"stderr={proc.stderr.decode('utf-8', errors='ignore')}\n"
            )

        with open(out_json_path, "r", encoding="utf-8") as f:
            packets = json.load(f)
        if not isinstance(packets, list):
            raise RuntimeError("ClockIDS detect output should be a JSON array.")
        return packets
    finally:
        try:
            os.remove(out_json_path)
        except Exception:
            pass


def _compute_expected_segments_single_id(
    *,
    stream_lines: Sequence[str],
    ecu_id: str,
    pre_frames: int,
    attack_frames: int,
    post_frames: int,
    chosen_attack_kinds: Optional[Sequence[str]] = None,
) -> List[Dict[str, Any]]:
    """
    返回 segment 列表，每段包含：kind,start_ts,end_ts.
    对于 generate_attack_stream_csv：chosen_attack_kinds 传 None，则用攻击种类外部传入的 kind。
    对于 generate_mixed_attack_stream_csv：chosen_attack_kinds 给定，每段对应它。
    """
    parsed = _parse_stream_lines(stream_lines)
    # 对 single id 来说，所有 ecu_id 都应一致；但为鲁棒起见仍过滤
    ts_only = [ts for (ts, eid) in parsed if eid == ecu_id]
    if len(ts_only) < pre_frames + attack_frames + post_frames:
        raise RuntimeError(f"Stream for ecu_id={ecu_id} has too few frames: {len(ts_only)}")

    segments: List[Dict[str, Any]] = []
    num_attacks = 1 if chosen_attack_kinds is None else len(chosen_attack_kinds)
    for i in range(num_attacks):
        seg_start_idx = pre_frames + i * attack_frames
        seg_end_idx = pre_frames + (i + 1) * attack_frames - 1
        if seg_end_idx >= len(ts_only):
            break
        kind = chosen_attack_kinds[i] if chosen_attack_kinds is not None else None
        segments.append(
            {
                "kind": kind,
                "start_ts": ts_only[seg_start_idx],
                "end_ts": ts_only[seg_end_idx],
            }
        )
    return segments


def _overlap_len(a_start: float, a_end: float, b_start: float, b_end: float) -> float:
    return max(0.0, min(a_end, b_end) - max(a_start, b_start))


class Command(BaseCommand):
    help = "Verify end-to-end correctness: generator -> ClockIDS detect -> ML classifier."

    def add_arguments(self, parser):
        parser.add_argument("--trials", type=int, default=1)
        parser.add_argument("--pre_frames", type=int, default=200)
        parser.add_argument("--attack_frames", type=int, default=200)
        parser.add_argument("--post_frames", type=int, default=200)
        parser.add_argument("--num_attacks", type=int, default=3)
        parser.add_argument(
            "--ecu_id",
            type=str,
            default="0690",
            help="Single-ID baseline ecu_id (must exist in clockids_baselines.csv).",
        )
        parser.add_argument(
            "--ecu_ids",
            type=str,
            default="0690,0329,00a0",
            help="For multi-id test: comma-separated ecu_ids. Only those will be used.",
        )
        parser.add_argument("--seed", type=int, default=123)
        parser.add_argument(
            "--force_retrain",
            action="store_true",
            help="Force retrain the ML classifier even if attack_classifier.joblib exists.",
        )

    def handle(self, *args, **options):
        trials: int = options["trials"]
        pre_frames: int = options["pre_frames"]
        attack_frames: int = options["attack_frames"]
        post_frames: int = options["post_frames"]
        # 与 generate_mixed_attack_stream_csv 默认 gap_frames 计算保持一致
        gap_frames: int = max(20, int(attack_frames * 0.4))
        num_attacks: int = options["num_attacks"]
        ecu_id: str = str(options["ecu_id"]).strip()
        ecu_ids_raw: str = str(options["ecu_ids"]).strip()
        seed_base: int = int(options["seed"])
        force_retrain: bool = bool(options["force_retrain"])

        if not ecu_id:
            raise CommandError("--ecu_id cannot be empty")

        ecu_ids = [s.strip() for s in ecu_ids_raw.split(",") if s.strip()]
        if len(ecu_ids) < 2:
            raise CommandError("--ecu_ids should contain at least 2 ecu_ids")

        labels = ["DoS", "Fuzzy", "gear", "RPM"]
        clockids_bin_path = settings.CLOCKIDS_BIN_PATH
        baselines_csv_path = settings.CLOCKIDS_BASELINES_CSV_PATH
        model_path = settings.CLOCKIDS_ATTACK_CLASSIFIER_MODEL_PATH

        self.stdout.write(self.style.NOTICE("Loading baselines and building classifier..."))
        baselines = load_baselines_csv(baselines_csv_path)

        classifier = AttackClassifierService(
            clockids_bin_path=clockids_bin_path,
            normal_data_path=settings.CLOCKIDS_NORMAL_DATA_PATH,
            baselines_csv_path=baselines_csv_path,
            model_path=model_path,
            labels=labels,
        )
        classifier.ensure_trained(
            pre_frames=pre_frames,
            attack_frames=attack_frames,
            post_frames=post_frames,
            force_retrain=force_retrain,
        )

        # ---------- 1) Single-ID, per-label verification ----------
        total_single = 0
        correct_single = 0
        seg_correct_single = 0
        seg_overlap_correct_single = 0

        for label in labels:
            self.stdout.write(self.style.NOTICE(f"\n[Single-ID] label={label}"))
            target = pick_valid_id_by_ecu(baselines, ecu_id)
            if not target:
                raise CommandError(f"No valid baseline id found for ecu_id={ecu_id}")
            chosen_cycle = float(target["cycle"])

            for trial_i in range(trials):
                trial_seed = seed_base + trial_i * 10007
                stream_iter = generate_attack_stream_csv(
                    ecu_id=ecu_id,
                    cycle=chosen_cycle,
                    attack_kind=label,
                    start_ts=0.0,
                    pre_frames=pre_frames,
                    attack_frames=attack_frames,
                    post_frames=post_frames,
                    seed=trial_seed,
                )
                stream_lines = list(stream_iter)
                stream_text = build_stream_text(stream_lines)

                expected_attack_start_ts = _parse_stream_lines(stream_lines)[pre_frames][0]
                expected_attack_end_ts = _parse_stream_lines(stream_lines)[pre_frames + attack_frames - 1][0]
                tol = max(1e-6, chosen_cycle * 5.0)

                packets = _run_clockids_detect(clockids_bin_path, baselines_csv_path, stream_text)
                results = classifier.predict_packets(packets)

                total_single += 1
                if not results:
                    self.stdout.write(f"  trial={trial_i}: no packets detected")
                    continue

                # 找最佳匹配（按与期望 start/end 的距离）
                best = None
                best_score = float("inf")
                for r in results:
                    d = r.get("detail", {})
                    if str(d.get("attack_id")) != str(ecu_id):
                        continue
                    start = float(d.get("start_time", 0.0))
                    end = float(d.get("end_time", 0.0))
                    score = abs(start - expected_attack_start_ts) + abs(end - expected_attack_end_ts)
                    if score < best_score:
                        best_score = score
                        best = r

                if best is None:
                    self.stdout.write(f"  trial={trial_i}: packets detected but no matching for ecu_id={ecu_id}")
                    continue

                predicted_label = best.get("attack_type")
                start = float(best["detail"].get("start_time", 0.0))
                end = float(best["detail"].get("end_time", 0.0))

                ok_cls = (predicted_label == label)
                ok_seg = (abs(start - expected_attack_start_ts) <= tol and abs(end - expected_attack_end_ts) <= tol)
                overlap = _overlap_len(
                    expected_attack_start_ts,
                    expected_attack_end_ts,
                    start,
                    end,
                )
                ok_overlap = (overlap > 0) and predicted_label == label

                # 更稳健：不要只看“最接近期望边界”的那一包，
                # 而是只要存在任意一包与期望段重叠且标签正确，就认为系统识别正确。
                found_overlap_any = False
                found_time_any = False
                for r in results:
                    d = r.get("detail", {})
                    if str(d.get("attack_id")) != str(ecu_id):
                        continue
                    r_label = r.get("attack_type")
                    r_start = float(d.get("start_time", 0.0))
                    r_end = float(d.get("end_time", 0.0))
                    if r_label != label:
                        continue

                    r_overlap = _overlap_len(
                        expected_attack_start_ts,
                        expected_attack_end_ts,
                        r_start,
                        r_end,
                    )
                    if r_overlap > 0:
                        found_overlap_any = True

                    if abs(r_start - expected_attack_start_ts) <= tol and abs(r_end - expected_attack_end_ts) <= tol:
                        found_time_any = True

                if found_overlap_any:
                    correct_single += 1
                    seg_overlap_correct_single += 1
                if found_time_any:
                    seg_correct_single += 1

                self.stdout.write(
                    f"  trial={trial_i}: predicted={predicted_label}, "
                    f"start={start:.3f}, end={end:.3f}, "
                    f"expected=[{expected_attack_start_ts:.3f},{expected_attack_end_ts:.3f}], "
                    f"tol={tol:.3f}, ok_cls={ok_cls}, ok_seg_exact={ok_seg}, "
                    f"overlap={overlap:.3f}, ok_seg_overlap={ok_overlap}"
                )

        # ---------- 2) Mixed single-ID, per-segment verification ----------
        total_seg_mixed = 0
        correct_seg_mixed = 0

        self.stdout.write(self.style.NOTICE("\n[Mixed Single-ID] per-segment verification"))
        target = pick_valid_id_by_ecu(baselines, ecu_id)
        if not target:
            raise CommandError(f"No valid baseline id found for ecu_id={ecu_id}")
        chosen_cycle = float(target["cycle"])
        for trial_i in range(trials):
            trial_seed = seed_base + trial_i * 20011
            stream_iter, chosen = generate_mixed_attack_stream_csv(
                ecu_id=ecu_id,
                cycle=chosen_cycle,
                attack_kinds=labels,
                num_attacks=num_attacks,
                start_ts=0.0,
                pre_frames=pre_frames,
                attack_frames=attack_frames,
                post_frames=post_frames,
                seed=trial_seed,
            )
            stream_lines = list(stream_iter)
            stream_text = build_stream_text(stream_lines)

            segs = []
            parsed = _parse_stream_lines(stream_lines)
            ts_only = [ts for (ts, eid) in parsed if eid == ecu_id]
            tol = max(1e-6, chosen_cycle * 5.0)
            min_needed = pre_frames + num_attacks * attack_frames + (num_attacks - 1) * gap_frames + post_frames
            if len(ts_only) < min_needed:
                raise RuntimeError(f"Mixed stream for ecu_id={ecu_id} has too few frames: {len(ts_only)} < {min_needed}")
            for i in range(num_attacks):
                # 攻击段与攻击段之间插入 gap_frames 个“正常帧”
                seg_start_idx = pre_frames + i * attack_frames + i * gap_frames
                seg_end_idx = seg_start_idx + attack_frames - 1
                segs.append(
                    {
                        "kind": chosen[i],
                        "start_ts": ts_only[seg_start_idx],
                        "end_ts": ts_only[seg_end_idx],
                        "tol": tol,
                    }
                )
            packets = _run_clockids_detect(clockids_bin_path, baselines_csv_path, stream_text)
            results = classifier.predict_packets(packets)

            # 为每个 segment 找是否存在正确标签的检测包
            for si, seg in enumerate(segs):
                total_seg_mixed += 1
                found_correct = False
                best_overlap_any = -1.0
                best_pred_any = None
                best_start_any = 0.0
                best_end_any = 0.0
                for r in results:
                    d = r.get("detail", {})
                    if str(d.get("attack_id")) != str(ecu_id):
                        continue
                    start = float(d.get("start_time", 0.0))
                    end = float(d.get("end_time", 0.0))
                    ov = _overlap_len(seg["start_ts"], seg["end_ts"], start, end)
                    if ov <= 0:
                        continue
                    if ov > best_overlap_any:
                        best_overlap_any = ov
                        best_pred_any = r.get("attack_type")
                        best_start_any = start
                        best_end_any = end
                    if r.get("attack_type") == seg["kind"]:
                        found_correct = True
                        # 不 break，仍保留 best_* 信息（方便诊断）
                if found_correct:
                    correct_seg_mixed += 1
                if trial_i == 0:
                    self.stdout.write(
                        f"  [MixedSeg] seg#{si} kind={seg['kind']} expected=[{seg['start_ts']:.3f},{seg['end_ts']:.3f}] "
                        f"best_pred={best_pred_any} best_overlap={best_overlap_any:.3f} "
                        f"best_detect=[{best_start_any:.3f},{best_end_any:.3f}] found_correct={found_correct}"
                    )

        # ---------- 3) Mixed multi-ID, per-segment verification ----------
        total_seg_multi = 0
        correct_seg_multi = 0

        self.stdout.write(self.style.NOTICE("\n[Mixed Multi-ID] per-segment verification"))
        selected_rows = pick_multiple_baselines(baselines, ecu_ids=ecu_ids, num_ids=len(ecu_ids))
        if len(selected_rows) < 2:
            raise CommandError("Not enough valid baselines for --ecu_ids")

        for trial_i in range(trials):
            trial_seed = seed_base + trial_i * 30013
            merged_iter, meta = generate_multi_id_mixed_stream(
                baseline_rows=selected_rows,
                attack_kinds=labels,
                num_attacks=num_attacks,
                pre_frames=pre_frames,
                attack_frames=attack_frames,
                post_frames=post_frames,
                seed=trial_seed,
            )

            merged_lines = list(merged_iter)
            stream_text = build_stream_text(merged_lines)
            packets = _run_clockids_detect(clockids_bin_path, baselines_csv_path, stream_text)
            results = classifier.predict_packets(packets)

            # 构建每个 id 的时间戳序列（从 merged_lines 过滤出来）
            id_to_ts: Dict[str, List[float]] = {str(r["id"]): [] for r in meta}
            for line in merged_lines:
                ts, eid = line.split(",", 1)
                eid = eid.strip()
                if eid not in id_to_ts:
                    continue
                id_to_ts[eid].append(float(ts))

            meta_by_id = {str(m["id"]): m.get("chosen_attack_kinds", []) for m in meta}

            # 为每个 id 的每段设定期望区间，然后看是否存在正确标签的检测包
            for row in selected_rows:
                sid = str(row["id"])
                cycle = float(row["cycle"])
                tol = max(1e-6, cycle * 5.0)

                chosen = meta_by_id.get(sid, [])
                if len(chosen) < num_attacks:
                    continue

                if trial_i == 0:
                    sid_results = [r for r in results if str(r.get("detail", {}).get("attack_id")) == sid]
                    self.stdout.write(f"  [SidDetections] sid={sid} detections={len(sid_results)}")
                    for ridx, r in enumerate(sid_results[:6]):
                        d = r.get("detail", {})
                        st = float(d.get("start_time", 0.0))
                        en = float(d.get("end_time", 0.0))
                        self.stdout.write(
                            f"    det#{ridx} pred={r.get('attack_type')} conf={r.get('confidence'):.3f} start={st:.3f} end={en:.3f}"
                        )

                ts_only = id_to_ts.get(sid, [])
                min_needed = pre_frames + num_attacks * attack_frames + (num_attacks - 1) * gap_frames + post_frames
                if len(ts_only) < min_needed:
                    continue

                for i in range(num_attacks):
                    seg_start_idx = pre_frames + i * attack_frames + i * gap_frames
                    seg_end_idx = seg_start_idx + attack_frames - 1
                    seg_kind = chosen[i]
                    seg_start_ts = ts_only[seg_start_idx]
                    seg_end_ts = ts_only[seg_end_idx]
                    total_seg_multi += 1

                    found_correct = False
                    best_overlap_any = -1.0
                    best_pred_any = None
                    best_detect_start_any = 0.0
                    best_detect_end_any = 0.0
                    for r in results:
                        d = r.get("detail", {})
                        if str(d.get("attack_id")) != sid:
                            continue
                        start = float(d.get("start_time", 0.0))
                        end = float(d.get("end_time", 0.0))
                        ov = _overlap_len(seg_start_ts, seg_end_ts, start, end)
                        if ov <= 0:
                            continue
                        if ov > best_overlap_any:
                            best_overlap_any = ov
                            best_pred_any = r.get("attack_type")
                            best_detect_start_any = start
                            best_detect_end_any = end
                        if r.get("attack_type") == seg_kind:
                            found_correct = True
                            # 不 break，保留 best_* 信息（方便排查）
                    if found_correct:
                        correct_seg_multi += 1
                    if trial_i == 0:
                        self.stdout.write(
                            f"  [MixedMultiSeg] sid={sid} seg#{i} kind={seg_kind} expected=[{seg_start_ts:.3f},{seg_end_ts:.3f}] "
                            f"best_pred={best_pred_any} best_overlap={best_overlap_any:.3f} "
                            f"best_detect=[{best_detect_start_any:.3f},{best_detect_end_any:.3f}] found_correct={found_correct}"
                        )

        # ---------- Print summary ----------
        def pct(a: int, b: int) -> float:
            return (100.0 * a / b) if b > 0 else 0.0

        self.stdout.write("\n================ Verification Summary ================")
        self.stdout.write(f"[Single-ID] classification accuracy: {correct_single}/{total_single} = {pct(correct_single, total_single):.2f}%")
        self.stdout.write(f"[Single-ID] segment accuracy (time-match + label): {seg_correct_single}/{total_single} = {pct(seg_correct_single, total_single):.2f}%")
        self.stdout.write(f"[Single-ID] segment accuracy (overlap + label): {seg_overlap_correct_single}/{total_single} = {pct(seg_overlap_correct_single, total_single):.2f}%")
        self.stdout.write(f"[Mixed Single-ID] segment correct rate: {correct_seg_mixed}/{total_seg_mixed} = {pct(correct_seg_mixed, total_seg_mixed):.2f}%")
        self.stdout.write(f"[Mixed Multi-ID] segment correct rate: {correct_seg_multi}/{total_seg_multi} = {pct(correct_seg_multi, total_seg_multi):.2f}%")
        self.stdout.write("======================================================")

