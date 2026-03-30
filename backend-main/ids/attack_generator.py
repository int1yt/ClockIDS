import csv
import heapq
import math
import random
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


DEFAULT_ATTACK_KINDS = ["DoS", "Fuzzy", "gear", "RPM"]


def load_baselines_csv(baselines_csv_path: str) -> List[Dict]:
    """
    读取 ClockIDS.cpp 生成的 baselines.csv
    期望表头：
      id,cycle,mean_skew,stddev_skew,valid
    """
    rows: List[Dict] = []
    with open(baselines_csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for r in reader:
            if not r:
                continue
            rows.append(
                {
                    "id": r["id"],
                    "cycle": float(r["cycle"]),
                    "mean_skew": float(r["mean_skew"]),
                    "stddev_skew": float(r["stddev_skew"]),
                    "valid": int(r["valid"]) != 0,
                }
            )
    return rows


def pick_first_valid_id(baselines: List[Dict]) -> Optional[Dict]:
    for b in baselines:
        if b.get("valid") and b.get("cycle", 0) > 0:
            return b
    return None


def pick_default_simulation_id(baselines: List[Dict]) -> Optional[Dict]:
    """
    合成流默认优先用周期较慢的 ID（如 0690/00a0），更容易在 3σ 规则下产生可观测告警。
    CSV 第一行若是 ~10ms 周期，扰动往往不够，网页端易出现 0 条告警。
    """
    preferred = ("0690", "00a0", "00a1", "05f0")
    for pid in preferred:
        for b in baselines:
            if str(b.get("id")) == pid and b.get("valid") and b.get("cycle", 0) > 0:
                return b
    return pick_first_valid_id(baselines)


def pick_valid_id_by_ecu(baselines: List[Dict], ecu_id: Optional[str]) -> Optional[Dict]:
    """
    若指定 ecu_id，则使用该 ID 的基线行（须 valid）；否则使用 pick_default_simulation_id。
    """
    if ecu_id:
        for b in baselines:
            if str(b.get("id")) == str(ecu_id) and b.get("valid") and b.get("cycle", 0) > 0:
                return b
    return pick_default_simulation_id(baselines)


def _jitter(cycle: float, jitter_ratio: float) -> float:
    # 对 CAN 周期引入小抖动；该抖动用于让 RLS 估计更贴近真实噪声
    return random.gauss(0.0, abs(cycle) * jitter_ratio)


def generate_attack_stream_csv(
    ecu_id: str,
    cycle: float,
    attack_kind: str,
    *,
    start_ts: float = 0.0,
    pre_frames: int = 120,
    attack_frames: int = 180,
    post_frames: int = 120,
    # 正常段抖动越小，RLS 越容易在攻击后快速回落到基线
    jitter_ratio_normal: float = 0.01,
    jitter_ratio_attack: float = 0.06,
    # attack strength 控制（不同攻击种类用不同策略；偏强以保证能触发 3σ）
    dos_cycle_delta: float = 0.65,
    fuzzy_cycle_noise: float = 0.45,
    gear_amp: float = 0.28,
    rpm_drift: float = 0.45,
    seed: Optional[int] = None,
) -> Iterable[str]:
    """
    生成一段“单 ID”的检测数据流（CSV 行）。

    ClockIDS.cpp 的 parse_csv_line 只关心前两列：timestamp, id
    后续列不存在也可以；这里仅输出两列保证简单。
    """
    if seed is not None:
        random.seed(seed)

    # 以“积分”的方式生成时间戳（每一帧的间隔可能随攻击种类变化）
    t = start_ts

    def emit(ts: float) -> str:
        # 保持足够小数位，避免浮点抖动过大影响解析/周期估计
        return f"{ts:.6f},{ecu_id}"

    # --- 正常段 ---
    for i in range(pre_frames):
        t += cycle + _jitter(cycle, jitter_ratio_normal)
        yield emit(t)

    # --- 攻击段 ---
    two_pi = 2.0 * math.pi
    for j in range(attack_frames):
        if attack_kind == "DoS":
            # 通过增大/减小周期，制造到达时序偏移
            interval = cycle * (1.0 + dos_cycle_delta)
            interval += _jitter(cycle, jitter_ratio_attack)
        elif attack_kind == "Fuzzy":
            # 引入较大随机噪声，使得 skew 统计明显偏离基线
            interval = cycle * (1.0 + random.uniform(-fuzzy_cycle_noise, fuzzy_cycle_noise))
            interval += _jitter(cycle, jitter_ratio_attack)
        elif attack_kind == "gear":
            # 周期按一个缓慢正弦波变化，制造“相对周期的结构性偏斜”
            period = max(12, attack_frames // 6)
            modulation = 1.0 + gear_amp * math.sin(two_pi * j / period)
            interval = cycle * modulation
            interval += _jitter(cycle, jitter_ratio_attack)
        elif attack_kind == "RPM":
            # 线性漂移：周期从基线逐步偏移
            modulation = 1.0 + rpm_drift * (j / max(1, attack_frames - 1))
            interval = cycle * modulation
            interval += _jitter(cycle, jitter_ratio_attack)
        else:
            # 未知攻击类型：退化为“轻微噪声偏离”
            interval = cycle * (1.0 + 0.05)
            interval += _jitter(cycle, jitter_ratio_attack)

        if interval <= 0:
            interval = max(1e-6, cycle)
        t += interval
        yield emit(t)

    # --- 恢复正常段 ---
    # 攻击段会改变累积时间相位；如果完全不做补偿，ClockIDS 的“全局预测误差”在 post-normal
    # 段里会持续偏离基线，导致攻击段 end_time 被拉得很长。
    # 这里在 post-normal 的前一小段窗口内，将累积漂移按帧平均拉回，模拟真实系统的快速恢复。
    expected_t_after_attack = start_ts + (pre_frames + attack_frames) * cycle
    drift = t - expected_t_after_attack  # >0 表示当前更“靠后/更长”，需要在前几帧缩短
    correction_window = max(1, min(post_frames, 30))

    for k in range(post_frames):
        base_interval = cycle + _jitter(cycle, jitter_ratio_normal)
        if k < correction_window:
            base_interval += (-drift / correction_window)
        if base_interval <= 0:
            base_interval = max(1e-6, cycle)
        t += base_interval
        yield emit(t)


def build_stream_text(lines: Iterable[str]) -> str:
    # ClockIDS.cpp 以“行”读取，最后必须有换行保证读取完最后一行
    return "\n".join(lines) + "\n"


def generate_mixed_attack_stream_csv(
    ecu_id: str,
    cycle: float,
    *,
    attack_kinds: Sequence[str] = DEFAULT_ATTACK_KINDS,
    num_attacks: int = 3,
    start_ts: float = 0.0,
    pre_frames: int = 240,
    attack_frames: int = 220,
    # 攻击段之间插入多少“正常帧”（用于让 ClockIDS.cpp 的攻击状态真正结束）
    # 默认按 attack_frames 自动推导，保证测试和验证的一致性
    gap_frames: Optional[int] = None,
    post_frames: int = 240,
    # 正常段抖动越小，RLS 越容易在攻击后快速回落到基线
    jitter_ratio_normal: float = 0.01,
    jitter_ratio_attack: float = 0.06,
    seed: Optional[int] = None,
) -> Tuple[Iterable[str], List[str]]:
    """
    生成一条“长数据流”：正常 -> 攻击(随机种类) -> 正常 -> 攻击 ...
    ClockIDS.cpp 在一次 detect 流处理期间会持续计算 skew，并在攻击段结束时输出多条告警。

    返回：
      stream_lines_iter：可迭代的行（timestamp,id）
      chosen_attack_kinds：生成器内部真实选择的攻击类型序列（用于调试，可不展示给前端）
    """
    if seed is not None:
        random.seed(seed)

    # 先确定每段攻击类型，便于调用方在迭代前拿到真实序列（与 ML 预测对照）
    chosen: List[str] = [random.choice(list(attack_kinds)) for _ in range(num_attacks)]
    if gap_frames is None:
        # 攻击段之间的间隔需要足够长，否则 ClockIDS 可能把相邻告警合并成一个超长段
        gap_frames = max(20, int(attack_frames * 0.4))

    def _iter():
        t = start_ts

        def emit(ts: float) -> str:
            return f"{ts:.6f},{ecu_id}"

        # initial normal
        for _ in range(pre_frames):
            t += cycle + _jitter(cycle, jitter_ratio_normal)
            yield emit(t)

        # alternating segments
        for seg_idx, kind in enumerate(chosen):

            two_pi = 2.0 * math.pi
            for j in range(attack_frames):
                if kind == "DoS":
                    interval = cycle * (1.0 + 0.65)
                    interval += _jitter(cycle, jitter_ratio_attack)
                elif kind == "Fuzzy":
                    interval = cycle * (1.0 + random.uniform(-0.45, 0.45))
                    interval += _jitter(cycle, jitter_ratio_attack)
                elif kind == "gear":
                    period = max(12, attack_frames // 6)
                    modulation = 1.0 + 0.28 * math.sin(two_pi * j / period)
                    interval = cycle * modulation
                    interval += _jitter(cycle, jitter_ratio_attack)
                elif kind == "RPM":
                    modulation = 1.0 + 0.45 * (j / max(1, attack_frames - 1))
                    interval = cycle * modulation
                    interval += _jitter(cycle, jitter_ratio_attack)
                else:
                    interval = cycle * (1.0 + 0.05)
                    interval += _jitter(cycle, jitter_ratio_attack)

                if interval <= 0:
                    interval = max(1e-6, cycle)
                t += interval
                yield emit(t)

            # 在攻击类型之间插入一段正常帧，避免多段攻击被合并成一个超长告警
            if seg_idx < len(chosen) - 1 and gap_frames > 0:
                for _ in range(gap_frames):
                    t += cycle + _jitter(cycle, jitter_ratio_normal)
                    yield emit(t)

            # trailing normal
            # 注意：post_frames 在所有 attack kind 结束后统一追加
        for _ in range(post_frames):
            t += cycle + _jitter(cycle, jitter_ratio_normal)
            yield emit(t)

    return _iter(), chosen


def merge_streams_by_timestamp(stream_iters: List[Iterable[str]]) -> Iterable[str]:
    """
    将多条「时间戳,can_id」行流按时间戳从小到大合并（多 ID 交错）。
    ClockIDS.cpp 按行顺序处理，每个 ID 独立维护 DetectState。
    """
    heap: List[Tuple[float, int, str, object]] = []
    for i, seq in enumerate(stream_iters):
        it = iter(seq)
        try:
            first = next(it)
        except StopIteration:
            continue
        ts = float(first.split(",")[0])
        heapq.heappush(heap, (ts, i, first, it))
    while heap:
        _ts, _i, line, it = heapq.heappop(heap)
        yield line
        try:
            nxt = next(it)
        except StopIteration:
            continue
        ts = float(nxt.split(",")[0])
        heapq.heappush(heap, (ts, _i, nxt, it))


def pick_multiple_baselines(
    baselines: List[Dict],
    *,
    ecu_ids: Optional[Sequence[str]] = None,
    num_ids: int = 5,
) -> List[Dict]:
    """
    选取多条 valid 基线行用于多 ID 合成。
    若传入 ecu_ids，则按顺序解析；否则按优先 ID 列表再补足。
    """
    if ecu_ids:
        out: List[Dict] = []
        for eid in ecu_ids:
            eid = str(eid).strip()
            if not eid:
                continue
            for b in baselines:
                if str(b.get("id")) == eid and b.get("valid") and b.get("cycle", 0) > 0:
                    out.append(b)
                    break
        return out

    preferred = [
        "0690",
        "00a0",
        "00a1",
        "05f0",
        "0329",
        "05a0",
        "0140",
        "0130",
        "0002",
    ]
    seen: set = set()
    out = []
    for pid in preferred:
        for b in baselines:
            if str(b.get("id")) == pid and b.get("valid") and b.get("cycle", 0) > 0:
                if pid not in seen:
                    out.append(b)
                    seen.add(pid)
                break
        if len(out) >= num_ids:
            return out[:num_ids]

    for b in baselines:
        bid = str(b.get("id"))
        if b.get("valid") and b.get("cycle", 0) > 0 and bid not in seen:
            out.append(b)
            seen.add(bid)
        if len(out) >= num_ids:
            break
    return out[:num_ids]


def generate_multi_id_mixed_stream(
    baseline_rows: List[Dict],
    *,
    attack_kinds: Sequence[str],
    num_attacks: int,
    pre_frames: int,
    attack_frames: int,
    post_frames: int,
    seed: Optional[int] = None,
) -> Tuple[Iterable[str], List[Dict[str, Any]]]:
    """
    每个 CAN ID 各生成一条 mixed 攻击流，再按时间戳合并为单条 stdin 流。
    返回：合并后的行迭代器、每 ID 的 chosen_attack_kinds 元数据。
    """
    stream_iters: List[Iterable[str]] = []
    meta: List[Dict[str, Any]] = []
    for i, b in enumerate(baseline_rows):
        ecu_id = str(b["id"])
        cycle = float(b["cycle"])
        s = None if seed is None else (seed + i * 9973)
        it, chosen = generate_mixed_attack_stream_csv(
            ecu_id,
            cycle,
            attack_kinds=attack_kinds,
            num_attacks=num_attacks,
            start_ts=0.0,
            pre_frames=pre_frames,
            attack_frames=attack_frames,
            post_frames=post_frames,
            seed=s,
        )
        stream_iters.append(it)
        meta.append({"id": ecu_id, "chosen_attack_kinds": chosen})
    merged = merge_streams_by_timestamp(stream_iters)
    return merged, meta

