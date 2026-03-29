import csv
import math
import random
from typing import Dict, Iterable, List, Optional, Sequence, Tuple


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
    jitter_ratio_normal: float = 0.01,
    jitter_ratio_attack: float = 0.03,
    # attack strength 控制（不同攻击种类用不同策略）
    dos_cycle_delta: float = 0.30,
    fuzzy_cycle_noise: float = 0.25,
    gear_amp: float = 0.16,
    rpm_drift: float = 0.20,
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
    for k in range(post_frames):
        t += cycle + _jitter(cycle, jitter_ratio_normal)
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
    post_frames: int = 240,
    jitter_ratio_normal: float = 0.01,
    jitter_ratio_attack: float = 0.03,
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

    chosen: List[str] = []

    def _iter():
        nonlocal chosen
        t = start_ts

        def emit(ts: float) -> str:
            return f"{ts:.6f},{ecu_id}"

        # initial normal
        for _ in range(pre_frames):
            t += cycle + _jitter(cycle, jitter_ratio_normal)
            yield emit(t)

        # alternating segments
        for _ in range(num_attacks):
            kind = random.choice(list(attack_kinds))
            chosen.append(kind)

            two_pi = 2.0 * math.pi
            for j in range(attack_frames):
                if kind == "DoS":
                    interval = cycle * (1.0 + 0.30)
                    interval += _jitter(cycle, jitter_ratio_attack)
                elif kind == "Fuzzy":
                    interval = cycle * (1.0 + random.uniform(-0.25, 0.25))
                    interval += _jitter(cycle, jitter_ratio_attack)
                elif kind == "gear":
                    period = max(12, attack_frames // 6)
                    modulation = 1.0 + 0.16 * math.sin(two_pi * j / period)
                    interval = cycle * modulation
                    interval += _jitter(cycle, jitter_ratio_attack)
                elif kind == "RPM":
                    modulation = 1.0 + 0.20 * (j / max(1, attack_frames - 1))
                    interval = cycle * modulation
                    interval += _jitter(cycle, jitter_ratio_attack)
                else:
                    interval = cycle * (1.0 + 0.05)
                    interval += _jitter(cycle, jitter_ratio_attack)

                if interval <= 0:
                    interval = max(1e-6, cycle)
                t += interval
                yield emit(t)

            # trailing normal
            for _ in range(post_frames):
                t += cycle + _jitter(cycle, jitter_ratio_normal)
                yield emit(t)

    return _iter(), chosen

