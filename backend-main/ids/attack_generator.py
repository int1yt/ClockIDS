import csv
import heapq
import math
import random
import datetime
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


DEFAULT_ATTACK_KINDS = ["DoS", "Fuzzy", "gear", "RPM"]

_CARHACK_CACHE: Dict[str, Any] = {}


def _repo_root() -> str:
    import os
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def _carhack_path(name: str) -> str:
    import os
    return os.path.join(_repo_root(), "CarHackData", name)


def _parse_normal_run_line(line: str) -> Optional[Tuple[str, int, str]]:
    # 例：Timestamp: 1479... ID: 0329 000 DLC: 8  87 b9 ...
    line = line.strip()
    if not line or "ID:" not in line or "DLC:" not in line:
        return None
    try:
        # ID
        id_pos = line.find("ID:")
        dlc_pos = line.find("DLC:")
        if id_pos < 0 or dlc_pos < 0:
            return None
        id_s = line[id_pos + 3 : dlc_pos].strip().split()[0]
        # DLC
        rest = line[dlc_pos + 4 :].strip()
        parts = rest.split()
        if not parts:
            return None
        dlc = int(parts[0])
        data_bytes = parts[1 : 1 + dlc]
        data_hex = "".join([b.zfill(2) for b in data_bytes]).lower()
        return str(id_s), int(dlc), str(data_hex)
    except Exception:
        return None


def _parse_attack_csv_line(line: str) -> Optional[Tuple[str, int, str]]:
    # 例：ts,0329,8,dc,b8,7e,14,11,20,00,14,R
    line = line.strip()
    if not line:
        return None
    parts = line.split(",")
    if len(parts) < 4:
        return None
    try:
        ecu_id = str(parts[1]).strip()
        dlc = int(parts[2])
        data_bytes = [p.strip() for p in parts[3 : 3 + dlc]]
        data_hex = "".join([b.zfill(2) for b in data_bytes]).lower()
        return ecu_id, dlc, data_hex
    except Exception:
        return None


def _reservoir_add(res: List[Tuple[int, str]], item: Tuple[int, str], k: int, n_seen: int) -> None:
    # 标准 reservoir sampling：均匀从流中保留 k 个样本
    if len(res) < k:
        res.append(item)
        return
    j = random.randint(0, n_seen)
    if j < k:
        res[j] = item


def _load_carhack_payload_pools(*, max_per_id: int = 4000) -> Dict[str, Any]:
    """
    从 CarHackData 构建 payload 池：
      pools["normal"][ecu_id] -> List[(dlc, data_hex)]
      pools["attack"][kind][ecu_id] -> List[(dlc, data_hex)]
    为避免占用内存过大，使用 reservoir sampling 限制每个 ecu_id 的样本数。
    """
    pools: Dict[str, Any] = {"normal": {}, "attack": {k: {} for k in DEFAULT_ATTACK_KINDS}}

    # normal_run_data.txt
    normal_fp = _carhack_path("normal_run_data.txt")
    counts: Dict[str, int] = {}
    try:
        with open(normal_fp, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                parsed = _parse_normal_run_line(line)
                if not parsed:
                    continue
                ecu_id, dlc, data_hex = parsed
                counts[ecu_id] = counts.get(ecu_id, 0) + 1
                bucket = pools["normal"].setdefault(ecu_id, [])
                _reservoir_add(bucket, (dlc, data_hex), max_per_id, counts[ecu_id] - 1)
    except FileNotFoundError:
        pass

    # attack datasets
    kind_to_file = {
        "DoS": "DoS_dataset.csv",
        "Fuzzy": "Fuzzy_dataset.csv",
        "gear": "gear_dataset.csv",
        "RPM": "RPM_dataset.csv",
    }
    for kind, fname in kind_to_file.items():
        fp = _carhack_path(fname)
        counts = {}
        try:
            with open(fp, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    parsed = _parse_attack_csv_line(line)
                    if not parsed:
                        continue
                    ecu_id, dlc, data_hex = parsed
                    counts[ecu_id] = counts.get(ecu_id, 0) + 1
                    bucket = pools["attack"][kind].setdefault(ecu_id, [])
                    _reservoir_add(bucket, (dlc, data_hex), max_per_id, counts[ecu_id] - 1)
        except FileNotFoundError:
            continue

    return pools


def _get_carhack_pools() -> Dict[str, Any]:
    pools = _CARHACK_CACHE.get("pools")
    if pools is None:
        pools = _load_carhack_payload_pools()
        _CARHACK_CACHE["pools"] = pools
    return pools


def _hex_bytes(bs: bytes) -> str:
    return bs.hex()


def _payload_for(
    *,
    ecu_id: str,
    idx: int,
    phase: str,
    attack_kind: Optional[str],
) -> Tuple[int, str]:
    """
    生成伪 CAN payload（用于让输出包含 dlc/data，可用于 ML）。
    返回 (dlc, data_hex)：
      - dlc 固定 8
      - data_hex 为 16 个 hex 字符（8 bytes）
    """
    pools = _get_carhack_pools()

    # 1) 优先从 CarHackData 抽真实 payload
    if phase == "attack" and attack_kind in pools.get("attack", {}):
        bucket = pools["attack"][str(attack_kind)].get(str(ecu_id))
        if bucket:
            return random.choice(bucket)

    bucket_n = pools.get("normal", {}).get(str(ecu_id))
    if bucket_n:
        return random.choice(bucket_n)

    # 2) 兜底：若 CarHackData 缺该 ID，则退化为合成 payload（仍满足 dlc/data）
    dlc = 8
    if attack_kind == "DoS":
        bs = bytes([0xFF] * 8)
    elif attack_kind == "Fuzzy":
        bs = bytes([random.randint(0, 255) for _ in range(8)])
    elif attack_kind == "gear":
        base = (idx // 10) & 0xFF
        bs = bytes([(base + i * 7) & 0xFF for i in range(8)])
    elif attack_kind == "RPM":
        base = idx & 0xFF
        bs = bytes([(base + i) & 0xFF for i in range(8)])
    else:
        seed = (int(ecu_id, 16) if all(c in "0123456789abcdefABCDEF" for c in ecu_id) else sum(ord(c) for c in ecu_id))
        v = (seed + idx * 13 + (0 if phase == "pre" else 1 if phase == "post" else 2)) & 0xFF
        bs = bytes([(v + i * 3) & 0xFF for i in range(8)])
    return dlc, _hex_bytes(bs)


def ethernet_csv_start_ts_epoch(
    csv_path: str,
    *,
    timestamp_col: str = " Timestamp",
    fallback_col: str = "Timestamp",
) -> float:
    """
    从 EthernetData 的 CICFlowMeter 风格 CSV 中取第一条记录的 Timestamp，
    转成 epoch seconds（UTC）。

    该 CSV 时间格式示例：'5/7/2017 8:42'（通常只有分钟粒度）。
    """
    import os

    # 允许传相对路径：相对于仓库根目录（ClockIDS-ver1）
    if not os.path.isabs(csv_path):
        repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        candidate = os.path.abspath(os.path.join(repo_root, csv_path))
        if os.path.exists(candidate):
            csv_path = candidate

    with open(csv_path, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if not row:
                continue
            ts_s = row.get(timestamp_col) or row.get(fallback_col) or ""
            ts_s = str(ts_s).strip()
            if not ts_s:
                continue
            # 兼容 m/d/Y H:M
            dt = datetime.datetime.strptime(ts_s, "%m/%d/%Y %H:%M")
            dt = dt.replace(tzinfo=datetime.timezone.utc)
            return dt.timestamp()
    raise RuntimeError(f"Cannot parse Timestamp from ethernet csv: {csv_path}")


def ethernet_csv_timeline_epochs(
    csv_path: str,
    *,
    timestamp_col: str = " Timestamp",
    fallback_col: str = "Timestamp",
    label_col: str = " Label",
    fallback_label_col: str = "Label",
) -> Tuple[List[float], List[bool]]:
    """
    读取 Ethernet CSV 的时间序列，返回：
      - epochs: 每条记录的 epoch seconds（UTC）
      - is_abnormal: 是否异常（Label != BENIGN）

    说明：
    - CICFlowMeter 风格数据通常只有分钟粒度；为了避免大量重复时间戳导致“调度点”完全重合，
      这里会按行号添加一个很小的单调扰动 (i * 1e-3) 秒。
    - 若 csv_path 为相对路径，则相对仓库根目录解析。
    """
    import os

    if not os.path.isabs(csv_path):
        repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        candidate = os.path.abspath(os.path.join(repo_root, csv_path))
        if os.path.exists(candidate):
            csv_path = candidate

    epochs: List[float] = []
    is_abnormal: List[bool] = []
    with open(csv_path, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        for i, row in enumerate(reader):
            if not row:
                continue
            ts_s = row.get(timestamp_col) or row.get(fallback_col) or ""
            ts_s = str(ts_s).strip()
            if not ts_s:
                continue
            try:
                dt = datetime.datetime.strptime(ts_s, "%m/%d/%Y %H:%M")
            except ValueError:
                dt = datetime.datetime.strptime(ts_s, "%m/%d/%Y %H:%M:%S")
            dt = dt.replace(tzinfo=datetime.timezone.utc)
            base = dt.timestamp()
            base += float(i) * 1e-3

            lab = row.get(label_col) or row.get(fallback_label_col) or ""
            lab = str(lab).strip().upper()
            abnormal = bool(lab and lab != "BENIGN")

            epochs.append(base)
            is_abnormal.append(abnormal)

    if not epochs:
        raise RuntimeError(f"Cannot parse any rows from ethernet csv: {csv_path}")

    order = sorted(range(len(epochs)), key=lambda k: epochs[k])
    epochs = [epochs[i] for i in order]
    is_abnormal = [is_abnormal[i] for i in order]
    return epochs, is_abnormal


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
        # 额外输出 dlc,data_hex 以便 ClockIDS 输出更完整的 CAN 信息
        dlc, data_hex = _payload_for(ecu_id=ecu_id, idx=frame_idx[0], phase=phase[0], attack_kind=attack_kind if phase[0] == "attack" else None)
        frame_idx[0] += 1
        return f"{ts:.6f},{ecu_id},{dlc},{data_hex}"

    frame_idx = [0]
    phase = ["pre"]

    # --- 正常段 ---
    for i in range(pre_frames):
        phase[0] = "pre"
        t += cycle + _jitter(cycle, jitter_ratio_normal)
        yield emit(t)

    # --- 攻击段 ---
    two_pi = 2.0 * math.pi
    for j in range(attack_frames):
        phase[0] = "attack"
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
        phase[0] = "post"
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
            dlc, data_hex = _payload_for(ecu_id=ecu_id, idx=frame_idx[0], phase=phase[0], attack_kind=kind_now[0] if phase[0] == "attack" else None)
            frame_idx[0] += 1
            return f"{ts:.6f},{ecu_id},{dlc},{data_hex}"

        frame_idx = [0]
        phase = ["pre"]
        kind_now = [None]

        # initial normal
        for _ in range(pre_frames):
            phase[0] = "pre"
            t += cycle + _jitter(cycle, jitter_ratio_normal)
            yield emit(t)

        # alternating segments
        for seg_idx, kind in enumerate(chosen):
            kind_now[0] = str(kind)

            two_pi = 2.0 * math.pi
            for j in range(attack_frames):
                phase[0] = "attack"
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
                    phase[0] = "gap"
                    t += cycle + _jitter(cycle, jitter_ratio_normal)
                    yield emit(t)

            # trailing normal
            # 注意：post_frames 在所有 attack kind 结束后统一追加
        for _ in range(post_frames):
            phase[0] = "post"
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


def generate_ethernet_chain_stream_csv(
    ecu_id: str,
    cycle: float,
    *,
    ethernet_csv_path: str,
    attack_kinds: Sequence[str] = DEFAULT_ATTACK_KINDS,
    num_attacks: int = 8,
    after_abnormal_ratio: float = 0.6,
    after_abnormal_delay_sec: float = 2.0,
    normal_jitter_sec: float = 10.0,
    start_ts: float = 0.0,
    pre_frames: int = 240,
    attack_frames: int = 220,
    gap_frames: Optional[int] = None,
    post_frames: int = 240,
    jitter_ratio_normal: float = 0.01,
    jitter_ratio_attack: float = 0.06,
    seed: Optional[int] = None,
) -> Tuple[Iterable[str], List[Dict[str, Any]]]:
    """
    以“以太网攻击链”为时间驱动生成单 ID CAN 流：
      - 一部分攻击段发生在 ethernet abnormal 时间点之后
      - 一部分攻击段发生在 ethernet benign 时间片中
      - 攻击段之间自动插入正常帧（避免 ClockIDS 合并成超长告警）

    返回：
      stream_iter: 行流（timestamp,id）
      segments_meta: 每段攻击的调度信息（kind/source/target_ts/actual_start_ts）
    """
    if seed is not None:
        random.seed(seed)

    if gap_frames is None:
        gap_frames = max(20, int(attack_frames * 0.4))

    epochs, abnormal_flags = ethernet_csv_timeline_epochs(ethernet_csv_path)
    abnormal_ts = [t for t, ab in zip(epochs, abnormal_flags) if ab]
    benign_ts = [t for t, ab in zip(epochs, abnormal_flags) if not ab]
    if not benign_ts:
        benign_ts = epochs[:]
    if not abnormal_ts:
        abnormal_ts = benign_ts[:]

    n_after = int(round(float(num_attacks) * max(0.0, min(1.0, after_abnormal_ratio))))
    n_norm = max(0, int(num_attacks) - n_after)

    targets: List[Tuple[float, str]] = []
    for _ in range(n_after):
        t0 = random.choice(abnormal_ts) + float(after_abnormal_delay_sec)
        targets.append((t0, "after_abnormal"))
    for _ in range(n_norm):
        base = random.choice(benign_ts)
        base += random.uniform(-abs(normal_jitter_sec), abs(normal_jitter_sec))
        targets.append((base, "during_normal"))
    targets.sort(key=lambda x: x[0])

    anchor_eth = targets[0][0] if targets else epochs[0]
    offset = float(start_ts) - float(anchor_eth)
    targets = [(t + offset, src) for (t, src) in targets]

    chosen_kinds: List[str] = [random.choice(list(attack_kinds)) for _ in range(len(targets))]
    segments_meta: List[Dict[str, Any]] = []

    def _iter():
        t = float(start_ts)

        def emit(ts: float) -> str:
            return f"{ts:.6f},{ecu_id}"

        for _ in range(pre_frames):
            t += cycle + _jitter(cycle, jitter_ratio_normal)
            yield emit(t)

        for idx, ((target_ts, src), kind) in enumerate(zip(targets, chosen_kinds)):
            while t + cycle < target_ts:
                t += cycle + _jitter(cycle, jitter_ratio_normal)
                yield emit(t)

            actual_start_ts = t
            segments_meta.append(
                {
                    "idx": idx,
                    "ecu_id": ecu_id,
                    "kind": kind,
                    "source": src,
                    "target_ts": float(target_ts),
                    "actual_start_ts": float(actual_start_ts),
                    "cycle": float(cycle),
                }
            )

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

            if gap_frames > 0:
                for _ in range(gap_frames):
                    t += cycle + _jitter(cycle, jitter_ratio_normal)
                    yield emit(t)

        for _ in range(post_frames):
            t += cycle + _jitter(cycle, jitter_ratio_normal)
            yield emit(t)

    return _iter(), segments_meta


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
    start_ts: float = 0.0,
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
            start_ts=start_ts,
            pre_frames=pre_frames,
            attack_frames=attack_frames,
            post_frames=post_frames,
            seed=s,
        )
        stream_iters.append(it)
        meta.append({"id": ecu_id, "chosen_attack_kinds": chosen})
    merged = merge_streams_by_timestamp(stream_iters)
    return merged, meta


def generate_multi_id_ethernet_chain_stream(
    baseline_rows: List[Dict],
    *,
    ethernet_csv_path: str,
    ecu_ids: Sequence[str],
    attack_kinds: Sequence[str],
    num_attacks: int,
    after_abnormal_ratio: float,
    start_ts: float,
    pre_frames: int,
    attack_frames: int,
    gap_frames: Optional[int],
    post_frames: int,
    seed: Optional[int] = None,
) -> Tuple[Iterable[str], List[Dict[str, Any]]]:
    """
    多 ID 版本的“以太网攻击链驱动”CAN 流生成。
    返回：
      merged_lines: 多 ID 交错后的行流
      plan_meta: 每个 ID 的 segments 计划（用于前端展示/调试/落盘 meta）
    """
    if seed is not None:
        random.seed(seed)

    picked = pick_multiple_baselines(baseline_rows, ecu_ids=ecu_ids, num_ids=len(list(ecu_ids)))
    if not picked:
        raise RuntimeError("No valid baseline rows for requested ecu_ids")

    stream_iters: List[Iterable[str]] = []
    plan_meta: List[Dict[str, Any]] = []

    for i, b in enumerate(picked):
        eid = str(b["id"])
        cyc = float(b["cycle"])
        it, segs = generate_ethernet_chain_stream_csv(
            eid,
            cyc,
            ethernet_csv_path=ethernet_csv_path,
            attack_kinds=attack_kinds,
            num_attacks=num_attacks,
            after_abnormal_ratio=after_abnormal_ratio,
            start_ts=start_ts,
            pre_frames=pre_frames,
            attack_frames=attack_frames,
            gap_frames=gap_frames,
            post_frames=post_frames,
            seed=None if seed is None else int(seed) + i * 997,
        )
        stream_iters.append(it)
        plan_meta.append({"id": eid, "segments": segs})

    merged = merge_streams_by_timestamp(stream_iters)
    return merged, plan_meta

