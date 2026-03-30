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
    load_baselines_csv,
    pick_valid_id_by_ecu,
)


def extract_features(packet: Dict[str, Any]) -> List[float]:
    """
    从 ClockIDS.cpp 的 attack_packets.json 单条告警提取特征。
    """
    return [
        float(packet.get("mean_skew", 0.0)),
        float(packet.get("stddev_skew", 0.0)),
        float(packet.get("duration", 0.0)),
        float(packet.get("frame_count", 0)),
    ]


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
        self._cached_artifacts = AttackClassifierArtifacts(labels=data["labels"], model=data["model"])
        return self._cached_artifacts

    def ensure_trained(
        self,
        *,
        pre_frames: int = 120,
        attack_frames: int = 180,
        post_frames: int = 120,
        samples_per_class: int = 20,
        max_total_samples: int = 200,
        random_seed: int = 42,
        force_retrain: bool = False,
    ) -> None:
        if (not force_retrain) and os.path.exists(self.model_path):
            return

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

        import random

        random.seed(random_seed)

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
                    stream_iter = generate_attack_stream_csv(
                        ecu_id,
                        cycle,
                        label,
                        start_ts=0.0,
                        pre_frames=pre_frames,
                        attack_frames=attack_frames,
                        post_frames=post_frames,
                        seed=random.randint(0, 10**9),
                    )
                    stream_text = build_stream_text(stream_iter)

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

                    pkt = packets[0]
                    X.append(extract_features(pkt))
                    y.append(label)
                    per_class += 1

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
            n_estimators=300,
            random_state=random_seed,
            class_weight="balanced",
        )
        model.fit(X, y)

        artifacts = {"labels": list(self.model_labels()), "model": model}
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
            prob_by_class = {str(classes[j]): float(proba[i][j]) for j in range(len(classes))}
            results.append(
                {
                    "attack_type": preds[i],
                    "confidence": float(proba[i][idx]),
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
        prob_by_class = {str(classes[i]): float(proba[i]) for i in range(len(classes))}

        return {
            "attack_type": pred,
            "confidence": float(proba[idx]),
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

