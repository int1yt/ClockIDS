import sys
import subprocess
import json

sys.path.append("backend-main")

from mysit import settings
from ids.attack_generator import (
    load_baselines_csv,
    generate_attack_stream_csv,
    build_stream_text,
    pick_valid_id_by_ecu,
)

baselines = load_baselines_csv(settings.CLOCKIDS_BASELINES_CSV_PATH)
target = pick_valid_id_by_ecu(baselines, "0690")
ecu_id = target["id"]
cycle = float(target["cycle"])

pre_frames = 20
attack_frames = 30
post_frames = 20
kind = "DoS"

stream_iter = generate_attack_stream_csv(
    ecu_id=ecu_id,
    cycle=cycle,
    attack_kind=kind,
    start_ts=0.0,
    pre_frames=pre_frames,
    attack_frames=attack_frames,
    post_frames=post_frames,
    seed=123,
)
stream_text = build_stream_text(list(stream_iter))

cmd = [
    settings.CLOCKIDS_BIN_PATH,
    "detect",
    "--baseline",
    settings.CLOCKIDS_BASELINES_CSV_PATH,
    "--out",
    "-",
    "--ndjson",
]

p = subprocess.Popen(
    cmd,
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
    bufsize=1,
)

out, err = p.communicate(input=stream_text, timeout=60)

lines = [l for l in out.splitlines() if l.strip()]
start_cnt = sum(1 for l in lines if '"event"' in l and '"start"' in l)
print("stdout_lines", len(lines))
print("event_start_cnt", start_cnt)
parse_ok = 0
parse_bad = 0
bad_samples = []
for l in lines:
    try:
        json.loads(l)
        parse_ok += 1
    except Exception as e:
        parse_bad += 1
        bad_samples.append((str(e), l[:160]))
print("json_ok", parse_ok, "json_bad", parse_bad)
if bad_samples:
    print("bad_samples:", bad_samples[:2])
print("first_3_lines:")
for l in lines[:3]:
    print(l[:220])
print("stderr_tail:")
tail = (err or "").splitlines()[-10:]
print("\n".join(tail))

