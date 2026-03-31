#ClockIDS 方案：结合CAN总线上的时间倾斜和以太网监控回溯的车内IDS方案


## 架构
我们预计系统将包含四个核心组件：
### ClockIDS
部署在CAN控制器附近，实时监听CAN消息，利用时钟倾斜特征检测异常，生成告警数据包。
### gPTP
提供精确时间同步服务，为各组件数据打上统一时间戳。
### 以太网监控 IDS
采用环形存储的方式，监听以太网流量，为每条以太网帧附加gPTP时间戳，缓存时间窗口内的数据。同时以太网也应具备IDS功能，初步识别来自于以太网的攻击。
### 中央处理器
计算核心，接收ClockIDS的异常数据，根据时间窗口向以太网监控请求对应数据，运行机器学习模型关联时序事件，输出攻击链.在车外训练模型，在车内轻量化部署。



## 数据流与攻击链还原流程
### 实时监控
ClockIDS持续监听CAN总线，实时计算时钟倾斜。以太网监控持续捕获网络流量，并存储带时间戳的元数据。
### 异常触发
当ClockIDS检测到某CAN ID的时钟倾斜异常（如突然偏移0.1%），立即生成告警数据包，通过gPTP获取精确时间戳，发送至中央处理器。此处ClockIDS先对数据进行初步检测，完成“正常-异常”的区分，并可初步给出针对CAN的攻击分类，后仅仅上传异常数据包。
### 跨域取证
中央处理器收到告警后，根据时间戳向以太网监控请求[t0-Δ, t0+Δ]窗口内的所有以太网事件。
### 关联分析
中央处理器将CAN异常数据包与以太网事件合并为时序特征向量，输入机器学习模型。中央处理器主要负责计算，是一个二维时序上的机器学习。
### 攻击链输出
模型输出攻击类别及置信度，中央处理器生成包含时间线、攻击步骤、受影响ECU的报告，供安全运营或响应系统使用。

---

## 代码结构
```
ClockIDS-ver1/
  src/embedded/
    ClockIDS.cpp              # C++：CAN 时钟倾斜检测（训练基线 + 流式检测 + JSON/NDJSON 输出）
    ClockIDS.exe              # 编译产物（Windows）

  backend-main/
    manage.py                 # Django 管理入口（runserver / verify_system 等）
    ids/
      views.py                # 后端 API：启动监测、轮询进度、读取 C++ NDJSON、落盘 upload_queue、触发 ML 分类
      ml_attack_classifier.py # ML：训练/预测（RandomForest），特征提取与模型持久化
      attack_generator.py     # 生成器：生成 normal/mixed/multi-id/ethernet_chain 的 CAN 流（ts,id,dlc,data_hex）
      management/commands/
        verify_system.py      # 端到端验证：生成数据 → C++ detect → ML classify → 评估段/类准确率
      templates/
        dashboard.html        # 前端：监控面板（开始/停止/轮询/表格显示/调试信息）

  upload_queue/               # C++ 检测到异常后落盘的 JSON 报告队列（供后续上传/取证/复现实验）
  EthernetData/               # （可选）以太网 CSV（用于时间对齐/攻击链调度）
  CarHackData/                # （可选）真实 CAN payload 数据源（dlc/data_hex）
```

## 各模块功能与作用（按运行链路）
### 1) C++ 检测器：`src/embedded/ClockIDS.cpp`
- **train**：读取正常数据，针对每个 CAN ID 估计周期 `cycle` 与基线统计（`mean_skew/stddev_skew`），输出 `baselines.csv`。
- **detect（file/stream）**：对输入流逐行解析 `timestamp,id,dlc,data_hex`，用 RLS + 3σ 做异常检测与切段。
- **输出**：
  - **JSON 数组**：一次 detect 结束后写出 `attack_packets.json`（包含 `ts_series/residual_series/dlc_series/data_hex_series` 等细粒度字段）。
  - **NDJSON**：流式模式下每行一个 JSON 对象，可实时被后端消费；支持 `event="start"` 让前端“注入阶段”立刻看到告警。
- **切段策略（当前）**：
  - 连续异常达到阈值即进入攻击段（短周期 ID 更快触发）。
  - 通过 `MAX_ATTACK_FRAMES_PER_SEGMENT / MAX_ATTACK_DURATION_SEC` 强制打散超长段，避免“告警合并”导致分类困难。

### 2) 数据生成器：`backend-main/ids/attack_generator.py`
- **目的**：生成可控的 CAN 流（支持 single/mixed/multi-id/ethernet_chain），用于验证检测器切段与 ML 分类。
- **输出格式**：每行 `timestamp,id,dlc,data_hex`
- **真实 payload**：可从 `CarHackData` 抽样（若存在），否则退化为合成 payload。

### 3) ML 分类器：`backend-main/ids/ml_attack_classifier.py`
- **训练**：自动从生成器采样数据 → 运行 C++ detect → 抽取与“期望攻击段”重叠最大的告警包作为训练样本 → 训练 RandomForest 并持久化。
- **特征**（当前）：除 `mean/std/duration/frame_count` 外，包含 `residual_series` 的分位数/波动/趋势、以及 `ts_series` 的间隔统计（对区分 DoS/Fuzzy/RPM/gear 很关键）。
- **输出**：`attack_type/confidence/probabilities` + 原始 detail（C++ 告警包）。

### 4) Django 后端 + 前端：`backend-main/ids/views.py` + `backend-main/ids/templates/dashboard.html`
- **start_monitor**：按用户选择的模式生成流，启动 C++ detect（NDJSON），实时接收告警并写入 `upload_queue/`。
- **poll_monitor**：前端轮询获取最新告警、阶段信息（injecting/training/classify 等）并更新表格展示。

## 详细运行步骤（Windows / PowerShell）
### 0) 环境准备
- **Python**：建议 3.10+（需安装 Django、sklearn、joblib 等）
- **编译器**：MinGW-w64 的 `g++`（支持 `-std=c++17`）

### 1) 编译 C++（生成 `ClockIDS.exe`）
在仓库根目录执行：
```powershell
cd "C:\Users\Luyutong\Desktop\ClockIDS-ver1"
g++ -O2 -std=c++17 .\src\embedded\ClockIDS.cpp -o .\src\embedded\ClockIDS.exe
```

### 2) 启动 Django 可视化面板
```powershell
cd "C:\Users\Luyutong\Desktop\ClockIDS-ver1\backend-main"
python .\manage.py runserver
```
浏览器打开 Django 输出的本地地址，进入监控面板后选择模式、参数并点击开始。

### 3) 运行端到端验证（推荐先跑这个确认正确性）
```powershell
cd "C:\Users\Luyutong\Desktop\ClockIDS-ver1\backend-main"
python .\manage.py verify_system `
  --trials 1 `
  --pre_frames 200 `
  --attack_frames 200 `
  --post_frames 200 `
  --num_attacks 3 `
  --ecu_id 0690 `
  --ecu_ids "0690,0329,00a0"
```
输出会给出：
- **Single-ID**：分类正确率、段重叠命中率
- **Mixed Single-ID**：每段是否找到正确标签（按重叠判断）
- **Mixed Multi-ID**：多 ID 每段命中情况（按重叠判断）

### 4) 结果文件（落盘 JSON）
- `upload_queue/`：ClockIDS 检测到异常后立即写入的 JSON 报告（适合后续上传/回放/离线 ML 复训）。

## 当前性能与已知瓶颈（以最近一次验证为准）
### 当前性能（verify_system）
- **Mixed Multi-ID**：segment correct rate **6/9 = 66.67%**
- **Mixed Single-ID**：segment correct rate **3/3 = 100%**
- **Single-ID**：分类准确率 **4/4 = 100%**（段严格 time-match 仍偏苛刻，但重叠命中稳定）

### 已知瓶颈/风险点
- **短周期 ID（例如 0329）**：更容易受多 ID 交错与周期估计误差影响，导致段边界与类型混淆，是 Multi-ID 的主要误差来源。
- **训练耗时**：ML 训练样本量增大后（默认 `samples_per_class=80 / max_total_samples=1200`），首次训练会更久，但通常会带来更稳定的置信度。

