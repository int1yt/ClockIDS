#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <deque>
#include <unordered_map>
#include <cmath>
#include <algorithm>
#include <iomanip>
#include <numeric>
#include <windows.h>
#include <chrono>

// ---------- 配置参数 ----------
const double LAMBDA_ER = 3.0;                    // 3-sigma 阈值
const double RLS_FORGET_FACTOR = 0.99;
const double RLS_P_INIT = 100.0;
const int WINDOW_SIZE = 30;                      // 偏斜滑动窗口大小
const int MIN_MSGS_FOR_CYCLE = 5;
const int CYCLE_UPDATE_INTERVAL = 100;
const int CYCLE_SAMPLE_SIZE = 100;
const int PROGRESS_INTERVAL = 1000;
const int MIN_CONSECUTIVE_ATTACKS = 1;            // 连续异常帧数达到此值才触发告警
const int CONTEXT_BEFORE = 5;                    // 攻击开始前保留的帧数
const int CONTEXT_AFTER = 5;                     // 攻击结束后保留的帧数
const double CYCLE_VARIATION_THRESHOLD = 0.2;    // 间隔变异系数阈值，超过则视为非周期

// ---------- 数据结构 ----------
struct ECUState {
    double t0;                                   // 第一个消息的时间戳
    int count;                                   // 已处理的消息总数
    double cycle;                                // 当前估计的周期
    int last_cycle_update;                       // 上次更新周期时的消息计数
    bool cycle_valid;                            // 周期是否有效（周期性）

    // RLS 参数
    double O_acc;
    double S;
    double P;

    // 偏斜滑动窗口
    std::deque<double> skew_window;

    // 训练阶段保存的基线
    double mean_skew;
    double stddev_skew;
    bool baseline_ready;                         // 基线是否已建立

    // 攻击状态跟踪（检测阶段使用）
    int consecutive_attacks;                     // 连续攻击帧数
    double attack_start_time;
    std::string attack_start_raw;
    double attack_skew_sum;
    double attack_skew_sq_sum;
    int attack_frame_count;
    std::vector<std::string> attack_context;     // 攻击期间的所有原始行
    std::vector<std::string> pre_context;        // 攻击前的上下文（暂存）

    // 构造函数
    ECUState(double first_ts)
        : t0(first_ts), count(1), cycle(0.0), last_cycle_update(1), cycle_valid(false),
          O_acc(0.0), S(0.0), P(RLS_P_INIT),
          mean_skew(0.0), stddev_skew(0.0), baseline_ready(false),
          consecutive_attacks(0), attack_start_time(0.0), attack_start_raw(""),
          attack_skew_sum(0.0), attack_skew_sq_sum(0.0), attack_frame_count(0) {}
};

// 检测阶段独立状态（与训练基线分离）
struct DetectState {
    double t0;                                   // 检测文件中该 ID 第一个时间戳
    int count;                                   // 已处理消息数
    double O_acc;                                // 累积绝对误差
    double S;                                    // RLS 估计的偏斜
    double P;                                    // RLS 协方差
    std::deque<double> skew_window;              // 偏斜滑动窗口
    double current_cycle;                        // 动态更新的周期
    int consecutive_attacks;
    double attack_start_time;
    std::string attack_start_raw;
    double attack_skew_sum;
    double attack_skew_sq_sum;
    int attack_frame_count;
    std::vector<std::string> attack_context;
    std::vector<std::string> pre_context;

    DetectState(double first_ts)
        : t0(first_ts), count(1), O_acc(0.0), S(0.0), P(RLS_P_INIT),
          current_cycle(0.0), consecutive_attacks(0), attack_start_time(0.0),
          attack_skew_sum(0.0), attack_skew_sq_sum(0.0), attack_frame_count(0) {}
};

// 训练结果基线
struct Baseline {
    double cycle;
    double mean_skew;
    double stddev_skew;
    bool valid;
    Baseline() : cycle(0.0), mean_skew(0.0), stddev_skew(0.0), valid(false) {}
};

// 全局变量
std::unordered_map<std::string, ECUState> ecu_states;   // 训练用
std::unordered_map<std::string, Baseline> baselines;    // 训练结果

// ---------- 辅助函数 ----------
std::string escape_json(const std::string& s) {
    std::ostringstream oss;
    for (char c : s) {
        switch (c) {
            case '"': oss << "\\\""; break;
            case '\\': oss << "\\\\"; break;
            case '\b': oss << "\\b"; break;
            case '\f': oss << "\\f"; break;
            case '\n': oss << "\\n"; break;
            case '\r': oss << "\\r"; break;
            case '\t': oss << "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    oss << "\\u" << std::hex << std::setw(4) << std::setfill('0') << (int)c;
                } else {
                    oss << c;
                }
                break;
        }
    }
    return oss.str();
}

// 解析带标签的行（修正ID提取）
bool parse_timestamp_line(const std::string& line, double& ts, std::string& id, std::string& raw_data) {
    size_t ts_pos = line.find("Timestamp:");
    if (ts_pos == std::string::npos) return false;
    std::stringstream ss(line.substr(ts_pos + 10));
    if (!(ss >> ts)) return false;

    size_t id_pos = line.find("ID:");
    if (id_pos == std::string::npos) return false;
    size_t id_start = id_pos + 3;
    while (id_start < line.size() && std::isspace(line[id_start])) ++id_start;
    size_t id_end = line.find_first_of(" \t", id_start);
    if (id_end == std::string::npos) id_end = line.size();
    id = line.substr(id_start, id_end - id_start);
    if (id.empty()) return false;

    raw_data = line;
    return true;
}

// 解析CSV行
bool parse_csv_line(const std::string& line, double& ts, std::string& id, std::string& raw_data) {
    std::stringstream ss(line);
    std::string token;
    if (!std::getline(ss, token, ',')) return false;
    try { ts = std::stod(token); } catch (...) { return false; }
    if (!std::getline(ss, token, ',')) return false;
    id = token;
    if (id.empty()) return false;
    raw_data = line;
    return true;
}

bool parse_line(const std::string& line, double& ts, std::string& id, std::string& raw_data) {
    if (line.find("Timestamp:") != std::string::npos)
        return parse_timestamp_line(line, ts, id, raw_data);
    else
        return parse_csv_line(line, ts, id, raw_data);
}

// 通用周期计算函数（返回周期，变异系数通过引用传出）
double compute_cycle(const std::deque<double>& timestamps, double& variation) {
    if (timestamps.size() < 2) return 0.0;
    std::vector<double> diffs;
    diffs.reserve(timestamps.size() - 1);
    for (size_t i = 1; i < timestamps.size(); ++i) {
        diffs.push_back(timestamps[i] - timestamps[i-1]);
    }
    size_t mid = diffs.size() / 2;
    auto med_iter = diffs.begin() + static_cast<ptrdiff_t>(mid);
    std::nth_element(diffs.begin(), med_iter, diffs.end());
    double median = *med_iter;
    std::vector<double> filtered;
    for (double d : diffs) {
        if (d <= 2.0 * median) filtered.push_back(d);
    }
    if (filtered.empty()) return 0.0;
    double sum = std::accumulate(filtered.begin(), filtered.end(), 0.0);
    double cycle = sum / static_cast<double>(filtered.size());
    double sq_sum = 0.0;
    for (double d : filtered) {
        double diff = d - cycle;
        sq_sum += diff * diff;
    }
    double stddev = std::sqrt(sq_sum / static_cast<double>(filtered.size()));
    variation = (cycle > 0) ? (stddev / cycle) : 1.0;
    return cycle;
}

bool update_cycle(ECUState& state, const std::deque<double>& timestamps, double& variation) {
    if (state.count < MIN_MSGS_FOR_CYCLE) return false;
    double new_cycle = compute_cycle(timestamps, variation);
    if (new_cycle <= 0) return false;
    state.cycle = new_cycle;
    return true;
}

void rls_update(ECUState& state, double t, double e) {
    double lam_inv = 1.0 / RLS_FORGET_FACTOR;
    double G = (lam_inv * state.P * t) / (1.0 + lam_inv * t * t * state.P);
    state.P = lam_inv * (state.P - G * t * state.P);
    state.S = state.S + G * e;
}

void rls_update(DetectState& state, double t, double e) {
    double lam_inv = 1.0 / RLS_FORGET_FACTOR;
    double G = (lam_inv * state.P * t) / (1.0 + lam_inv * t * t * state.P);
    state.P = lam_inv * (state.P - G * t * state.P);
    state.S = state.S + G * e;
}

void update_baseline(ECUState& state) {
    if (state.skew_window.size() < static_cast<size_t>(WINDOW_SIZE) / 2) return;
    double sum = 0.0;
    for (double s : state.skew_window) sum += s;
    state.mean_skew = sum / static_cast<double>(state.skew_window.size());
    double sq_sum = 0.0;
    for (double s : state.skew_window) sq_sum += (s - state.mean_skew) * (s - state.mean_skew);
    state.stddev_skew = std::sqrt(sq_sum / static_cast<double>(state.skew_window.size()));
    state.baseline_ready = true;
}

// ---------- 训练 ----------
void train_on_file(const std::string& input_file) {
    std::ifstream fin(input_file);
    if (!fin.is_open()) {
        std::cerr << "[Error] Cannot open training file: " << input_file << std::endl;
        return;
    }
    std::cout << "Training on: " << input_file << std::endl;

    std::unordered_map<std::string, std::deque<double>> id_timestamps;
    std::string line;
    int line_num = 0, total_msgs = 0, parse_errors = 0;

    while (std::getline(fin, line)) {
        ++line_num;
        if (line.empty()) continue;
        double ts;
        std::string id, raw;
        if (!parse_line(line, ts, id, raw)) {
            ++parse_errors;
            if (parse_errors <= 10) std::cerr << "  Warning: Failed to parse line " << line_num << std::endl;
            continue;
        }
        total_msgs++;

        auto it = ecu_states.find(id);
        if (it == ecu_states.end()) {
            ecu_states.emplace(id, ECUState(ts));
            it = ecu_states.find(id);
        }
        ECUState& state = it->second;

        auto& ts_queue = id_timestamps[id];
        ts_queue.push_back(ts);
        if (ts_queue.size() > static_cast<size_t>(CYCLE_SAMPLE_SIZE)) ts_queue.pop_front();

        state.count++;
        int cur_count = state.count;

        if (cur_count - state.last_cycle_update >= CYCLE_UPDATE_INTERVAL) {
            double variation = 0.0;
            bool ok = update_cycle(state, ts_queue, variation);
            if (ok && variation <= CYCLE_VARIATION_THRESHOLD) {
                state.cycle_valid = true;
            } else {
                state.cycle_valid = false;
            }
            state.last_cycle_update = cur_count;
        }

        if (!state.cycle_valid || state.cycle <= 0) continue;

        double predicted = state.t0 + (cur_count - 1) * state.cycle;
        double O = ts - predicted;
        state.O_acc += std::abs(O);

        double t = ts - state.t0;
        double e = state.O_acc - state.S * t;
        rls_update(state, t, e);

        state.skew_window.push_back(state.S);
        if (state.skew_window.size() > static_cast<size_t>(WINDOW_SIZE)) state.skew_window.pop_front();

        if (total_msgs % PROGRESS_INTERVAL == 0) {
            std::cout << "  Processed " << total_msgs << " messages..." << std::endl;
        }
    }
    fin.close();

    for (auto& pair : ecu_states) {
        if (pair.second.cycle_valid) {
            update_baseline(pair.second);
        }
        Baseline bl;
        bl.cycle = pair.second.cycle;
        bl.mean_skew = pair.second.mean_skew;
        bl.stddev_skew = pair.second.stddev_skew;
        bl.valid = pair.second.baseline_ready;
        baselines[pair.first] = bl;

        if (pair.second.baseline_ready) {
            std::cout << "  ID " << pair.first << ": cycle=" << pair.second.cycle
                      << ", mean_skew=" << pair.second.mean_skew
                      << ", stddev_skew=" << pair.second.stddev_skew << std::endl;
        } else {
            std::cout << "  ID " << pair.first << ": insufficient data or non-periodic, baseline not set" << std::endl;
        }
    }
    std::cout << "Training completed. Total messages: " << total_msgs
              << ", Parse errors: " << parse_errors << std::endl;
}

// ---------- 检测 ----------
void detect_on_file(const std::string& input_file, const std::string& output_prefix) {
    std::ifstream fin(input_file);
    if (!fin.is_open()) {
        std::cerr << "[Error] Cannot open detection file: " << input_file << std::endl;
        return;
    }
    std::cout << "Detecting on: " << input_file << std::endl;

    // 检测独立状态
    std::unordered_map<std::string, DetectState> detect_states;
    // 用于动态周期的队列和计数器
    std::unordered_map<std::string, std::deque<double>> ts_queues;
    std::unordered_map<std::string, int> last_cycle_update_counts;
    // 用于上下文的环形缓冲区
    std::unordered_map<std::string, std::deque<std::string>> recent_msgs;
    // 用于记录偏斜的CSV文件
    std::unordered_map<std::string, std::ofstream> skew_files;

    std::string line;
    int line_num = 0, total_msgs = 0, parse_errors = 0, attack_alerts = 0;
    std::vector<std::string> attack_packets;
    double first_ts = 0.0, last_ts = 0.0;
    bool first_ts_set = false;

    while (std::getline(fin, line)) {
        ++line_num;
        if (line.empty()) continue;
        double ts;
        std::string id, raw;
        if (!parse_line(line, ts, id, raw)) {
            ++parse_errors;
            if (parse_errors <= 10) std::cerr << "  Warning: Failed to parse line " << line_num << std::endl;
            continue;
        }
        total_msgs++;
        if (!first_ts_set) {
            first_ts = ts;
            first_ts_set = true;
        }
        last_ts = ts;

        auto bl_it = baselines.find(id);
        if (bl_it == baselines.end() || !bl_it->second.valid) continue;

        // 获取或创建检测状态
        auto ds_it = detect_states.find(id);
        if (ds_it == detect_states.end()) {
            ds_it = detect_states.emplace(id, DetectState(ts)).first;
            ds_it->second.current_cycle = bl_it->second.cycle;
            ts_queues[id] = std::deque<double>();
            last_cycle_update_counts[id] = 0;
            // 打开偏斜记录文件
            std::string skew_filename = output_prefix + "_skew_" + id + ".csv";
            skew_files[id].open(skew_filename);
            if (skew_files[id].is_open()) {
                skew_files[id] << "timestamp,skew,is_attack\n";
            } else {
                std::cerr << "  Warning: Cannot open skew file for ID " << id << std::endl;
            }
        }
        DetectState& ds = ds_it->second;

        // 更新时间戳队列（用于周期更新）
        auto& ts_queue = ts_queues[id];
        ts_queue.push_back(ts);
        if (ts_queue.size() > static_cast<size_t>(CYCLE_SAMPLE_SIZE)) ts_queue.pop_front();

        // 定期更新周期
        ds.count++;
        if (ds.count - last_cycle_update_counts[id] >= CYCLE_UPDATE_INTERVAL) {
            double variation = 0.0;
            double new_cycle = compute_cycle(ts_queue, variation);
            if (new_cycle > 0 && variation <= CYCLE_VARIATION_THRESHOLD) {
                ds.current_cycle = new_cycle;
            }
            last_cycle_update_counts[id] = ds.count;
        }

        // 预测当前时间（使用动态周期）
        double predicted = ds.t0 + (ds.count - 1) * ds.current_cycle;
        double O = ts - predicted;
        ds.O_acc += std::abs(O);
        double t = ts - ds.t0;
        double e = ds.O_acc - ds.S * t;
        rls_update(ds, t, e);
        ds.skew_window.push_back(ds.S);
        if (ds.skew_window.size() > static_cast<size_t>(WINDOW_SIZE)) ds.skew_window.pop_front();

        bool attack = std::abs(ds.S - bl_it->second.mean_skew) > LAMBDA_ER * bl_it->second.stddev_skew;

        // 写入偏斜记录
        auto& skew_file = skew_files[id];
        if (skew_file.is_open()) {
            skew_file << std::fixed << std::setprecision(6)
                      << ts << "," << ds.S << "," << (attack ? 1 : 0) << "\n";
        }

        // 保存最近消息用于上下文
        auto& msg_queue = recent_msgs[id];
        msg_queue.push_back(raw);
        if (msg_queue.size() > static_cast<size_t>(CONTEXT_BEFORE + CONTEXT_AFTER + 1)) msg_queue.pop_front();

        if (attack) {
            if (ds.consecutive_attacks == 0) {
                // 攻击开始
                ds.attack_start_time = ts;
                ds.attack_start_raw = raw;
                ds.attack_skew_sum = ds.S;
                ds.attack_skew_sq_sum = ds.S * ds.S;
                ds.attack_frame_count = 1;
                ds.attack_context.clear();
                ds.attack_context.push_back(raw);
                // 保存攻击前上下文
                ds.pre_context.clear();
                int before = std::min(static_cast<int>(msg_queue.size()), CONTEXT_BEFORE);
                if (before > 0) {
                    auto it_before = msg_queue.end();
                    std::advance(it_before, -before);
                    for (int i = 0; i < before; ++i) {
                        ds.pre_context.push_back(*it_before);
                        ++it_before;
                    }
                }
            } else {
                ds.attack_skew_sum += ds.S;
                ds.attack_skew_sq_sum += ds.S * ds.S;
                ds.attack_frame_count++;
                ds.attack_context.push_back(raw);
            }
            ds.consecutive_attacks++;
        } else {
            if (ds.consecutive_attacks >= MIN_CONSECUTIVE_ATTACKS) {
                double attack_mean = ds.attack_skew_sum / ds.attack_frame_count;
                double attack_var = (ds.attack_skew_sq_sum / ds.attack_frame_count) - attack_mean * attack_mean;
                double attack_std = std::sqrt(std::max(0.0, attack_var));
                double duration = ts - ds.attack_start_time;

                // 收集攻击后上下文
                std::vector<std::string> post_context;
                int after = 0;
                auto it_post = msg_queue.rbegin();
                while (after < CONTEXT_AFTER && it_post != msg_queue.rend()) {
                    post_context.push_back(*it_post);
                    ++after;
                    ++it_post;
                }
                std::reverse(post_context.begin(), post_context.end());

                std::ostringstream alert;
                alert << std::fixed << std::setprecision(6);
                alert << "{\n  \"attack_id\": \"" << id << "\",\n"
                      << "  \"start_time\": " << ds.attack_start_time << ",\n"
                      << "  \"end_time\": " << ts << ",\n"
                      << "  \"duration\": " << duration << ",\n"
                      << "  \"frame_count\": " << ds.attack_frame_count << ",\n"
                      << "  \"mean_skew\": " << attack_mean << ",\n"
                      << "  \"stddev_skew\": " << attack_std << ",\n"
                      << "  \"pre_context\": [\n";
                for (size_t i = 0; i < ds.pre_context.size(); ++i) {
                    alert << "    \"" << escape_json(ds.pre_context[i]) << "\""
                          << (i+1 < ds.pre_context.size() ? "," : "") << "\n";
                }
                alert << "  ],\n  \"attack_frames\": [\n";
                for (size_t i = 0; i < ds.attack_context.size(); ++i) {
                    alert << "    \"" << escape_json(ds.attack_context[i]) << "\""
                          << (i+1 < ds.attack_context.size() ? "," : "") << "\n";
                }
                alert << "  ],\n  \"post_context\": [\n";
                for (size_t i = 0; i < post_context.size(); ++i) {
                    alert << "    \"" << escape_json(post_context[i]) << "\""
                          << (i+1 < post_context.size() ? "," : "") << "\n";
                }
                alert << "  ]\n}\n";
                attack_packets.push_back(alert.str());
                attack_alerts++;
            }
            // 重置攻击状态
            ds.consecutive_attacks = 0;
            ds.attack_frame_count = 0;
            ds.attack_context.clear();
            ds.pre_context.clear();
        }
    }
    fin.close();

    // 处理文件末尾未结束的攻击段
    for (auto& pair : detect_states) {
        const std::string& id = pair.first;
        DetectState& ds = pair.second;
        if (ds.consecutive_attacks >= MIN_CONSECUTIVE_ATTACKS) {
            double attack_mean = ds.attack_skew_sum / ds.attack_frame_count;
            double attack_var = (ds.attack_skew_sq_sum / ds.attack_frame_count) - attack_mean * attack_mean;
            double attack_std = std::sqrt(std::max(0.0, attack_var));
            double duration = last_ts - ds.attack_start_time;

            // 收集攻击后上下文（文件末尾，取最后几帧）
            std::vector<std::string> post_context;
            auto& msg_queue = recent_msgs[id];
            int after = 0;
            auto it_post = msg_queue.rbegin();
            while (after < CONTEXT_AFTER && it_post != msg_queue.rend()) {
                post_context.push_back(*it_post);
                ++after;
                ++it_post;
            }
            std::reverse(post_context.begin(), post_context.end());

            std::ostringstream alert;
            alert << std::fixed << std::setprecision(6);
            alert << "{\n  \"attack_id\": \"" << id << "\",\n"
                  << "  \"start_time\": " << ds.attack_start_time << ",\n"
                  << "  \"end_time\": " << last_ts << ",\n"
                  << "  \"duration\": " << duration << ",\n"
                  << "  \"frame_count\": " << ds.attack_frame_count << ",\n"
                  << "  \"mean_skew\": " << attack_mean << ",\n"
                  << "  \"stddev_skew\": " << attack_std << ",\n"
                  << "  \"pre_context\": [\n";
            for (size_t i = 0; i < ds.pre_context.size(); ++i) {
                alert << "    \"" << escape_json(ds.pre_context[i]) << "\""
                      << (i+1 < ds.pre_context.size() ? "," : "") << "\n";
            }
            alert << "  ],\n  \"attack_frames\": [\n";
            for (size_t i = 0; i < ds.attack_context.size(); ++i) {
                alert << "    \"" << escape_json(ds.attack_context[i]) << "\""
                      << (i+1 < ds.attack_context.size() ? "," : "") << "\n";
            }
            alert << "  ],\n  \"post_context\": [\n";
            for (size_t i = 0; i < post_context.size(); ++i) {
                alert << "    \"" << escape_json(post_context[i]) << "\""
                      << (i+1 < post_context.size() ? "," : "") << "\n";
            }
            alert << "  ]\n}\n";
            attack_packets.push_back(alert.str());
            attack_alerts++;
        }
    }

    // 关闭所有偏斜文件
    for (auto& pair : skew_files) {
        pair.second.close();
    }

    std::string outfile = output_prefix + "_attack_packets.json";
    std::ofstream fout(outfile);
    if (!fout.is_open()) {
        std::cerr << "[Error] Cannot create output file: " << outfile << std::endl;
        return;
    }
    fout << "[\n";
    for (size_t i = 0; i < attack_packets.size(); ++i) {
        fout << attack_packets[i] << (i+1 < attack_packets.size() ? ",\n" : "\n");
    }
    fout << "]\n";
    fout.close();

    std::cout << "Detection completed. Total messages: " << total_msgs
              << ", Parse errors: " << parse_errors
              << ", Attack alerts: " << attack_alerts
              << "\n  Attack packets saved to: " << outfile
              << "\n  Skew CSV files saved with prefix: " << output_prefix << "_skew_*.csv"
              << "\n  File time range: " << std::fixed << std::setprecision(6)
              << first_ts << " - " << last_ts
              << ", duration: " << (last_ts - first_ts) << " seconds" << std::endl;
}

// ---------- 主函数 ----------
int main() {
    // 文件路径（根据实际情况修改）
    std::string normal_file = "../../CarHackData/normal_run_data.txt";
    std::vector<std::string> attack_files = {
        "../../CarHackData/DoS_dataset.csv",
        "../../CarHackData/Fuzzy_dataset.csv",
        "../../CarHackData/gear_dataset.csv",
        "../../CarHackData/RPM_dataset.csv"
    };

    train_on_file(normal_file);

    for (const auto& attack_file : attack_files) {
        std::string prefix = attack_file.substr(0, attack_file.find_last_of('.'));
        detect_on_file(attack_file, prefix);
    }

    std::cout << "All tasks completed." << std::endl;
    system("pause");
    return 0;
}