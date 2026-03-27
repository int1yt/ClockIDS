import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
import os
import glob

# 设置 matplotlib 支持中文（可选）
plt.rcParams['font.sans-serif'] = ['SimHei']
plt.rcParams['axes.unicode_minus'] = False

def plot_skew(csv_file, output_dir=None):
    """绘制单个偏斜 CSV 文件的曲线"""
    df = pd.read_csv(csv_file)
    if 'timestamp' not in df.columns or 'skew' not in df.columns or 'is_attack' not in df.columns:
        print(f"Warning: {csv_file} missing required columns, skip.")
        return

    t0 = df['timestamp'].iloc[0]
    df['rel_time'] = df['timestamp'] - t0

    base = os.path.basename(csv_file)
    parts = base.replace('_skew_', '_').split('_')
    if len(parts) >= 2:
        id_str = parts[-1].replace('.csv', '')
    else:
        id_str = "unknown"

    fig, ax = plt.subplots(figsize=(12, 6))
    ax.plot(df['rel_time'], df['skew'], 'b-', linewidth=0.8, label='Skew', alpha=0.7)

    attack_df = df[df['is_attack'] == 1]
    if not attack_df.empty:
        ax.scatter(attack_df['rel_time'], attack_df['skew'], 
                   c='red', s=10, label='Attack', alpha=0.6, edgecolors='none')

    ax.set_xlabel('Relative Time (seconds)')
    ax.set_ylabel('Skew (S)')
    ax.set_title(f'ID {id_str} - Skew over Time')
    ax.legend()
    ax.grid(True, linestyle='--', alpha=0.5)

    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
        out_file = os.path.join(output_dir, f'skew_plot_{id_str}.png')
        plt.savefig(out_file, dpi=150, bbox_inches='tight')
        print(f"Saved plot to {out_file}")
    else:
        plt.show()
    plt.close(fig)

def main():
    # ===== 修改此处为你的实际路径 =====
    # 绝对路径示例：
    # data_dir = r"C:\Users\Luyutong\Desktop\ClockIDS-ver1\CarHackData"
    # 或者使用相对路径（确保工作目录正确）：
    data_dir = "./CarHackData"   # 如果 CarHackData 在当前目录下
    # =================================

    # 如果目录不存在，尝试上级目录
    if not os.path.exists(data_dir):
        print(f"Directory {data_dir} not found. Trying '../../CarHackData'...")
        data_dir = "../../CarHackData"
        if not os.path.exists(data_dir):
            print(f"Directory {data_dir} also not found. Please set correct path in script.")
            return

    print(f"Using directory: {os.path.abspath(data_dir)}")
    pattern = os.path.join(data_dir, "*_skew_*.csv")
    csv_files = glob.glob(pattern)

    if not csv_files:
        print(f"No skew CSV files found in {data_dir} with pattern *_skew_*.csv")
        # 列出该目录下所有 CSV 文件，帮助诊断
        all_csv = glob.glob(os.path.join(data_dir, "*.csv"))
        print(f"All CSV files in {data_dir}: {all_csv}")
        return

    print(f"Found {len(csv_files)} skew files.")
    for f in csv_files:
        print(f"Processing {f}...")
        plot_skew(f, output_dir=data_dir)  # 图片保存在同一目录

    print("All plots generated.")

if __name__ == "__main__":
    main()