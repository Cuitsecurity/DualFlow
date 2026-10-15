import pandas as pd
from sklearn.model_selection import train_test_split
import os
import argparse
from pathlib import Path

parser = argparse.ArgumentParser(description="Stratified 80/10/10 split of MultiFlow feature CSV.")
parser.add_argument("--input", required=True)
parser.add_argument("--output-dir", required=True)
args = parser.parse_args()
output_dir = Path(args.output_dir)
output_dir.mkdir(parents=True, exist_ok=True)

# 读取 CSV
df = pd.read_csv(args.input)

# X = 特征列, y = 标签列
X = df.drop(columns=["label"])
y = df["label"]

# 第一次划分：80% 训练集 / 20% 临时集
X_train, X_temp, y_train, y_temp = train_test_split(
    X, y, test_size=0.2, stratify=y, random_state=41
)

# 第二次划分：临时集 50% 验证 / 50% 测试 → 各占总数据 10%
X_valid, X_test, y_valid, y_test = train_test_split(
    X_temp, y_temp, test_size=0.5, stratify=y_temp, random_state=42
)

# 输出路径，如果不存在则创建


# 保存 CSV
X_train.assign(label=y_train).to_csv(output_dir / "train.csv", index=False)
X_valid.assign(label=y_valid).to_csv(output_dir / "valid.csv", index=False)
X_test.assign(label=y_test).to_csv(output_dir / "test.csv", index=False)

print("划分完成:")
print(f"训练集: {len(X_train)} 流")
print(f"验证集: {len(X_valid)} 流")
print(f"测试集: {len(X_test)} 流")