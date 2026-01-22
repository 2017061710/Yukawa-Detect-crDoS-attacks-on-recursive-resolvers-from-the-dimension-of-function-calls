from tail_detector import load_tail_detector, predict_with_tail_detector
import optuna
import numpy as np
import pandas as pd

# 加载模型
detector = load_tail_detector("models/detector.pkl")

# 进行预测（不返回分数）
predictions, _, _ = predict_with_tail_detector(
    detector=detector,
    test_data_path="data/merged_filtered_data_test.csv",
    return_scores=False
)

# 统计结果
malicious_count = np.sum(predictions)
total_count = len(predictions)
benign_count = total_count - malicious_count

print(f"检测完成! 共分析 {total_count} 个样本")
print(f"  良性样本: {benign_count} ({benign_count/total_count:.1%})")
print(f"  恶意样本: {malicious_count} ({malicious_count/total_count:.1%})")
