from tail_detector import train_tail_detector

# 训练模型（默认开启所有开关）
detector, params = train_tail_detector(
    benign_path="data/Benign_data.csv",
    malicious_train_path="data/merged_filtered_data_train.csv",
    output_model_path="models/detector.pkl",
    n_trials=50,  # Optuna搜索次数
    beta=1.0,     # F-beta分数的beta值
    fpr_low=5e-5, # FPR搜索下限
    fpr_high=2e-2 # FPR搜索上限
)

print("\nTraining completed successfully!")
print(f"Best parameters: {params['best_params']}")
print(f"Threshold: {params['threshold']:.6f}")
print(f"Model saved to: models/tail_detector_model.pkl")
