import optuna
import numpy as np
import pandas as pd

optuna.logging.set_verbosity(optuna.logging.WARNING)
from .core import TailDetector, ModuleSwitches
from .utils import (
    load_csv, extract_xy, split_data, 
    threshold_under_fpr_exact, evaluate_scores
)
from typing import Dict, Any, Tuple, Optional

def build_objective(
    Xb_fit: pd.DataFrame,
    Xb_cal: pd.DataFrame,
    Xm_val: pd.DataFrame,
    feat_cols: list,
    switches: ModuleSwitches,
    beta: float,
    fpr_low: float,
    fpr_high: float,
    fpr_penalty: float
) -> callable:
    """构建Optuna目标函数"""
    def objective(trial: optuna.Trial) -> float:
        # 超参数搜索空间
        max_fpr = trial.suggest_float("max_fpr_target", fpr_low, fpr_high, log=True)
        t0 = trial.suggest_float("t0", 0.0, 10.0) if switches.use_gate_t0 else 0.0
        gamma = trial.suggest_float("gamma", 0.3, 7.0) if switches.use_power_transform else 1.0
        trim_frac = trial.suggest_float("trim_frac", 0.001, 0.03)
        
        # 训练检测器
        det = TailDetector(
            t0=t0,
            gamma=gamma,
            trim_frac=trim_frac,
            switches=switches
        ).fit(Xb_fit, feat_cols)
        
        # 评估性能
        z_b = det.score_samples(Xb_cal)
        z_m = det.score_samples(Xm_val)
        thr = threshold_under_fpr_exact(z_b, max_fpr=max_fpr)
        metrics = evaluate_scores(z_b, z_m, thr, beta=beta)
        
        # 添加FPR惩罚项
        penalty = fpr_penalty * np.log10(max_fpr / fpr_low)
        f1 = metrics["f1"]
        
        # 记录关键指标
        trial.set_user_attr("f1", float(f1))
        trial.set_user_attr("fpr_target", float(max_fpr))
        trial.set_user_attr("fpr_actual", float(metrics["fpr"]))
        trial.set_user_attr("precision", float(metrics["precision"]))
        trial.set_user_attr("recall", float(metrics["recall"]))
        trial.set_user_attr("auc", float(metrics["auc"]))
        
        return float(f1) - penalty
    
    return objective

def train_tail_detector(
    benign_path: str,
    malicious_train_path: str,
    output_model_path: str,
    n_trials: int = 30,
    beta: float = 4.0,
    fpr_low: float = 1e-4,
    fpr_high: float = 2e-2,
    fpr_penalty: float = 0.03,
    seed: int = 42,
    verbose: bool = True
) -> Tuple[TailDetector, Dict[str, Any]]:
    """
    训练TailDetector模型并保存
    
    Args:
        benign_path: 良性数据CSV路径
        malicious_train_path: 恶意训练数据CSV路径
        output_model_path: 模型保存路径
        n_trials: Optuna搜索次数
        beta: F-beta分数的beta值
        fpr_low: FPR搜索下限
        fpr_high: FPR搜索上限
        fpr_penalty: FPR惩罚系数
        seed: 随机种子
        verbose: 是否显示详细日志
        
    Returns:
        detector: 训练好的检测器（包含阈值）
        best_params: 最佳超参数和性能指标
    """
    if verbose:
        print(f"Loading data from {benign_path} and {malicious_train_path}")
    
    # 加载数据
    benign_df = load_csv(benign_path)
    mal_train_df = load_csv(malicious_train_path)
    
    # 提取特征
    Xb, yb, feat_cols_b = extract_xy(benign_df)
    Xm_tr, ym_tr, _ = extract_xy(mal_train_df)
    
    # 确保特征一致
    feat_cols = [c for c in feat_cols_b if c in Xm_tr.columns]
    if not feat_cols:
        raise ValueError("No common feature columns among datasets.")
    
    Xb = Xb[feat_cols]
    Xm_tr = Xm_tr[feat_cols]
    
    # 只保留恶意样本
    Xm_train_mal = Xm_tr[ym_tr == 1] if np.any(ym_tr == 1) else Xm_tr
    
    if verbose:
        print(f"Found {len(feat_cols)} common features")
        print(f"Benign samples: {len(Xb)}, Malicious samples: {len(Xm_train_mal)}")
    
    # 数据划分
    Xb_fit, Xb_cal, Xb_test, Xm_fit, Xm_val = split_data(
        X_benign=Xb, 
        X_malicious=Xm_train_mal,
        seed=seed
    )
    
    if verbose:
        print("Data split completed:")
        print(f"  Training benign: {len(Xb_fit)}")
        print(f"  Calibration benign: {len(Xb_cal)}")
        print(f"  Testing benign: {len(Xb_test)}")
        print(f"  Training malicious: {len(Xm_fit)}")
        print(f"  Validation malicious: {len(Xm_val)}")
    
    # 配置Optuna
    sampler = optuna.samplers.TPESampler(seed=seed)
    pruner = optuna.pruners.MedianPruner(n_warmup_steps=max(10, n_trials // 6))
    study = optuna.create_study(
        direction="maximize", 
        sampler=sampler, 
        pruner=pruner
    )
    
    # 优化目标函数
    obj = build_objective(
        Xb_fit=Xb_fit, 
        Xb_cal=Xb_cal, 
        Xm_val=Xm_val, 
        feat_cols=feat_cols,
        switches=ModuleSwitches(),  # 默认开启所有开关
        beta=beta,
        fpr_low=fpr_low,
        fpr_high=fpr_high,
        fpr_penalty=fpr_penalty,
    )
    
    if verbose:
        print(f"Starting Optuna optimization with {n_trials} trials...")
    
    study.optimize(obj, n_trials=n_trials, show_progress_bar=verbose)
    
    # 获取最佳参数
    bp = study.best_params
    best_fpr = float(bp["max_fpr_target"])
    
    if verbose:
        print(f"\nOptimization completed. Best FPR target: {best_fpr:.2e}")
        print(f"Best objective value: {study.best_value:.4f}")
    
    # 用最佳参数训练最终模型
    detector = TailDetector(
        t0=float(bp["t0"]),
        gamma=float(bp["gamma"]),
        trim_frac=float(bp["trim_frac"]),
        switches=ModuleSwitches()  # 默认开启所有开关
    ).fit(Xb_fit, feat_cols)
    
    # 计算并保存阈值
    z_b_cal = detector.score_samples(Xb_cal)
    final_threshold = threshold_under_fpr_exact(z_b_cal, max_fpr=best_fpr)
    detector.set_threshold(final_threshold)
    
    if verbose:
        z_m_fit = detector.score_samples(Xm_fit)
        metrics = evaluate_scores(z_b_cal, z_m_fit, final_threshold, beta=beta)
        print("\nFinal model performance on calibration set:")
        print(f"  Precision: {metrics['precision']:.4f}")
        print(f"  Recall: {metrics['recall']:.4f}")
        print(f"  F1: {metrics['f1']:.4f}")
        print(f"  F{beta}: {metrics[f'f{beta}']:.4f}")
        print(f"  FPR: {metrics['fpr']:.2e}")
        print(f"  AUC: {metrics['auc']:.4f}")
        print(f"  Threshold: {final_threshold:.6f}")
    
    # 保存模型
    detector.save(output_model_path)
    
    if verbose:
        print(f"\nModel saved to {output_model_path}")
    
    # 返回结果
    return detector, {
        "best_params": bp,
        "best_fpr": best_fpr,
        "best_value": study.best_value,
        "threshold": final_threshold,
        "feature_cols": feat_cols
    }
