import os
from .core import TailDetector
import numpy as np
from .utils import (
    load_csv, extract_xy, 
    threshold_under_fpr_exact, 
    evaluate_scores
)
from typing import Tuple, Dict, Any, Optional

def load_tail_detector(model_path: str) -> TailDetector:
    """
    加载训练好的TailDetector模型
    
    Args:
        model_path: 模型文件路径
        
    Returns:
        detector: 加载的检测器（包含阈值）
    """
    if not os.path.exists(model_path):
        raise FileNotFoundError(f"Model file not found: {model_path}")
    
    detector = TailDetector.load(model_path)
    return detector

def predict_with_tail_detector(
    detector: TailDetector,
    test_data_path: str,
    return_scores: bool = False
) -> Tuple[np.ndarray, Optional[np.ndarray], Dict[str, float]]:
    """
    使用加载的模型进行预测
    
    Args:
        detector: 加载的TailDetector模型
        test_data_path: 测试数据CSV路径
        return_scores: 是否返回原始分数
        
    Returns:
        predictions: 预测结果 (0=benign, 1=malicious)
        scores: 原始异常分数（如果return_scores=True）
        metrics: 评估指标（如果测试数据包含标签）
    """
    # 加载测试数据
    test_df = load_csv(test_data_path)
    X_test, y_test, _ = extract_xy(test_df)
    
    # 获取特征列
    feature_cols = detector.feature_cols_
    X_test = X_test[feature_cols]
    
    # 计算分数和预测
    scores = detector.score_samples(X_test)
    predictions = (scores >= detector.get_threshold()).astype(int)
    
    # 评估（如果存在标签）
    metrics = {}
    if y_test is not None and len(y_test) > 0:
        # 分离良性/恶意测试样本
        benign_mask = (y_test == 0)
        mal_mask = (y_test == 1)
        
        if np.any(benign_mask) and np.any(mal_mask):
            z_b_test = scores[benign_mask]
            z_m_test = scores[mal_mask]
            
            metrics = evaluate_scores(
                z_b_test, 
                z_m_test, 
                detector.get_threshold(), 
                beta=4.0  # 默认使用F4
            )
    
    if return_scores:
        return predictions, scores, metrics
    else:
        return predictions, None, metrics

def evaluate_tail_detector(
    model_path: str,
    benign_cal_path: str,
    test_data_path: str
) -> Dict[str, float]:
    """
    评估训练好的模型
    
    Args:
        model_path: 模型文件路径
        benign_cal_path: 用于校准阈值的良性数据路径
        test_data_path: 测试数据路径
        
    Returns:
        metrics: 评估指标
    """
    # 加载模型
    detector = load_tail_detector(model_path)
    
    # 加载校准数据（良性）
    cal_df = load_csv(benign_cal_path)
    X_cal, _, feat_cols = extract_xy(cal_df)
    X_cal = X_cal[feat_cols]
    
    # 计算校准集分数
    z_cal = detector.score_samples(X_cal)
    
    # 加载测试数据
    test_df = load_csv(test_data_path)
    X_test, y_test, _ = extract_xy(test_df)
    X_test = X_test[feat_cols]
    
    # 分离良性/恶意测试样本
    benign_mask = (y_test == 0)
    mal_mask = (y_test == 1)
    
    z_b_test = detector.score_samples(X_test[benign_mask])
    z_m_test = detector.score_samples(X_test[mal_mask])
    
    # 使用模型中保存的阈值
    thr = detector.get_threshold()
    
    # 评估
    metrics = evaluate_scores(z_b_test, z_m_test, thr, beta=4.0)
    
    return metrics
