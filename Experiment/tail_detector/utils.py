import os
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    precision_recall_fscore_support,
    confusion_matrix,
    roc_auc_score,
)

def load_csv(path: str) -> pd.DataFrame:
    """安全加载CSV文件"""
    if not os.path.exists(path):
        raise FileNotFoundError(f"File not found: {path}")
    return pd.read_csv(path)

def extract_xy(df: pd.DataFrame) -> tuple:
    """从DataFrame中提取特征和标签"""
    if df.shape[1] < 4:
        raise ValueError(f"Expect >=4 columns, got {df.shape[1]}")
    
    label_col = df.columns[1]
    feature_cols = list(df.columns[3:])
    
    y = pd.to_numeric(df[label_col], errors="coerce").fillna(0).astype(int).values
    X = df.loc[:, feature_cols].copy()
    
    for c in feature_cols:
        X[c] = pd.to_numeric(X[c], errors="coerce")
    
    return X, y, feature_cols

def fbeta(p: float, r: float, beta: float) -> float:
    """计算F-beta分数"""
    p = float(p); r = float(r); beta = float(beta)
    if p <= 0 or r <= 0:
        return 0.0
    b2 = beta * beta
    return (1 + b2) * p * r / (b2 * p + r)

def threshold_under_fpr_exact(benign_scores: np.ndarray, max_fpr: float) -> float:
    """
    计算满足FPR约束的阈值
    确保：mean(score >= thr) <= max_fpr
    """
    s = np.asarray(benign_scores, dtype=float)
    n = len(s)
    max_fpr = float(max_fpr)
    
    if n == 0:
        raise ValueError("Empty benign_scores")
    if max_fpr <= 0:
        return float(np.nextafter(np.max(s), np.inf))

    allowed_fp = int(np.floor(max_fpr * n))
    if allowed_fp <= 0:
        return float(np.nextafter(np.max(s), np.inf))

    s_desc = np.sort(s)[::-1]
    thr = float(s_desc[allowed_fp - 1])
    
    # 精确调整阈值
    while float(np.mean(s >= thr)) > max_fpr:
        thr = float(np.nextafter(thr, np.inf))
        if thr > float(np.max(s)):
            break
    return float(thr)

def evaluate_scores(z_b: np.ndarray, z_m: np.ndarray, thr: float, beta: float) -> dict[str, float]:
    """评估模型性能"""
    z_b = np.asarray(z_b, dtype=float)
    z_m = np.asarray(z_m, dtype=float)
    
    y_true = np.concatenate([np.zeros_like(z_b, dtype=int), np.ones_like(z_m, dtype=int)])
    y_pred = np.concatenate([(z_b >= thr).astype(int), (z_m >= thr).astype(int)])

    p, r, f1, _ = precision_recall_fscore_support(
        y_true, y_pred, average="binary", zero_division=0
    )
    
    fpr = float(np.mean(z_b >= thr))
    
    try:
        auc = float(roc_auc_score(y_true, np.concatenate([z_b, z_m])))
    except Exception:
        auc = float("nan")
        
    return {
        "precision": float(p),
        "recall": float(r),
        "f1": float(f1),
        f"f{beta}": float(fbeta(p, r, beta=beta)),
        "fpr": fpr,
        "auc": auc,
    }

def split_data(
    X_benign: pd.DataFrame,
    X_malicious: pd.DataFrame,
    seed: int = 42
) -> tuple:
    """划分训练/校准/测试数据集"""
    # 良性数据划分
    Xb_fit, Xb_tmp = train_test_split(X_benign, test_size=0.30, random_state=seed)
    Xb_cal, Xb_test = train_test_split(Xb_tmp, test_size=0.50, random_state=seed)
    
    # 恶意数据划分（确保至少有20个样本用于验证）
    if len(X_malicious) >= 20:
        Xm_fit, Xm_val = train_test_split(X_malicious, test_size=0.30, random_state=seed)
    else:
        Xm_fit, Xm_val = X_malicious, X_malicious
    
    return Xb_fit, Xb_cal, Xb_test, Xm_fit, Xm_val
