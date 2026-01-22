import numpy as np
import pandas as pd
import joblib
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, Tuple, Union
@dataclass(frozen=True)
class ModuleSwitches:
    """模块开关配置（默认全部开启）"""
    use_ties: bool = True
    two_sided: bool = True
    use_gate_t0: bool = True
    use_power_transform: bool = True

@dataclass
class TailDetector:
    """尾部异常检测器核心实现（默认全部开关开启）"""
    t0: float = 0.0
    gamma: float = 1.5
    trim_frac: float = 0.0
    eps: float = 1e-12
    threshold_: float = 0.0  # 保存的阈值
    
    switches: ModuleSwitches = field(default_factory=ModuleSwitches)
    
    # 内部状态（fit后填充）
    feature_cols_: List[str] = field(default_factory=list)
    sorted_benign_: List[np.ndarray] = field(default_factory=list)
    medians_: Optional[np.ndarray] = None
    loc_: float = 0.0
    scale_: float = 1.0

    def fit(self, X_benign: pd.DataFrame, feature_cols: List[str]) -> 'TailDetector':
        """使用良性数据拟合检测器"""
        self.feature_cols_ = feature_cols
        X = X_benign[feature_cols].values.astype(float)
        
        # 处理缺失值
        self.medians_ = np.nanmedian(X, axis=0)
        X = np.where(np.isnan(X), self.medians_, X)
        
        # 良性数据清洗（去除异常良性样本）
        if self.trim_frac > 0:
            row_stat = np.nanmax(X, axis=1)
            thr = np.quantile(row_stat, 1.0 - self.trim_frac)
            X = X[row_stat <= thr]
        
        # 存储排序后的良性数据
        self.sorted_benign_ = [np.sort(X[:, j]) for j in range(X.shape[1])]
        
        # 计算标准化参数（保持原逻辑）
        _ = self._raw_scores_from_array(X)
        self.loc_, self.scale_ = 0.0, 1.0
        return self

    def _pvalues(self, sarr: np.ndarray, xcol: np.ndarray) -> np.ndarray:
        """计算p值（处理重复值和双尾检验）"""
        n = len(sarr)
        
        if self.switches.use_ties:
            lo = np.searchsorted(sarr, xcol, side="left")
            hi = np.searchsorted(sarr, xcol, side="right")
            eq = hi - lo
            
            left_mass = lo + 0.5 * eq
            right_mass = (n - hi) + 0.5 * eq
            
            p_low = (left_mass + 1.0) / (n + 2.0)
            p_up = (right_mass + 1.0) / (n + 2.0)
            
            p_low = np.clip(p_low, self.eps, 1.0)
            p_up = np.clip(p_up, self.eps, 1.0)
            
            if self.switches.two_sided:
                p = np.minimum(1.0, 2.0 * np.minimum(p_low, p_up))
            else:
                p = p_up
        else:
            idx = np.searchsorted(sarr, xcol, side="left")
            tail = (n - idx)
            p_up = (tail + 1.0) / (n + 2.0)
            p_up = np.clip(p_up, self.eps, 1.0)
            
            if self.switches.two_sided:
                p_low = (idx + 1.0) / (n + 2.0)
                p = np.minimum(1.0, 2.0 * np.minimum(p_low, p_up))
            else:
                p = p_up
        
        return np.clip(p, self.eps, 1.0)
    
    def predict_single(self, feature_vector: Union[pd.Series, Dict, np.ndarray]) -> Tuple[int, float]:
        """
        对单个样本进行预测（逐条预测）
        
        Args:
            feature_vector: 单个样本的特征向量，可以是:
                - pd.Series: 索引为特征名
                - dict: 键为特征名
                - np.ndarray: 按feature_cols_顺序排列
        
        Returns:
            prediction: 预测结果 (0=benign, 1=malicious)
            score: 原始异常分数
        """
        # 处理不同类型的输入
        if isinstance(feature_vector, (dict, pd.Series)):
            # 确保包含所有必需的特征
            row = {}
            for col in self.feature_cols_:
                if col in feature_vector:
                    row[col] = feature_vector[col]
                else:
                    row[col] = np.nan
            X = pd.DataFrame([row])
        elif isinstance(feature_vector, np.ndarray):
            if len(feature_vector) != len(self.feature_cols_):
                warnings.warn(
                    f"Expected {len(self.feature_cols_)} features, got {len(feature_vector)}. "
                    "Using as many as possible and filling rest with NaN.",
                    UserWarning
                )
                # 填充或截断以匹配特征数量
                if len(feature_vector) < len(self.feature_cols_):
                    feature_vector = np.pad(
                        feature_vector, 
                        (0, len(self.feature_cols_) - len(feature_vector)),
                        'constant', 
                        constant_values=np.nan
                    )
                else:
                    feature_vector = feature_vector[:len(self.feature_cols_)]
            X = pd.DataFrame([feature_vector], columns=self.feature_cols_)
        else:
            raise TypeError("feature_vector must be dict, pd.Series, or np.ndarray")
        
        # 计算分数
        scores = self.score_samples(X)
        score = float(scores[0])
        
        # 预测
        prediction = 1 if score >= self.threshold_ else 0
        
        return prediction, score

    def _gate(self, u: np.ndarray) -> np.ndarray:
        """门控函数（t0处理）"""
        if self.switches.use_gate_t0:
            x = u - self.t0
            return np.maximum(x, 0.0)
        return u

    def _raw_scores_from_array(self, X: np.ndarray) -> np.ndarray:
        """计算原始异常分数"""
        n, d = X.shape
        raw = np.zeros(n, dtype=float)
        
        for j in range(d):
            sarr = self.sorted_benign_[j]
            p = self._pvalues(sarr, X[:, j])
            u = -np.log(p)
            
            a = self._gate(u)
            
            if self.switches.use_power_transform and self.gamma != 1.0:
                a = np.power(a, self.gamma)
                
            raw += a
            
        return raw

    def score_samples(self, X: pd.DataFrame) -> np.ndarray:
        """计算标准化异常分数"""
        # 确保特征顺序一致
        X = X[self.feature_cols_].values.astype(float)
        X = np.where(np.isnan(X), self.medians_, X)
        
        raw = self._raw_scores_from_array(X)
        return (raw - self.loc_) / (self.scale_ + self.eps)

    def predict(self, X: pd.DataFrame) -> np.ndarray:
        """使用保存的阈值进行预测"""
        scores = self.score_samples(X)
        return (scores >= self.threshold_).astype(int)

    def set_threshold(self, threshold: float):
        """设置并保存阈值"""
        self.threshold_ = threshold

    def get_threshold(self) -> float:
        """获取保存的阈值"""
        return self.threshold_

    def save(self, path: str):
        """保存完整模型（包括阈值）到文件"""
        joblib.dump(self, path)

    @classmethod
    def load(cls, path: str) -> 'TailDetector':
        """从文件加载完整模型（包括阈值）"""
        return joblib.load(path)
