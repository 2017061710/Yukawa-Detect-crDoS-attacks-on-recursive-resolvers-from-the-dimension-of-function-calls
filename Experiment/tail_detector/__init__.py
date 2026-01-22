from .core import TailDetector, ModuleSwitches
from .trainer import train_tail_detector
from .predictor import (
    load_tail_detector, 
    predict_with_tail_detector,
    evaluate_tail_detector
)
from .config import DEFAULT_TRAINING_CONFIG, DEFAULT_PREDICTION_CONFIG

__version__ = "1.0.0"
__all__ = [
    'TailDetector',
    'ModuleSwitches',
    'train_tail_detector',
    'load_tail_detector',
    'predict_with_tail_detector',
    'evaluate_tail_detector',
    'DEFAULT_TRAINING_CONFIG',
    'DEFAULT_PREDICTION_CONFIG'
]
