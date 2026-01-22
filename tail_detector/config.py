"""默认配置参数"""
DEFAULT_TRAINING_CONFIG = {
    'n_trials': 30,
    'beta': 4.0,
    'fpr_low': 1e-4,
    'fpr_high': 2e-2,
    'fpr_penalty': 0.03,
    'seed': 42,
    'verbose': True
}

DEFAULT_PREDICTION_CONFIG = {
    'return_scores': False
}
