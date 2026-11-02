"""
config_loader.py - Configuration Loading and Validation
"""

import yaml
from pathlib import Path
from typing import Dict, Any, Optional

def load_config(config_path: str) -> Dict[str, Any]:
    """
    Load and validate configuration from a YAML file.
    """
    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")
    
    with open(path, "r", encoding="utf-8") as f:
        try:
            config = yaml.safe_load(f)
        except yaml.YAMLError as e:
            raise ValueError(f"Error parsing YAML config: {e}")
            
    if not isinstance(config, dict):
        raise ValueError("Config file must be a YAML dictionary")
        
    allowed = {
        "target", "endpoint", "token", "type", "secret", "method", "headers",
        "output", "html_report", "rate_limit", "timeout", "safe_mode", "verbose",
        "ml_rank", "grpc", "proxy", "insecure", "auth_header", "async_scan",
        "concurrency", "wordlist", "cookie_name", "api_key_header",
    }
    if not all(isinstance(key, str) for key in config):
        raise ValueError("Configuration keys must be strings")
    unknown = sorted(set(config) - allowed)
    if unknown:
        raise ValueError(f"Unknown config option(s): {', '.join(unknown)}")
    return config

def merge_config_with_args(config: Dict[str, Any], args: Dict[str, Any]) -> Dict[str, Any]:
    """
    Merge configuration from file with CLI arguments (arguments override config).
    """
    merged = config.copy()
    for key, value in args.items():
        # Only override if the CLI argument is not None or is explicitly set
        if value is not None:
            merged[key] = value
    return merged
