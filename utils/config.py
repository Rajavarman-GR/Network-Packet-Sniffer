import json
import os
import time


def default_config():
    return {
        "theme": "dark",
        "max_packets": 10000,
        "default_interface": "",
        "default_protocol": "ALL",
        "auto_scroll": True,
        "timestamp_format": "%H:%M:%S",
    }


def default_config_path():
    return os.path.abspath(os.path.join(os.path.dirname(os.path.dirname(__file__)), "config.json"))


def normalize_config(config):
    defaults = default_config()
    if not isinstance(config, dict):
        return defaults

    normalized = defaults.copy()
    normalized.update({key: value for key, value in config.items() if key in defaults})
    try:
        normalized["max_packets"] = max(1, int(normalized["max_packets"]))
    except (TypeError, ValueError):
        normalized["max_packets"] = defaults["max_packets"]
    if normalized["theme"] not in {"dark", "light"}:
        normalized["theme"] = defaults["theme"]
    if normalized["default_protocol"] not in {"ALL", "TCP", "UDP", "ICMP", "ARP", "DNS", "ICMPv6"}:
        normalized["default_protocol"] = defaults["default_protocol"]
    normalized["auto_scroll"] = bool(normalized["auto_scroll"])
    try:
        time.strftime(normalized["timestamp_format"])
    except (TypeError, ValueError):
        normalized["timestamp_format"] = defaults["timestamp_format"]
    return normalized


def load_config(path=None):
    config_path = path or default_config_path()
    if not os.path.exists(config_path):
        return default_config()

    try:
        with open(config_path, "r", encoding="utf-8") as handle:
            loaded = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return default_config()
    return normalize_config(loaded)


def save_config(path_or_config, config=None):
    if config is None:
        config_path = default_config_path()
        config_data = path_or_config
    else:
        config_path = path_or_config
        config_data = config

    config_path = os.path.abspath(config_path)
    os.makedirs(os.path.dirname(config_path), exist_ok=True)

    with open(config_path, "w", encoding="utf-8") as handle:
        json.dump(normalize_config(config_data), handle, indent=2)
