import json
import os


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


def load_config(path=None):
    config_path = path or default_config_path()
    if not os.path.exists(config_path):
        return default_config()

    with open(config_path, "r", encoding="utf-8") as handle:
        loaded = json.load(handle)

    config = default_config()
    for key, value in loaded.items():
        if key in config:
            config[key] = value

    return config


def save_config(path_or_config, config=None):
    if config is None:
        config_path = default_config_path()
        config_data = path_or_config
    else:
        config_path = path_or_config
        config_data = config

    os.makedirs(os.path.dirname(config_path), exist_ok=True)

    with open(config_path, "w", encoding="utf-8") as handle:
        json.dump(config_data, handle, indent=2)
