from config import load_settings


def build_application() -> dict[str, str]:
    return load_settings("settings.toml")
