# Window

WINDOW_WIDTH = 1400
WINDOW_HEIGHT = 850

# Legacy names remain aliases so callers keep their existing API while the
# semantic palette has one source of truth in utils.theme.
from utils.theme import get_tokens

_DARK = get_tokens("dark")
DARK_BG = _DARK["background"]
HEADER_BG = _DARK["navigation"]
PANEL_BG = _DARK["surface"]
TABLE_BG = _DARK["table"]
TEXT_COLOR = _DARK["text"]
PRIMARY = _DARK["accent"]
SUCCESS = _DARK["success"]
ERROR = _DARK["danger"]
WARNING = _DARK["warning"]
INFO = _DARK["info"]
