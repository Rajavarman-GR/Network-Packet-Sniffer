"""Explicit schema for the separate UNSW-NB15 flow dataset."""

UNSW_FLOW_SCHEMA_VERSION = "1.0"

TARGET_LABEL = "label"
TARGET_ATTACK_CATEGORY = "attack_cat"
TARGET_COLUMNS = (TARGET_LABEL, TARGET_ATTACK_CATEGORY)

EXCLUDED_PREDICTOR_COLUMNS = ("id", TARGET_LABEL, TARGET_ATTACK_CATEGORY)

NUMERIC_PREDICTOR_COLUMNS = (
    "dur",
    "spkts",
    "dpkts",
    "sbytes",
    "dbytes",
    "rate",
    "sttl",
    "dttl",
    "sload",
    "dload",
    "sloss",
    "dloss",
    "sinpkt",
    "dinpkt",
    "sjit",
    "djit",
    "swin",
    "stcpb",
    "dtcpb",
    "dwin",
    "tcprtt",
    "synack",
    "ackdat",
    "smean",
    "dmean",
    "trans_depth",
    "response_body_len",
    "ct_srv_src",
    "ct_state_ttl",
    "ct_dst_ltm",
    "ct_src_dport_ltm",
    "ct_dst_sport_ltm",
    "ct_dst_src_ltm",
    "is_ftp_login",
    "ct_ftp_cmd",
    "ct_flw_http_mthd",
    "ct_src_ltm",
    "ct_srv_dst",
    "is_sm_ips_ports",
)

CATEGORICAL_PREDICTOR_COLUMNS = ("proto", "service", "state")
PREDICTOR_COLUMNS = NUMERIC_PREDICTOR_COLUMNS + CATEGORICAL_PREDICTOR_COLUMNS

REQUIRED_COLUMNS = ("id",) + PREDICTOR_COLUMNS + (TARGET_LABEL,)
OPTIONAL_COLUMNS = (TARGET_ATTACK_CATEGORY,)
ALLOWED_COLUMNS = frozenset(REQUIRED_COLUMNS + OPTIONAL_COLUMNS)

EXPECTED_LABEL_VALUES = frozenset(("0", "1"))
EXPECTED_ATTACK_CATEGORIES = frozenset((
    "Analysis",
    "Backdoor",
    "DoS",
    "Exploits",
    "Fuzzers",
    "Generic",
    "Normal",
    "Reconnaissance",
    "Shellcode",
    "Worms",
))