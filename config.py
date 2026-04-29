"""
config.py
功能：集中管理 Flask 项目的全局配置项，包括数据库连接、会话安全和加密密钥。
注意事项：
1. 所有密钥优先从环境变量读取。
2. 当环境变量缺失时，会自动生成随机密钥，避免硬编码固定值。
"""

import base64
import os
import secrets
from datetime import timedelta
from urllib.parse import quote_plus

from dotenv import load_dotenv

load_dotenv()


def _str_to_bool(value: str | None, default: bool = False) -> bool:
    """
    功能：将字符串安全转换为布尔值。
    参数：
        value (str | None): 待转换的字符串。
        default (bool): 转换失败时返回的默认值。
    返回值：
        bool: 转换后的布尔结果。
    注意事项：
        支持 true/false、1/0、yes/no、on/off 等常见表达。
    """
    if value is None:
        return default

    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    return default


def _safe_int(value: str | None, default: int) -> int:
    """
    功能：将字符串安全转换为整数。
    参数：
        value (str | None): 待转换的字符串。
        default (int): 转换失败时返回的默认值。
    返回值：
        int: 转换后的整数。
    注意事项：
        若输入为空或格式错误，返回默认值，避免程序启动失败。
    """
    try:
        return int(value) if value is not None else default
    except (TypeError, ValueError):
        return default


def _safe_float(value: str | None, default: float) -> float:
    """
    功能：将字符串安全转换为浮点数。
    参数：
        value (str | None): 待转换的字符串。
        default (float): 转换失败时返回的默认值。
    返回值：
        float: 转换后的浮点数。
    注意事项：
        若输入为空或格式错误，返回默认值。
    """
    try:
        return float(value) if value is not None else default
    except (TypeError, ValueError):
        return default


def _load_aes_key(env_name: str = "AES_KEY_B64") -> bytes:
    """
    功能：读取并校验 AES-256 密钥。
    参数：
        env_name (str): 环境变量名。
    返回值：
        bytes: 32 字节 AES 密钥。
    注意事项：
        1. 优先从指定环境变量中读取 Base64 字符串。
        2. 若变量为空，则自动生成随机 32 字节密钥。
        3. 若变量存在但格式非法或长度错误，会抛出 ValueError。
    """
    raw_value = os.getenv(env_name, "").strip()
    if not raw_value:
        return os.urandom(32)

    try:
        decoded_key = base64.b64decode(raw_value, validate=True)
    except (ValueError, TypeError) as exc:
        raise ValueError("环境变量 AES_KEY_B64 不是合法的 Base64 字符串。") from exc

    if len(decoded_key) != 32:
        raise ValueError("环境变量 AES_KEY_B64 解码后长度必须为 32 字节。")

    return decoded_key


class Config:
    """
    功能：Flask 配置类。
    参数：
        无（通过类属性暴露配置项）。
    返回值：
        无。
    注意事项：
        本类仅定义配置，不执行数据库建表等业务逻辑。
    """

    # Flask 基础配置
    SECRET_KEY = os.getenv("SECRET_KEY") or secrets.token_urlsafe(64)
    FLASK_ENV = os.getenv("FLASK_ENV", "development")
    DEBUG = _str_to_bool(os.getenv("FLASK_DEBUG"), default=True)

    # MySQL 连接配置
    _db_host = os.getenv("DATABASE_HOST", "localhost")
    _db_port = _safe_int(os.getenv("DATABASE_PORT"), 3306)
    _db_user = os.getenv("DATABASE_USER", "root")
    _db_password = quote_plus(os.getenv("DATABASE_PASSWORD", ""))
    _db_name = os.getenv("DATABASE_NAME", "classified_system")

    SQLALCHEMY_DATABASE_URI = (
        f"mysql+pymysql://{_db_user}:{_db_password}@{_db_host}:{_db_port}/{_db_name}"
        "?charset=utf8mb4"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_pre_ping": True,
        "pool_recycle": 3600,
    }

    # 会话与 Cookie 安全配置
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SECURE = _str_to_bool(
        os.getenv("SESSION_COOKIE_SECURE"),
        default=False,
    )
    SESSION_COOKIE_SAMESITE = os.getenv("SESSION_COOKIE_SAMESITE", "Lax")
    PERMANENT_SESSION_LIFETIME = timedelta(
        minutes=_safe_int(os.getenv("SESSION_LIFETIME_MINUTES"), 30)
    )

    # 加密配置（AES-256）
    AES_KEY = _load_aes_key()
    FACE_FEATURE_AES_KEY = _load_aes_key("FACE_FEATURE_AES_KEY_B64")

    # 人脸识别模型配置
    DLIB_LANDMARK_MODEL_PATH = os.getenv(
        "DLIB_LANDMARK_MODEL_PATH",
        "resource_models/shape_predictor_68_face_landmarks.dat",
    )
    FACE_MATCH_THRESHOLD = _safe_float(
        os.getenv("FACE_MATCH_THRESHOLD"),
        0.6,
    )

    # 文件加解密配置（模块9）
    _project_root = os.path.dirname(os.path.abspath(__file__))
    FILE_KEY_DIR = os.getenv("FILE_KEY_DIR", os.path.join(_project_root, "keys"))
    FILE_CRYPTO_CHUNK_SIZE = max(
        4096,
        _safe_int(os.getenv("FILE_CRYPTO_CHUNK_SIZE"), 1024 * 1024),
    )
    MAX_UPLOAD_FILE_SIZE = max(
        1024 * 1024,
        _safe_int(os.getenv("MAX_UPLOAD_FILE_SIZE"), 100 * 1024 * 1024),
    )
    # multipart/form-data 含边界开销，设置略高于单文件限制用于兜底拦截。
    MAX_CONTENT_LENGTH = max(
        MAX_UPLOAD_FILE_SIZE,
        _safe_int(os.getenv("MAX_CONTENT_LENGTH", "120000000"), 120 * 1024 * 1024),
    )

    # 人脸录入图片请求限制（单独设置，允许较大图片上传）
    FACE_IMAGE_MAX_CONTENT_LENGTH = _safe_int(
        os.getenv("FACE_IMAGE_MAX_CONTENT_LENGTH", "10000000"),  # 10MB
        10 * 1024 * 1024,
    )

    # 模板与 JSON 配置
    TEMPLATES_AUTO_RELOAD = DEBUG
    JSON_AS_ASCII = False
