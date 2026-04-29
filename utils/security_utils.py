"""
utils/security_utils.py
功能：提供密码哈希与校验能力，使用 bcrypt 存储用户密码。
注意事项：
1. 仅保存哈希值，不保存明文密码。
2. bcrypt 内置盐值，具备抗彩虹表攻击能力。
"""

import bcrypt


class PasswordSecurityError(Exception):
    """
    功能：密码安全工具统一异常类型。
    参数：
        message (str): 异常描述信息。
    返回值：
        无。
    注意事项：
        业务层可捕获该异常并输出友好提示。
    """


def hash_password(password: str, rounds: int = 12) -> str:
    """
    功能：对用户明文密码进行 bcrypt 哈希。
    参数：
        password (str): 用户输入的明文密码。
        rounds (int): bcrypt 计算轮数，默认 12。
    返回值：
        str: 可持久化存储的密码哈希字符串。
    注意事项：
        1. 入参必须为非空字符串。
        2. rounds 过低会降低安全性，过高会影响性能。
    """
    try:
        if not isinstance(password, str) or not password.strip():
            raise PasswordSecurityError("密码不能为空，且必须为字符串。")
        if rounds < 10 or rounds > 16:
            raise PasswordSecurityError("bcrypt 轮数建议在 10 到 16 之间。")

        password_bytes = password.encode("utf-8")
        salt = bcrypt.gensalt(rounds=rounds)
        hashed_bytes = bcrypt.hashpw(password_bytes, salt)
        return hashed_bytes.decode("utf-8")
    except PasswordSecurityError:
        raise
    except Exception as exc:
        raise PasswordSecurityError("密码哈希失败，请稍后重试。") from exc


def verify_password(password: str, hashed_password: str) -> bool:
    """
    功能：校验明文密码与 bcrypt 哈希是否匹配。
    参数：
        password (str): 用户输入的明文密码。
        hashed_password (str): 数据库存储的 bcrypt 哈希。
    返回值：
        bool: 匹配返回 True，不匹配返回 False。
    注意事项：
        1. 该函数会处理非法哈希格式并返回 False。
        2. 调用方可根据返回值决定是否提示登录失败。
    """
    try:
        if not isinstance(password, str) or not isinstance(hashed_password, str):
            return False
        if not password or not hashed_password:
            return False

        password_bytes = password.encode("utf-8")
        hashed_bytes = hashed_password.encode("utf-8")
        return bool(bcrypt.checkpw(password_bytes, hashed_bytes))
    except (ValueError, TypeError):
        return False
    except Exception as exc:
        raise PasswordSecurityError("密码校验失败，请稍后重试。") from exc
