"""
init_db.py
功能：初始化数据库与数据表。
执行效果：
1. 若数据库不存在，自动创建数据库。
2. 自动创建系统定义的所有 ORM 数据表。
注意事项：
1. 运行前请确认 MySQL 服务已启动。
2. 本脚本可重复执行，重复执行不会重复建库建表。
"""

import os
from urllib.parse import quote_plus

from dotenv import load_dotenv
from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError

from app import create_app
from extensions import db

load_dotenv()


def _safe_int(value: str | None, default: int) -> int:
    """
    功能：将字符串安全转换为整数。
    参数：
        value (str | None): 待转换值。
        default (int): 转换失败时的默认值。
    返回值：
        int: 转换结果。
    注意事项：
        可避免环境变量格式错误导致脚本崩溃。
    """
    try:
        return int(value) if value is not None else default
    except (TypeError, ValueError):
        return default


def _build_server_uri() -> str:
    """
    功能：构建不指定数据库名的 MySQL 连接字符串。
    参数：
        无。
    返回值：
        str: MySQL 服务器级连接 URI。
    注意事项：
        该 URI 用于执行 CREATE DATABASE 语句。
    """
    db_host = os.getenv("DATABASE_HOST", "localhost")
    db_port = _safe_int(os.getenv("DATABASE_PORT"), 3306)
    db_user = os.getenv("DATABASE_USER", "root")
    db_password = quote_plus(os.getenv("DATABASE_PASSWORD", ""))
    return f"mysql+pymysql://{db_user}:{db_password}@{db_host}:{db_port}/?charset=utf8mb4"


def create_database_if_not_exists() -> None:
    """
    功能：在 MySQL 中创建目标数据库（若不存在）。
    参数：
        无。
    返回值：
        None
    注意事项：
        数据库字符集固定为 utf8mb4，排序规则为 utf8mb4_unicode_ci。
    """
    db_name = os.getenv("DATABASE_NAME", "classified_system")
    server_uri = _build_server_uri()

    try:
        engine = create_engine(server_uri, pool_pre_ping=True)
        with engine.begin() as connection:
            connection.execute(
                text(
                    "CREATE DATABASE IF NOT EXISTS "
                    f"`{db_name}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
                )
            )
    except SQLAlchemyError as exc:
        raise RuntimeError("数据库创建失败，请检查 MySQL 连接配置。") from exc


def create_all_tables() -> None:
    """
    功能：基于 ORM 模型创建全部数据表。
    参数：
        无。
    返回值：
        None
    注意事项：
        必须先导入模型，再调用 create_all，避免漏表。
    """
    app = create_app()

    try:
        with app.app_context():
            # 导入模型用于触发表结构注册。
            from app.models import (  # noqa: F401
                Administrator,
                AuditLog,
                BiometricData,
                SecretFile,
                User,
            )
            from app.services.audit_log_service import AuditLogService

            db.create_all()
            AuditLogService.ensure_immutable_triggers()
    except SQLAlchemyError as exc:
        raise RuntimeError("数据表创建失败，请检查模型定义与数据库权限。") from exc


def main() -> None:
    """
    功能：数据库初始化脚本入口。
    参数：
        无。
    返回值：
        None
    注意事项：
        发生异常时会抛出错误，便于在终端中定位问题。
    """
    try:
        create_database_if_not_exists()
        create_all_tables()
        print("数据库与数据表初始化完成。")
    except Exception as exc:
        print(f"数据库初始化失败：{exc}")
        raise


if __name__ == "__main__":
    main()
