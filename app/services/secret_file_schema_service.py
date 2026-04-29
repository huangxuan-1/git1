"""
app/services/secret_file_schema_service.py
功能：确保 secret_file 表具备文件层级管理所需字段与索引。
注意事项：
1. 本服务采用幂等方式执行，可在应用启动时重复调用。
2. 支持 MySQL 与 SQLite，其他方言使用通用回退策略。
"""

from __future__ import annotations

from sqlalchemy import inspect, text

from extensions import db


class SecretFileSchemaService:
    """
    功能：维护 secret_file 表的层级管理结构（parent_id / is_folder）与回收站扩展字段（original_path）。
    参数：
        无。
    返回值：
        无。
    注意事项：
        建议在应用启动阶段调用 ensure_hierarchy_schema。
    """

    @staticmethod
    def _mysql_column_exists(connection, column_name: str) -> bool:
        result = connection.execute(
            text(
                "SELECT COUNT(1) "
                "FROM information_schema.COLUMNS "
                "WHERE TABLE_SCHEMA = DATABASE() "
                "AND TABLE_NAME = 'secret_file' "
                "AND COLUMN_NAME = :column_name"
            ),
            {"column_name": column_name},
        )
        return int(result.scalar() or 0) > 0

    @staticmethod
    def _mysql_index_exists(connection, index_name: str) -> bool:
        result = connection.execute(
            text(
                "SELECT COUNT(1) "
                "FROM information_schema.STATISTICS "
                "WHERE TABLE_SCHEMA = DATABASE() "
                "AND TABLE_NAME = 'secret_file' "
                "AND INDEX_NAME = :index_name"
            ),
            {"index_name": index_name},
        )
        return int(result.scalar() or 0) > 0

    @staticmethod
    def _sqlite_columns(connection) -> set[str]:
        rows = connection.execute(text("PRAGMA table_info(secret_file)")).mappings().all()
        return {str(row.get("name") or "") for row in rows}

    @staticmethod
    def _ensure_mysql_upload_time_schema(connection) -> None:
        has_uploaded_at = SecretFileSchemaService._mysql_column_exists(connection, "uploaded_at")
        has_created_at = SecretFileSchemaService._mysql_column_exists(connection, "created_at")

        if not has_uploaded_at and has_created_at:
            connection.execute(
                text(
                    "ALTER TABLE secret_file "
                    "CHANGE COLUMN created_at uploaded_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP"
                )
            )
            has_uploaded_at = True

        if not has_uploaded_at:
            connection.execute(
                text(
                    "ALTER TABLE secret_file "
                    "ADD COLUMN uploaded_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP"
                )
            )

        if SecretFileSchemaService._mysql_column_exists(connection, "updated_at"):
            connection.execute(text("ALTER TABLE secret_file DROP COLUMN updated_at"))

        if SecretFileSchemaService._mysql_index_exists(connection, "idx_secret_file_search"):
            connection.execute(text("DROP INDEX idx_secret_file_search ON secret_file"))

        connection.execute(
            text(
                "CREATE INDEX idx_secret_file_search "
                "ON secret_file(name, level, uploaded_at)"
            )
        )

    @staticmethod
    def ensure_hierarchy_schema() -> None:
        """
        功能：为 secret_file 表补齐 parent_id、is_folder、original_path 与目录索引。
        参数：
            无。
        返回值：
            None
        注意事项：
            若 secret_file 表尚不存在，则直接跳过。
        """
        inspector = inspect(db.engine)
        if "secret_file" not in inspector.get_table_names():
            return

        dialect_name = str(db.engine.dialect.name or "").lower()

        with db.engine.begin() as connection:
            if dialect_name == "mysql":
                SecretFileSchemaService._ensure_mysql_upload_time_schema(connection)

                if not SecretFileSchemaService._mysql_column_exists(connection, "parent_id"):
                    connection.execute(
                        text(
                            "ALTER TABLE secret_file "
                            "ADD COLUMN parent_id INT NOT NULL DEFAULT 0 AFTER name"
                        )
                    )

                if not SecretFileSchemaService._mysql_column_exists(connection, "is_folder"):
                    connection.execute(
                        text(
                            "ALTER TABLE secret_file "
                            "ADD COLUMN is_folder TINYINT(1) NOT NULL DEFAULT 0 AFTER status"
                        )
                    )

                if not SecretFileSchemaService._mysql_column_exists(connection, "original_path"):
                    connection.execute(
                        text(
                            "ALTER TABLE secret_file "
                            "ADD COLUMN original_path VARCHAR(255) NULL AFTER deleted_by_type"
                        )
                    )

                if not SecretFileSchemaService._mysql_index_exists(
                    connection,
                    "idx_secret_file_parent_latest",
                ):
                    connection.execute(
                        text(
                            "CREATE INDEX idx_secret_file_parent_latest "
                            "ON secret_file(parent_id, is_latest, is_deleted)"
                        )
                    )
                return

            if dialect_name == "sqlite":
                columns = SecretFileSchemaService._sqlite_columns(connection)
                if "uploaded_at" not in columns:
                    if "created_at" in columns:
                        try:
                            connection.execute(
                                text(
                                    "ALTER TABLE secret_file "
                                    "RENAME COLUMN created_at TO uploaded_at"
                                )
                            )
                        except Exception:
                            connection.execute(
                                text(
                                    "ALTER TABLE secret_file "
                                    "ADD COLUMN uploaded_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP"
                                )
                            )
                            connection.execute(
                                text(
                                    "UPDATE secret_file "
                                    "SET uploaded_at = COALESCE(created_at, CURRENT_TIMESTAMP)"
                                )
                            )
                    else:
                        connection.execute(
                            text(
                                "ALTER TABLE secret_file "
                                "ADD COLUMN uploaded_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP"
                            )
                        )

                columns = SecretFileSchemaService._sqlite_columns(connection)
                if "updated_at" in columns:
                    try:
                        connection.execute(text("ALTER TABLE secret_file DROP COLUMN updated_at"))
                    except Exception:
                        pass

                connection.execute(text("DROP INDEX IF EXISTS idx_secret_file_search"))
                connection.execute(
                    text(
                        "CREATE INDEX IF NOT EXISTS idx_secret_file_search "
                        "ON secret_file(name, level, uploaded_at)"
                    )
                )

                if "parent_id" not in columns:
                    connection.execute(
                        text(
                            "ALTER TABLE secret_file "
                            "ADD COLUMN parent_id INTEGER NOT NULL DEFAULT 0"
                        )
                    )

                columns = SecretFileSchemaService._sqlite_columns(connection)
                if "is_folder" not in columns:
                    connection.execute(
                        text(
                            "ALTER TABLE secret_file "
                            "ADD COLUMN is_folder INTEGER NOT NULL DEFAULT 0"
                        )
                    )

                columns = SecretFileSchemaService._sqlite_columns(connection)
                if "original_path" not in columns:
                    connection.execute(
                        text(
                            "ALTER TABLE secret_file "
                            "ADD COLUMN original_path TEXT NULL"
                        )
                    )

                connection.execute(
                    text(
                        "CREATE INDEX IF NOT EXISTS idx_secret_file_parent_latest "
                        "ON secret_file(parent_id, is_latest, is_deleted)"
                    )
                )
                return

            # 通用回退：通过 SQLAlchemy Inspector 判断字段并尝试标准语句。
            current_columns = {column["name"] for column in inspect(db.engine).get_columns("secret_file")}
            if "uploaded_at" not in current_columns:
                if "created_at" in current_columns:
                    try:
                        connection.execute(
                            text(
                                "ALTER TABLE secret_file "
                                "RENAME COLUMN created_at TO uploaded_at"
                            )
                        )
                    except Exception:
                        connection.execute(
                            text(
                                "ALTER TABLE secret_file "
                                "ADD COLUMN uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP"
                            )
                        )
                else:
                    connection.execute(
                        text(
                            "ALTER TABLE secret_file "
                            "ADD COLUMN uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP"
                        )
                    )

            current_columns = {column["name"] for column in inspect(db.engine).get_columns("secret_file")}
            if "updated_at" in current_columns:
                try:
                    connection.execute(text("ALTER TABLE secret_file DROP COLUMN updated_at"))
                except Exception:
                    pass

            if "parent_id" not in current_columns:
                connection.execute(
                    text(
                        "ALTER TABLE secret_file "
                        "ADD COLUMN parent_id INTEGER NOT NULL DEFAULT 0"
                    )
                )
            if "is_folder" not in current_columns:
                connection.execute(
                    text(
                        "ALTER TABLE secret_file "
                        "ADD COLUMN is_folder BOOLEAN NOT NULL DEFAULT 0"
                    )
                )
            if "original_path" not in current_columns:
                connection.execute(
                    text(
                        "ALTER TABLE secret_file "
                        "ADD COLUMN original_path VARCHAR(255)"
                    )
                )
