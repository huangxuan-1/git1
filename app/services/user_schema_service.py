"""
app/services/user_schema_service.py
功能：确保 customer 表具备用户回收站字段与用户ID字符串化结构。
注意事项：
1. 本服务采用幂等方式执行，可在应用启动时重复调用。
2. 用户ID类型迁移当前主要支持 MySQL。
"""

from __future__ import annotations

from sqlalchemy import inspect, text

from extensions import db


class UserSchemaService:
    """
    功能：维护 customer 表软删除结构与用户ID字段结构。
    参数：
        无。
    返回值：
        无。
    注意事项：
        建议在应用启动阶段调用 ensure_soft_delete_schema。
    """

    @staticmethod
    def _mysql_table_column_data_type(connection, table_name: str, column_name: str) -> str:
        row = connection.execute(
            text(
                "SELECT DATA_TYPE "
                "FROM information_schema.COLUMNS "
                "WHERE TABLE_SCHEMA = DATABASE() "
                "AND TABLE_NAME = :table_name "
                "AND COLUMN_NAME = :column_name "
                "LIMIT 1"
            ),
            {"table_name": table_name, "column_name": column_name},
        ).scalar()
        return str(row or "").lower()

    @staticmethod
    def _mysql_customer_fk_exists(connection, table_name: str, column_name: str) -> bool:
        row = connection.execute(
            text(
                "SELECT COUNT(1) "
                "FROM information_schema.KEY_COLUMN_USAGE "
                "WHERE TABLE_SCHEMA = DATABASE() "
                "AND TABLE_NAME = :table_name "
                "AND COLUMN_NAME = :column_name "
                "AND REFERENCED_TABLE_NAME = 'customer' "
                "AND REFERENCED_COLUMN_NAME = 'id'"
            ),
            {"table_name": table_name, "column_name": column_name},
        ).scalar()
        return int(row or 0) > 0

    @staticmethod
    def _mysql_drop_customer_foreign_keys(connection) -> None:
        fk_rows = connection.execute(
            text(
                "SELECT TABLE_NAME, CONSTRAINT_NAME "
                "FROM information_schema.KEY_COLUMN_USAGE "
                "WHERE TABLE_SCHEMA = DATABASE() "
                "AND REFERENCED_TABLE_NAME = 'customer' "
                "AND REFERENCED_COLUMN_NAME = 'id' "
                "AND TABLE_NAME IN ('biometric_data', 'audit_log') "
                "GROUP BY TABLE_NAME, CONSTRAINT_NAME"
            )
        ).mappings().all()

        for row in fk_rows:
            table_name = str(row.get("TABLE_NAME") or "").strip()
            constraint_name = str(row.get("CONSTRAINT_NAME") or "").strip()
            if not table_name or not constraint_name:
                continue
            connection.execute(
                text(f"ALTER TABLE `{table_name}` DROP FOREIGN KEY `{constraint_name}`")
            )

    @staticmethod
    def _mysql_column_exists(connection, column_name: str) -> bool:
        result = connection.execute(
            text(
                "SELECT COUNT(1) "
                "FROM information_schema.COLUMNS "
                "WHERE TABLE_SCHEMA = DATABASE() "
                "AND TABLE_NAME = 'customer' "
                "AND COLUMN_NAME = :column_name"
            ),
            {"column_name": column_name},
        )
        return int(result.scalar() or 0) > 0

    @staticmethod
    def _mysql_table_column_exists(connection, table_name: str, column_name: str) -> bool:
        result = connection.execute(
            text(
                "SELECT COUNT(1) "
                "FROM information_schema.COLUMNS "
                "WHERE TABLE_SCHEMA = DATABASE() "
                "AND TABLE_NAME = :table_name "
                "AND COLUMN_NAME = :column_name"
            ),
            {"table_name": table_name, "column_name": column_name},
        )
        return int(result.scalar() or 0) > 0

    @staticmethod
    def _mysql_index_exists(connection, index_name: str) -> bool:
        result = connection.execute(
            text(
                "SELECT COUNT(1) "
                "FROM information_schema.STATISTICS "
                "WHERE TABLE_SCHEMA = DATABASE() "
                "AND TABLE_NAME = 'customer' "
                "AND INDEX_NAME = :index_name"
            ),
            {"index_name": index_name},
        )
        return int(result.scalar() or 0) > 0

    @staticmethod
    def _sqlite_columns(connection, table_name: str = "customer") -> set[str]:
        rows = connection.execute(text(f"PRAGMA table_info({table_name})")).mappings().all()
        return {str(row.get("name") or "") for row in rows}

    @staticmethod
    def ensure_soft_delete_schema() -> None:
        """
        功能：为 customer 表补齐 is_deleted、deleted_at 与回收站索引。
        参数：
            无。
        返回值：
            None
        注意事项：
            若 customer 表尚不存在，则直接跳过。
        """
        inspector = inspect(db.engine)
        if "customer" not in inspector.get_table_names():
            return

        dialect_name = str(db.engine.dialect.name or "").lower()

        with db.engine.begin() as connection:
            if dialect_name == "mysql":
                if not UserSchemaService._mysql_column_exists(connection, "is_deleted"):
                    connection.execute(
                        text(
                            "ALTER TABLE customer "
                            "ADD COLUMN is_deleted TINYINT(1) NOT NULL DEFAULT 0 AFTER lock_until"
                        )
                    )

                if not UserSchemaService._mysql_column_exists(connection, "deleted_at"):
                    connection.execute(
                        text(
                            "ALTER TABLE customer "
                            "ADD COLUMN deleted_at DATETIME NULL AFTER is_deleted"
                        )
                    )

                connection.execute(text("UPDATE customer SET is_deleted = IFNULL(is_deleted, 0)"))

                if not UserSchemaService._mysql_index_exists(connection, "idx_customer_recycle"):
                    connection.execute(
                        text(
                            "CREATE INDEX idx_customer_recycle "
                            "ON customer(is_deleted, deleted_at)"
                        )
                    )
                return

            if dialect_name == "sqlite":
                columns = UserSchemaService._sqlite_columns(connection)
                if "is_deleted" not in columns:
                    connection.execute(
                        text(
                            "ALTER TABLE customer "
                            "ADD COLUMN is_deleted INTEGER NOT NULL DEFAULT 0"
                        )
                    )

                columns = UserSchemaService._sqlite_columns(connection)
                if "deleted_at" not in columns:
                    connection.execute(
                        text(
                            "ALTER TABLE customer "
                            "ADD COLUMN deleted_at DATETIME NULL"
                        )
                    )

                connection.execute(
                    text(
                        "CREATE INDEX IF NOT EXISTS idx_customer_recycle "
                        "ON customer(is_deleted, deleted_at)"
                    )
                )
                return

            current_columns = {column["name"] for column in inspect(db.engine).get_columns("customer")}
            if "is_deleted" not in current_columns:
                connection.execute(
                    text(
                        "ALTER TABLE customer "
                        "ADD COLUMN is_deleted BOOLEAN NOT NULL DEFAULT 0"
                    )
                )
            if "deleted_at" not in current_columns:
                connection.execute(
                    text(
                        "ALTER TABLE customer "
                        "ADD COLUMN deleted_at DATETIME"
                    )
                )

    @staticmethod
    def ensure_login_security_schema() -> None:
        """
        功能：为 customer 与 administrator 表补齐登录尝试次数与账户状态字段。
        参数：
            无。
        返回值：
            None
        注意事项：
            字段补齐采用幂等方式，可与现有启动迁移重复执行。
        """
        inspector = inspect(db.engine)
        table_names = set(inspector.get_table_names())
        target_tables = ("customer", "administrator")

        if not any(table_name in table_names for table_name in target_tables):
            return

        dialect_name = str(db.engine.dialect.name or "").lower()

        with db.engine.begin() as connection:
            for table_name in target_tables:
                if table_name not in table_names:
                    continue

                if dialect_name == "mysql":
                    if not UserSchemaService._mysql_table_column_exists(connection, table_name, "login_attempts"):
                        connection.execute(
                            text(
                                f"ALTER TABLE `{table_name}` "
                                "ADD COLUMN login_attempts INT NOT NULL DEFAULT 0 AFTER lock_until"
                            )
                        )

                    if not UserSchemaService._mysql_table_column_exists(connection, table_name, "account_status"):
                        connection.execute(
                            text(
                                f"ALTER TABLE `{table_name}` "
                                "ADD COLUMN account_status TINYINT(1) NOT NULL DEFAULT 0 AFTER login_attempts"
                            )
                        )
                    continue

                if dialect_name == "sqlite":
                    columns = UserSchemaService._sqlite_columns(connection, table_name)
                    if "login_attempts" not in columns:
                        connection.execute(
                            text(
                                f"ALTER TABLE {table_name} "
                                "ADD COLUMN login_attempts INTEGER NOT NULL DEFAULT 0"
                            )
                        )

                    columns = UserSchemaService._sqlite_columns(connection, table_name)
                    if "account_status" not in columns:
                        connection.execute(
                            text(
                                f"ALTER TABLE {table_name} "
                                "ADD COLUMN account_status INTEGER NOT NULL DEFAULT 0"
                            )
                        )
                    continue

                current_columns = {column["name"] for column in inspect(db.engine).get_columns(table_name)}
                if "login_attempts" not in current_columns:
                    connection.execute(
                        text(
                            f"ALTER TABLE {table_name} "
                            "ADD COLUMN login_attempts INTEGER NOT NULL DEFAULT 0"
                        )
                    )
                if "account_status" not in current_columns:
                    connection.execute(
                        text(
                            f"ALTER TABLE {table_name} "
                            "ADD COLUMN account_status INTEGER NOT NULL DEFAULT 0"
                        )
                    )

    @staticmethod
    def ensure_face_feature_schema() -> None:
        """
        功能：为 customer 表补齐人脸特征加密字段。
        参数：
            无。
        返回值：
            None
        注意事项：
            字段补齐采用幂等方式，可与现有启动迁移重复执行。
        """
        inspector = inspect(db.engine)
        if "customer" not in inspector.get_table_names():
            return

        dialect_name = str(db.engine.dialect.name or "").lower()

        with db.engine.begin() as connection:
            if dialect_name == "mysql":
                if not UserSchemaService._mysql_column_exists(connection, "face_feature_encrypted"):
                    connection.execute(
                        text(
                            "ALTER TABLE customer "
                            "ADD COLUMN face_feature_encrypted TEXT NULL AFTER password"
                        )
                    )
                return

            if dialect_name == "sqlite":
                columns = UserSchemaService._sqlite_columns(connection)
                if "face_feature_encrypted" not in columns:
                    connection.execute(
                        text(
                            "ALTER TABLE customer "
                            "ADD COLUMN face_feature_encrypted TEXT NULL"
                        )
                    )
                return

            current_columns = {column["name"] for column in inspect(db.engine).get_columns("customer")}
            if "face_feature_encrypted" not in current_columns:
                connection.execute(
                    text(
                        "ALTER TABLE customer "
                        "ADD COLUMN face_feature_encrypted TEXT"
                    )
                )

    @staticmethod
    def ensure_user_id_schema() -> None:
        """
        功能：将用户ID相关字段统一为字符串类型，支持5位随机数字ID。
        参数：
            无。
        返回值：
            None
        注意事项：
            1. 当前自动迁移仅对 MySQL 生效。
            2. 该方法会以幂等方式处理 customer、biometric_data、audit_log、secret_file。
        """
        inspector = inspect(db.engine)
        table_names = set(inspector.get_table_names())
        if "customer" not in table_names:
            return

        dialect_name = str(db.engine.dialect.name or "").lower()
        if dialect_name != "mysql":
            return

        with db.engine.begin() as connection:
            customer_id_type = UserSchemaService._mysql_table_column_data_type(
                connection,
                "customer",
                "id",
            )
            biometric_customer_type = UserSchemaService._mysql_table_column_data_type(
                connection,
                "biometric_data",
                "customer_id",
            ) if "biometric_data" in table_names else ""
            audit_customer_type = UserSchemaService._mysql_table_column_data_type(
                connection,
                "audit_log",
                "customer_id",
            ) if "audit_log" in table_names else ""
            uploader_id_type = UserSchemaService._mysql_table_column_data_type(
                connection,
                "secret_file",
                "uploader_id",
            ) if "secret_file" in table_names else ""
            deleted_by_id_type = UserSchemaService._mysql_table_column_data_type(
                connection,
                "secret_file",
                "deleted_by_id",
            ) if "secret_file" in table_names else ""

            need_customer_related_migration = (
                customer_id_type != "varchar"
                or ("biometric_data" in table_names and biometric_customer_type and biometric_customer_type != "varchar")
                or ("audit_log" in table_names and audit_customer_type and audit_customer_type != "varchar")
            )

            if need_customer_related_migration:
                UserSchemaService._mysql_drop_customer_foreign_keys(connection)

                connection.execute(
                    text(
                        "ALTER TABLE customer "
                        "MODIFY COLUMN id VARCHAR(10) NOT NULL"
                    )
                )

                if "biometric_data" in table_names and biometric_customer_type:
                    connection.execute(
                        text(
                            "ALTER TABLE biometric_data "
                            "MODIFY COLUMN customer_id VARCHAR(10) NULL"
                        )
                    )

                if "audit_log" in table_names and audit_customer_type:
                    connection.execute(
                        text(
                            "ALTER TABLE audit_log "
                            "MODIFY COLUMN customer_id VARCHAR(10) NULL"
                        )
                    )

            if "secret_file" in table_names and uploader_id_type and uploader_id_type != "varchar":
                connection.execute(
                    text(
                        "ALTER TABLE secret_file "
                        "MODIFY COLUMN uploader_id VARCHAR(32) NOT NULL"
                    )
                )

            if "secret_file" in table_names and deleted_by_id_type and deleted_by_id_type != "varchar":
                connection.execute(
                    text(
                        "ALTER TABLE secret_file "
                        "MODIFY COLUMN deleted_by_id VARCHAR(32) NULL"
                    )
                )

            if "biometric_data" in table_names and not UserSchemaService._mysql_customer_fk_exists(
                connection,
                "biometric_data",
                "customer_id",
            ):
                connection.execute(
                    text(
                        "ALTER TABLE biometric_data "
                        "ADD CONSTRAINT fk_biometric_data_customer_id "
                        "FOREIGN KEY (customer_id) REFERENCES customer(id) "
                        "ON DELETE CASCADE"
                    )
                )

            if "audit_log" in table_names and not UserSchemaService._mysql_customer_fk_exists(
                connection,
                "audit_log",
                "customer_id",
            ):
                connection.execute(
                    text(
                        "ALTER TABLE audit_log "
                        "ADD CONSTRAINT fk_audit_log_customer_id "
                        "FOREIGN KEY (customer_id) REFERENCES customer(id) "
                        "ON DELETE SET NULL"
                    )
                )
