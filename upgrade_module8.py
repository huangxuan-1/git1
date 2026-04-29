"""
upgrade_module8.py
功能：将已有 secret_file 表升级到模块8所需结构（版本控制 + 回收站）。
执行效果：
1. 增加文件分组、主次版本、最新版本标记、回收站相关字段。
2. 为历史数据补齐 file_group_id 并按 version 回填 major/minor。
3. 重新计算每个文件分组的最新版本标记。
注意事项：
1. 仅用于已存在数据库的增量升级。
2. 可重复执行，脚本会自动跳过已存在列和索引。
"""

from __future__ import annotations

from sqlalchemy import inspect, text
from sqlalchemy.exc import SQLAlchemyError

from app import create_app
from extensions import db


def _column_exists(inspector, table_name: str, column_name: str) -> bool:
    """
    功能：判断指定列是否存在。
    参数：
        inspector: SQLAlchemy Inspector 对象。
        table_name (str): 表名。
        column_name (str): 列名。
    返回值：
        bool: 存在返回 True。
    注意事项：
        仅用于结构升级过程中的幂等判断。
    """
    columns = inspector.get_columns(table_name)
    return any(column.get("name") == column_name for column in columns)


def _index_exists(connection, table_name: str, index_name: str) -> bool:
    """
    功能：判断指定索引是否存在。
    参数：
        connection: 数据库连接。
        table_name (str): 表名。
        index_name (str): 索引名。
    返回值：
        bool: 存在返回 True。
    注意事项：
        通过 SHOW INDEX 进行查询，兼容 MySQL。
    """
    result = connection.execute(
        text(
            "SELECT COUNT(1) FROM INFORMATION_SCHEMA.STATISTICS "
            "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = :table_name "
            "AND INDEX_NAME = :index_name"
        ),
        {"table_name": table_name, "index_name": index_name},
    )
    return int(result.scalar() or 0) > 0


def _add_column_if_missing(connection, inspector, ddl: str, column_name: str) -> None:
    """
    功能：在列不存在时执行 ADD COLUMN。
    参数：
        connection: 数据库连接。
        inspector: SQLAlchemy Inspector 对象。
        ddl (str): ALTER TABLE 语句。
        column_name (str): 待检查列名。
    返回值：
        None
    注意事项：
        执行后会自动刷新 inspector。
    """
    if _column_exists(inspector, "secret_file", column_name):
        print(f"列已存在，跳过：{column_name}")
        return

    connection.execute(text(ddl))
    print(f"已新增列：{column_name}")


def _upgrade_secret_file_table() -> None:
    """
    功能：升级 secret_file 表结构并回填历史数据。
    参数：
        无。
    返回值：
        None
    注意事项：
        若表不存在则直接跳过。
    """
    inspector = inspect(db.engine)
    if "secret_file" not in inspector.get_table_names():
        print("未检测到 secret_file 表，跳过升级。")
        return

    with db.engine.begin() as connection:
        _add_column_if_missing(
            connection,
            inspector,
            "ALTER TABLE secret_file ADD COLUMN file_group_id VARCHAR(64) NULL AFTER id",
            "file_group_id",
        )
        inspector = inspect(db.engine)

        _add_column_if_missing(
            connection,
            inspector,
            "ALTER TABLE secret_file ADD COLUMN mime_type VARCHAR(120) NOT NULL DEFAULT 'application/octet-stream' AFTER content",
            "mime_type",
        )
        inspector = inspect(db.engine)

        _add_column_if_missing(
            connection,
            inspector,
            "ALTER TABLE secret_file ADD COLUMN major_version INT NOT NULL DEFAULT 1 AFTER status",
            "major_version",
        )
        inspector = inspect(db.engine)

        _add_column_if_missing(
            connection,
            inspector,
            "ALTER TABLE secret_file ADD COLUMN minor_version INT NOT NULL DEFAULT 1 AFTER major_version",
            "minor_version",
        )
        inspector = inspect(db.engine)

        _add_column_if_missing(
            connection,
            inspector,
            "ALTER TABLE secret_file ADD COLUMN is_latest TINYINT(1) NOT NULL DEFAULT 1 AFTER version",
            "is_latest",
        )
        inspector = inspect(db.engine)

        _add_column_if_missing(
            connection,
            inspector,
            "ALTER TABLE secret_file ADD COLUMN is_deleted TINYINT(1) NOT NULL DEFAULT 0 AFTER is_latest",
            "is_deleted",
        )
        inspector = inspect(db.engine)

        _add_column_if_missing(
            connection,
            inspector,
            "ALTER TABLE secret_file ADD COLUMN deleted_at DATETIME NULL AFTER is_deleted",
            "deleted_at",
        )
        inspector = inspect(db.engine)

        _add_column_if_missing(
            connection,
            inspector,
            "ALTER TABLE secret_file ADD COLUMN deleted_by_id INT NULL AFTER deleted_at",
            "deleted_by_id",
        )
        inspector = inspect(db.engine)

        _add_column_if_missing(
            connection,
            inspector,
            "ALTER TABLE secret_file ADD COLUMN deleted_by_type ENUM('用户','管理员') NULL AFTER deleted_by_id",
            "deleted_by_type",
        )

        connection.execute(
            text(
                "UPDATE secret_file SET file_group_id = CONCAT('legacy-', id) "
                "WHERE file_group_id IS NULL OR file_group_id = ''"
            )
        )

        connection.execute(
            text(
                "UPDATE secret_file SET major_version = "
                "CASE "
                "WHEN version REGEXP '^[0-9]+\\.[0-9]+$' THEN CAST(SUBSTRING_INDEX(version, '.', 1) AS UNSIGNED) "
                "ELSE 1 END"
            )
        )

        connection.execute(
            text(
                "UPDATE secret_file SET minor_version = "
                "CASE "
                "WHEN version REGEXP '^[0-9]+\\.[0-9]+$' THEN CAST(SUBSTRING_INDEX(version, '.', -1) AS UNSIGNED) "
                "ELSE 1 END"
            )
        )

        connection.execute(
            text(
                "UPDATE secret_file SET version = CONCAT(major_version, '.', minor_version)"
            )
        )

        connection.execute(text("UPDATE secret_file SET is_deleted = IFNULL(is_deleted, 0)"))

        connection.execute(
            text(
                "UPDATE secret_file sf "
                "JOIN ("
                "  SELECT id, ROW_NUMBER() OVER ("
                "    PARTITION BY file_group_id "
                "    ORDER BY major_version DESC, minor_version DESC, id DESC"
                "  ) AS rn "
                "  FROM secret_file"
                ") ranked ON ranked.id = sf.id "
                "SET sf.is_latest = CASE WHEN ranked.rn = 1 THEN 1 ELSE 0 END"
            )
        )

        connection.execute(
            text("ALTER TABLE secret_file MODIFY COLUMN file_group_id VARCHAR(64) NOT NULL")
        )

        if not _index_exists(connection, "secret_file", "idx_secret_file_group_latest"):
            connection.execute(
                text(
                    "CREATE INDEX idx_secret_file_group_latest "
                    "ON secret_file(file_group_id, is_latest)"
                )
            )
            print("已新增索引：idx_secret_file_group_latest")

        if not _index_exists(connection, "secret_file", "idx_secret_file_search"):
            connection.execute(
                text(
                    "CREATE INDEX idx_secret_file_search "
                    "ON secret_file(name, level, uploaded_at)"
                )
            )
            print("已新增索引：idx_secret_file_search")

        if not _index_exists(connection, "secret_file", "idx_secret_file_recycle"):
            connection.execute(
                text(
                    "CREATE INDEX idx_secret_file_recycle "
                    "ON secret_file(is_deleted, deleted_at)"
                )
            )
            print("已新增索引：idx_secret_file_recycle")

    print("secret_file 表升级完成。")


def main() -> None:
    """
    功能：模块8数据库升级脚本入口。
    参数：
        无。
    返回值：
        None
    注意事项：
        执行失败会抛出异常并保留完整堆栈。
    """
    app = create_app()
    with app.app_context():
        try:
            _upgrade_secret_file_table()
            print("模块8数据库升级完成。")
        except SQLAlchemyError as exc:
            print(f"模块8数据库升级失败：{exc}")
            raise


if __name__ == "__main__":
    main()
