"""
upgrade_module11.py
功能：模块11升级脚本。
执行效果：
1. 为 audit_log 表补充 file_id / prev_hash / entry_hash 字段与索引。
2. 回填历史审计日志哈希链。
3. 启用数据库层防篡改触发器（禁止更新/删除）。
执行方式：
    python upgrade_module11.py
"""

from __future__ import annotations

import hashlib
import sys
from datetime import datetime
from pathlib import Path

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app import create_app
from app.services.audit_log_service import AuditLogService
from extensions import db


def _column_exists(table_name: str, column_name: str) -> bool:
    count_value = db.session.execute(
        text(
            "SELECT COUNT(1) "
            "FROM information_schema.COLUMNS "
            "WHERE TABLE_SCHEMA = DATABASE() "
            "AND TABLE_NAME = :table_name "
            "AND COLUMN_NAME = :column_name"
        ),
        {"table_name": table_name, "column_name": column_name},
    ).scalar()
    return int(count_value or 0) > 0


def _index_exists(table_name: str, index_name: str) -> bool:
    count_value = db.session.execute(
        text(
            "SELECT COUNT(1) "
            "FROM information_schema.STATISTICS "
            "WHERE TABLE_SCHEMA = DATABASE() "
            "AND TABLE_NAME = :table_name "
            "AND INDEX_NAME = :index_name"
        ),
        {"table_name": table_name, "index_name": index_name},
    ).scalar()
    return int(count_value or 0) > 0


def _build_payload(row: dict, prev_hash: str) -> str:
    operation_time = row.get("operation_time")
    if isinstance(operation_time, datetime):
        operation_time_text = operation_time.strftime("%Y-%m-%d %H:%M:%S")
    else:
        operation_time_text = ""

    return "|".join(
        [
            str(row.get("customer_id") or ""),
            str(row.get("administrator_id") or ""),
            str(row.get("file_id") or ""),
            row.get("ip_address") or "",
            operation_time_text,
            row.get("operation_type") or "",
            row.get("detail") or "",
            "1" if bool(row.get("is_success")) else "0",
            prev_hash or "",
        ]
    )


def _ensure_columns_and_indexes() -> None:
    if not _column_exists("audit_log", "file_id"):
        db.session.execute(text("ALTER TABLE audit_log ADD COLUMN file_id INT NULL"))

    if not _column_exists("audit_log", "prev_hash"):
        db.session.execute(
            text(
                "ALTER TABLE audit_log "
                "ADD COLUMN prev_hash VARCHAR(64) NOT NULL DEFAULT ''"
            )
        )

    if not _column_exists("audit_log", "entry_hash"):
        db.session.execute(
            text(
                "ALTER TABLE audit_log "
                "ADD COLUMN entry_hash VARCHAR(64) NOT NULL DEFAULT ''"
            )
        )

    if not _index_exists("audit_log", "idx_audit_log_file_id"):
        db.session.execute(text("CREATE INDEX idx_audit_log_file_id ON audit_log (file_id)"))

    if not _index_exists("audit_log", "idx_audit_log_entry_hash"):
        db.session.execute(text("CREATE INDEX idx_audit_log_entry_hash ON audit_log (entry_hash)"))

    db.session.commit()


def _backfill_hash_chain() -> int:
    rows = db.session.execute(
        text(
            "SELECT id, customer_id, administrator_id, file_id, ip_address, "
            "operation_time, operation_type, detail, is_success "
            "FROM audit_log ORDER BY id ASC"
        )
    ).mappings().all()

    prev_hash = ""
    updated_count = 0

    for row in rows:
        row_dict = dict(row)
        payload = _build_payload(row_dict, prev_hash)
        entry_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()

        db.session.execute(
            text(
                "UPDATE audit_log SET prev_hash = :prev_hash, entry_hash = :entry_hash "
                "WHERE id = :log_id"
            ),
            {
                "prev_hash": prev_hash,
                "entry_hash": entry_hash,
                "log_id": row_dict["id"],
            },
        )

        prev_hash = entry_hash
        updated_count += 1

    db.session.commit()
    return updated_count


def main() -> None:
    app = create_app()

    with app.app_context():
        try:
            AuditLogService.drop_immutable_triggers_if_exists()
            _ensure_columns_and_indexes()
            count = _backfill_hash_chain()
            AuditLogService.ensure_immutable_triggers()
            print(f"[MODULE11] 升级完成，已回填日志哈希链 {count} 条。")
        except SQLAlchemyError as exc:
            db.session.rollback()
            print(f"[MODULE11] 升级失败：{exc}")
            raise
        except Exception as exc:
            db.session.rollback()
            print(f"[MODULE11] 升级异常：{exc}")
            raise


if __name__ == "__main__":
    main()
