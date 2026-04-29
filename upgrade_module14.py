"""
upgrade_module14.py
功能：模块14升级脚本（回收站扩展字段）。
执行效果：
1. 为 customer 表补齐 is_deleted、deleted_at 字段及索引。
2. 为 secret_file 表补齐 original_path 字段。
执行方式：
    python upgrade_module14.py
"""

from __future__ import annotations

from sqlalchemy.exc import SQLAlchemyError

from app import create_app
from app.services.secret_file_schema_service import SecretFileSchemaService
from app.services.user_schema_service import UserSchemaService


def main() -> None:
    app = create_app()

    with app.app_context():
        try:
            SecretFileSchemaService.ensure_hierarchy_schema()
            UserSchemaService.ensure_soft_delete_schema()
            print("[MODULE14] recycle schema upgrade completed")
        except SQLAlchemyError as exc:
            print(f"[MODULE14] upgrade failed: {exc}")
            raise
        except Exception as exc:
            print(f"[MODULE14] unexpected error: {exc}")
            raise


if __name__ == "__main__":
    main()
