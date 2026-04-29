"""
upgrade_module13.py
功能：模块13升级脚本（文件目录层级字段与索引）。
执行效果：
1. 为 secret_file 表补齐 parent_id 与 is_folder 字段。
2. 为目录查询新增 idx_secret_file_parent_latest 索引。
执行方式：
    python upgrade_module13.py
"""

from __future__ import annotations

from sqlalchemy.exc import SQLAlchemyError

from app import create_app
from app.services.secret_file_schema_service import SecretFileSchemaService


def main() -> None:
    app = create_app()

    with app.app_context():
        try:
            SecretFileSchemaService.ensure_hierarchy_schema()
            print("[MODULE13] secret_file hierarchy schema upgrade completed")
        except SQLAlchemyError as exc:
            print(f"[MODULE13] upgrade failed: {exc}")
            raise
        except Exception as exc:
            print(f"[MODULE13] unexpected error: {exc}")
            raise


if __name__ == "__main__":
    main()
