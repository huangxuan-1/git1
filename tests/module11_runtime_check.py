"""
tests/module11_runtime_check.py
功能：模块11运行级冒烟脚本（防篡改审计日志：查询、分页、导出、不可修改删除）。
执行方式：
    python -X faulthandler tests/module11_runtime_check.py
注意事项：
1. 依赖本地 MySQL 与已配置环境变量。
2. 脚本会创建临时用户与测试文件，并在结束时清理。
"""

from __future__ import annotations

import io
import sys
from pathlib import Path

from sqlalchemy import text

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app import create_app
from app.models import AuditLog, AuditLogImmutableError, SecretFile, User
from app.services.audit_log_service import AuditLogService
from extensions import db

TEST_USER = "module11_user"
TEST_FILE = "module11_runtime_file.txt"
TEST_CSRF_TOKEN = "test-csrf-token"


def _set_session(client, account_id: int, account_type: str, username: str, security_level: str) -> None:
    with client.session_transaction() as sess:
        sess["account_id"] = account_id
        sess["account_type"] = account_type
        sess["account_name"] = username
        sess["username"] = username
        sess["security_level"] = security_level
        sess["csrf_token"] = TEST_CSRF_TOKEN
        if account_type == "administrator":
            sess["permissions"] = ["system:admin"]
        else:
            sess["permissions"] = ["file:view"]


def _cleanup() -> None:
    files = SecretFile.query.filter_by(name=TEST_FILE).all()
    stale_ids = [int(item.id) for item in files]

    if files:
        groups = list({item.file_group_id for item in files})
        SecretFile.query.filter(SecretFile.file_group_id.in_(groups)).delete(synchronize_session=False)

    User.query.filter_by(username=TEST_USER).delete(synchronize_session=False)

    for file_id in stale_ids:
        key_path = PROJECT_ROOT / "keys" / f"{file_id}.key"
        if key_path.exists():
            key_path.unlink()

    db.session.commit()


def main() -> None:
    app = create_app()

    with app.app_context():
        _cleanup()
        AuditLogService.ensure_immutable_triggers()

        test_user = User(
            name="模块11测试用户",
            username=TEST_USER,
            password="test-password",
            security_level="初级",
            status="启用",
            login_fail_count=0,
        )
        db.session.add(test_user)
        db.session.commit()
        test_user_id = int(test_user.id)

    client = app.test_client()

    _set_session(client, account_id=1, account_type="administrator", username="admin", security_level="管理员")

    upload_resp = client.post(
        "/files/upload",
        data={
            "csrf_token": TEST_CSRF_TOKEN,
            "level": "秘密",
            "secret_file": (io.BytesIO(b"module11-payload"), TEST_FILE),
        },
        content_type="multipart/form-data",
        follow_redirects=False,
    )
    assert upload_resp.status_code == 302

    with app.app_context():
        file_item = SecretFile.query.filter_by(name=TEST_FILE, is_latest=True).first()
        assert file_item is not None
        file_id = int(file_item.id)
        target_log = (
            AuditLog.query.filter_by(file_id=file_id)
            .order_by(AuditLog.id.desc())
            .first()
        )
        assert target_log is not None
        target_log_id = int(target_log.id)

        for index in range(25):
            AuditLogService.append_log(
                operation_type="分页测试",
                detail=f"分页日志-{index}",
                is_success=True,
                administrator_id=1,
            )
        db.session.commit()

    list_resp = client.get(
        f"/audit/logs?operation_type=文件加密存储&file_id={file_id}",
        follow_redirects=True,
    )
    assert list_resp.status_code == 200
    html = list_resp.get_data(as_text=True)
    assert "审计日志列表" in html
    assert str(file_id) in html

    detail_resp = client.get(
        f"/audit/logs/{target_log_id}",
        follow_redirects=True,
    )
    if detail_resp.status_code == 200:
        detail_html = detail_resp.get_data(as_text=True)
        assert "审计日志详情" in detail_html

    page_two_resp = client.get(
        "/audit/logs?operation_type=分页测试&page=2",
        follow_redirects=True,
    )
    assert page_two_resp.status_code == 200
    assert "2 /" in page_two_resp.get_data(as_text=True)

    export_resp = client.get(
        f"/audit/logs/export?operation_type=文件加密存储&file_id={file_id}",
        follow_redirects=False,
    )
    assert export_resp.status_code == 200
    export_text = export_resp.get_data(as_text=True)
    assert "日志ID" in export_text
    assert "文件ID" in export_text

    _set_session(client, account_id=test_user_id, account_type="customer", username=TEST_USER, security_level="初级")
    denied_resp = client.get("/audit/logs", follow_redirects=True)
    denied_html = denied_resp.get_data(as_text=True)
    assert "权限不足" in denied_html

    with app.app_context():
        any_log = AuditLog.query.order_by(AuditLog.id.desc()).first()
        assert any_log is not None

        old_detail = any_log.detail
        any_log.detail = old_detail + "-tamper"
        caught_update_block = False
        try:
            db.session.commit()
        except AuditLogImmutableError:
            db.session.rollback()
            caught_update_block = True
        except Exception:
            db.session.rollback()
            caught_update_block = True
        assert caught_update_block

        caught_delete_block = False
        try:
            db.session.execute(text("DELETE FROM audit_log WHERE id = :log_id"), {"log_id": any_log.id})
            db.session.commit()
        except Exception:
            db.session.rollback()
            caught_delete_block = True
        assert caught_delete_block

        _cleanup()

    print("[MODULE11] tamper-proof audit log check passed")


if __name__ == "__main__":
    main()
