"""
tests/module12_integration_check.py
功能：模块12系统整合与全局功能回归脚本。
执行方式：
    python -X faulthandler tests/module12_integration_check.py
注意事项：
1. 依赖本地 MySQL 与已配置环境变量。
2. 脚本会创建并清理 module12_integration_* 测试数据。
"""

from __future__ import annotations

import io
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app import create_app
from app.models import AuditLog, SecretFile, User
from extensions import db
from utils.security_utils import hash_password

TEST_FILE_SECRET = "module12_integration_secret.txt"
TEST_FILE_CONFIDENTIAL = "module12_integration_confidential.txt"
TEST_FILE_TOP_SECRET = "module12_integration_top_secret.txt"
TEST_USER_LOW = "module12_integration_low"
TEST_USER_MID = "module12_integration_mid"
TEST_USER_HIGH = "module12_integration_high"
TEST_CSRF_TOKEN = "test-csrf-token"


def _set_session(client, account_id: int, account_type: str, username: str, security_level: str) -> None:
    """
    功能：向测试客户端注入登录会话。
    参数：
        client: Flask 测试客户端。
        account_id (int): 账号ID。
        account_type (str): 账号类型（customer/administrator）。
        username (str): 用户名。
        security_level (str): 安全级别。
    返回值：
        None
    注意事项：
        用于绕过登录页面，直接验证整合链路。
    """
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


def _cleanup_test_data() -> None:
    """
    功能：清理模块12整合测试产生的用户、文件与密钥。
    参数：
        无。
    返回值：
        None
    注意事项：
        仅清理 module12_integration_* 前缀数据，避免误删业务数据。
    """
    stale_files = SecretFile.query.filter(
        SecretFile.name.in_(
            [
                TEST_FILE_SECRET,
                TEST_FILE_CONFIDENTIAL,
                TEST_FILE_TOP_SECRET,
            ]
        )
    ).all()
    stale_ids = [int(item.id) for item in stale_files]

    if stale_files:
        group_ids = list({item.file_group_id for item in stale_files})
        SecretFile.query.filter(SecretFile.file_group_id.in_(group_ids)).delete(
            synchronize_session=False
        )

    User.query.filter(
        User.username.in_([TEST_USER_LOW, TEST_USER_MID, TEST_USER_HIGH])
    ).delete(synchronize_session=False)

    db.session.commit()

    for stale_id in stale_ids:
        key_path = PROJECT_ROOT / "keys" / f"{stale_id}.key"
        if key_path.exists():
            key_path.unlink()


def main() -> None:
    """
    功能：执行模块12系统整合功能回归。
    参数：
        无。
    返回值：
        None
    注意事项：
        任一步失败会抛出 AssertionError。
    """
    app = create_app()

    with app.app_context():
        _cleanup_test_data()

        low_user = User(
            name="模块12低级用户",
            username=TEST_USER_LOW,
            password=hash_password("Module12@123"),
            security_level="初级",
            status="启用",
            login_fail_count=0,
        )
        mid_user = User(
            name="模块12中级用户",
            username=TEST_USER_MID,
            password=hash_password("Module12@123"),
            security_level="中级",
            status="启用",
            login_fail_count=0,
        )
        high_user = User(
            name="模块12高级用户",
            username=TEST_USER_HIGH,
            password=hash_password("Module12@123"),
            security_level="高级",
            status="启用",
            login_fail_count=0,
        )
        db.session.add_all([low_user, mid_user, high_user])
        db.session.commit()

        low_user_id = int(low_user.id)
        mid_user_id = int(mid_user.id)
        high_user_id = int(high_user.id)

        before_user_change_logs = AuditLog.query.filter_by(operation_type="用户安全级别变更").count()
        before_file_change_logs = AuditLog.query.filter_by(operation_type="文件密级变更").count()
        before_upload_logs = AuditLog.query.filter_by(operation_type="文件加密存储").count()

    client = app.test_client()

    _set_session(
        client,
        account_id=1,
        account_type="administrator",
        username="admin",
        security_level="管理员",
    )

    upload_cases = [
        ("秘密", TEST_FILE_SECRET, b"module12-secret-payload"),
        ("机密", TEST_FILE_CONFIDENTIAL, b"module12-confidential-payload"),
        ("绝密", TEST_FILE_TOP_SECRET, b"module12-top-secret-payload"),
    ]
    for level, file_name, payload in upload_cases:
        upload_response = client.post(
            "/files/upload",
            data={
                "csrf_token": TEST_CSRF_TOKEN,
                "level": level,
                "secret_file": (io.BytesIO(payload), file_name),
            },
            content_type="multipart/form-data",
            follow_redirects=False,
        )
        assert upload_response.status_code == 302

    with app.app_context():
        secret_file = SecretFile.query.filter_by(name=TEST_FILE_SECRET, is_latest=True).first()
        confidential_file = SecretFile.query.filter_by(
            name=TEST_FILE_CONFIDENTIAL,
            is_latest=True,
        ).first()
        top_secret_file = SecretFile.query.filter_by(
            name=TEST_FILE_TOP_SECRET,
            is_latest=True,
        ).first()

        assert secret_file is not None
        assert confidential_file is not None
        assert top_secret_file is not None

        secret_group = secret_file.file_group_id
        confidential_group = confidential_file.file_group_id
        top_secret_group = top_secret_file.file_group_id

    _set_session(
        client,
        account_id=low_user_id,
        account_type="customer",
        username=TEST_USER_LOW,
        security_level="初级",
    )
    low_list_html = client.get("/files", follow_redirects=True).get_data(as_text=True)
    assert TEST_FILE_SECRET in low_list_html
    assert TEST_FILE_CONFIDENTIAL not in low_list_html
    assert TEST_FILE_TOP_SECRET not in low_list_html

    low_denied_response = client.get(
        f"/files/{confidential_group}/download",
        follow_redirects=True,
    )
    assert "权限不足" in low_denied_response.get_data(as_text=True)

    _set_session(
        client,
        account_id=mid_user_id,
        account_type="customer",
        username=TEST_USER_MID,
        security_level="中级",
    )
    mid_list_html = client.get("/files", follow_redirects=True).get_data(as_text=True)
    assert TEST_FILE_SECRET in mid_list_html
    assert TEST_FILE_CONFIDENTIAL in mid_list_html
    assert TEST_FILE_TOP_SECRET not in mid_list_html

    _set_session(
        client,
        account_id=high_user_id,
        account_type="customer",
        username=TEST_USER_HIGH,
        security_level="高级",
    )
    high_list_html = client.get("/files", follow_redirects=True).get_data(as_text=True)
    assert TEST_FILE_SECRET in high_list_html
    assert TEST_FILE_CONFIDENTIAL in high_list_html
    assert TEST_FILE_TOP_SECRET in high_list_html

    high_download_response = client.get(
        f"/files/{top_secret_group}/download",
        follow_redirects=False,
    )
    assert high_download_response.status_code == 200
    assert b"module12-top-secret-payload" in high_download_response.data

    _set_session(
        client,
        account_id=1,
        account_type="administrator",
        username="admin",
        security_level="管理员",
    )

    user_level_change_response = client.post(
        f"/abac/users/{low_user_id}/security-level",
        data={"security_level": "中级"},
        follow_redirects=False,
    )
    assert user_level_change_response.status_code == 302

    file_level_change_response = client.post(
        f"/abac/files/{secret_group}/level",
        data={"level": "绝密"},
        follow_redirects=False,
    )
    assert file_level_change_response.status_code == 302

    _set_session(
        client,
        account_id=low_user_id,
        account_type="customer",
        username=TEST_USER_LOW,
        security_level="中级",
    )
    low_after_change_html = client.get("/files", follow_redirects=True).get_data(as_text=True)
    assert TEST_FILE_SECRET not in low_after_change_html
    assert TEST_FILE_CONFIDENTIAL in low_after_change_html

    _set_session(
        client,
        account_id=1,
        account_type="administrator",
        username="admin",
        security_level="管理员",
    )
    audit_page_response = client.get(
        "/audit/logs?operation_type=文件加密存储",
        follow_redirects=True,
    )
    assert audit_page_response.status_code == 200
    assert "审计日志列表" in audit_page_response.get_data(as_text=True)

    export_response = client.get(
        "/audit/logs/export?operation_type=文件加密存储",
        follow_redirects=False,
    )
    assert export_response.status_code == 200
    assert "日志ID" in export_response.get_data(as_text=True)

    _set_session(
        client,
        account_id=mid_user_id,
        account_type="customer",
        username=TEST_USER_MID,
        security_level="中级",
    )
    denied_audit_response = client.get("/audit/logs", follow_redirects=True)
    assert "权限不足" in denied_audit_response.get_data(as_text=True)

    _set_session(
        client,
        account_id=1,
        account_type="administrator",
        username="admin",
        security_level="管理员",
    )

    with app.app_context():
        purge_record_ids = [
            int(item.id)
            for item in SecretFile.query.filter_by(file_group_id=confidential_group).all()
        ]

    delete_to_recycle_response = client.post(
        f"/files/{confidential_group}/delete",
        follow_redirects=False,
    )
    assert delete_to_recycle_response.status_code == 302

    purge_response = client.post(
        f"/files/{confidential_group}/purge",
        follow_redirects=False,
    )
    assert purge_response.status_code == 302

    with app.app_context():
        assert SecretFile.query.filter_by(file_group_id=confidential_group).count() == 0

        for record_id in purge_record_ids:
            key_path = PROJECT_ROOT / "keys" / f"{record_id}.key"
            assert not key_path.exists()

        refreshed_low_user = User.query.filter_by(id=low_user_id).first()
        assert refreshed_low_user is not None
        assert refreshed_low_user.security_level == "中级"

        changed_secret_files = SecretFile.query.filter_by(file_group_id=secret_group).all()
        assert changed_secret_files
        assert all(item.level == "绝密" for item in changed_secret_files)

        after_user_change_logs = AuditLog.query.filter_by(operation_type="用户安全级别变更").count()
        after_file_change_logs = AuditLog.query.filter_by(operation_type="文件密级变更").count()
        after_upload_logs = AuditLog.query.filter_by(operation_type="文件加密存储").count()

        assert after_user_change_logs >= before_user_change_logs + 1
        assert after_file_change_logs >= before_file_change_logs + 1
        assert after_upload_logs >= before_upload_logs + 3

        integrity_target_types = [
            "文件加密存储",
            "文件自动解密下载",
            "用户安全级别变更",
            "文件密级变更",
            "文件删除(回收站)",
            "文件彻底删除",
        ]
        target_logs = (
            AuditLog.query.filter(AuditLog.operation_type.in_(integrity_target_types))
            .order_by(AuditLog.id.desc())
            .limit(30)
            .all()
        )
        assert target_logs
        for log_item in target_logs:
            assert len((log_item.entry_hash or "").strip()) == 64
            assert len((log_item.prev_hash or "").strip()) in {0, 64}

        _cleanup_test_data()

    print("[MODULE12] system integration check passed")


if __name__ == "__main__":
    main()
