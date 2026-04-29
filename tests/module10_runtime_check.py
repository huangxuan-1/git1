"""
tests/module10_runtime_check.py
功能：模块10运行级冒烟脚本（ABAC 权限匹配 + 权限变更管理 + 审计日志）。
执行方式：
    python -X faulthandler tests/module10_runtime_check.py
注意事项：
1. 依赖本地 MySQL 与已配置环境变量。
2. 脚本会创建临时用户与测试文件，并在结束时清理文件记录与密钥文件。
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

TEST_FILE_SECRET = "module10_runtime_secret.txt"
TEST_FILE_CONFIDENTIAL = "module10_runtime_confidential.txt"
TEST_FILE_TOP_SECRET = "module10_runtime_top_secret.txt"
TEST_USER_LOW = "module10_low"
TEST_USER_MID = "module10_mid"
TEST_USER_HIGH = "module10_high"
TEST_CSRF_TOKEN = "test-csrf-token"


def _set_session(client, account_id: int, account_type: str, username: str, security_level: str) -> None:
    """
    功能：向测试客户端注入登录会话。
    参数：
        client: Flask 测试客户端。
        account_id (int): 账号ID。
        account_type (str): 账号类型。
        username (str): 用户名。
        security_level (str): 安全级别。
    返回值：
        None
    注意事项：
        用于绕过登录流程，直接验证业务权限链路。
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
    功能：清理旧测试数据，避免重复执行冲突。
    参数：
        无。
    返回值：
        None
    注意事项：
        仅清理模块10运行脚本使用的数据。
    """
    stale_files = SecretFile.query.filter(
        SecretFile.name.in_([
            TEST_FILE_SECRET,
            TEST_FILE_CONFIDENTIAL,
            TEST_FILE_TOP_SECRET,
        ])
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
    功能：执行模块10 ABAC 核心链路冒烟检查。
    参数：
        无。
    返回值：
        None
    注意事项：
        任一步失败将抛出 AssertionError。
    """
    app = create_app()

    with app.app_context():
        _cleanup_test_data()

        low_user = User(
            name="低级测试用户",
            username=TEST_USER_LOW,
            password="test-password",
            security_level="初级",
            status="启用",
            login_fail_count=0,
        )
        mid_user = User(
            name="中级测试用户",
            username=TEST_USER_MID,
            password="test-password",
            security_level="中级",
            status="启用",
            login_fail_count=0,
        )
        high_user = User(
            name="高级测试用户",
            username=TEST_USER_HIGH,
            password="test-password",
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

    client = app.test_client()

    _set_session(client, account_id=1, account_type="administrator", username="admin", security_level="管理员")

    for level, file_name, payload in [
        ("秘密", TEST_FILE_SECRET, b"module10-secret"),
        ("机密", TEST_FILE_CONFIDENTIAL, b"module10-confidential"),
        ("绝密", TEST_FILE_TOP_SECRET, b"module10-top-secret"),
    ]:
        response = client.post(
            "/files/upload",
            data={
                "csrf_token": TEST_CSRF_TOKEN,
                "level": level,
                "secret_file": (io.BytesIO(payload), file_name),
            },
            content_type="multipart/form-data",
            follow_redirects=False,
        )
        assert response.status_code == 302

    with app.app_context():
        secret_file = SecretFile.query.filter_by(name=TEST_FILE_SECRET, is_latest=True).first()
        confidential_file = SecretFile.query.filter_by(name=TEST_FILE_CONFIDENTIAL, is_latest=True).first()
        top_secret_file = SecretFile.query.filter_by(name=TEST_FILE_TOP_SECRET, is_latest=True).first()

        assert secret_file is not None
        assert confidential_file is not None
        assert top_secret_file is not None

        secret_group = secret_file.file_group_id
        confidential_group = confidential_file.file_group_id

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

    _set_session(client, account_id=1, account_type="administrator", username="admin", security_level="管理员")

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

    with app.app_context():
        refreshed_low_user = User.query.filter_by(id=low_user_id).first()
        assert refreshed_low_user is not None
        assert refreshed_low_user.security_level == "中级"

        changed_levels = SecretFile.query.filter_by(file_group_id=secret_group).all()
        assert changed_levels
        assert all(item.level == "绝密" for item in changed_levels)

        after_user_change_logs = AuditLog.query.filter_by(operation_type="用户安全级别变更").count()
        after_file_change_logs = AuditLog.query.filter_by(operation_type="文件密级变更").count()
        assert after_user_change_logs >= before_user_change_logs + 1
        assert after_file_change_logs >= before_file_change_logs + 1

    _set_session(
        client,
        account_id=mid_user_id,
        account_type="customer",
        username=TEST_USER_MID,
        security_level="中级",
    )
    post_change_html = client.get("/files", follow_redirects=True).get_data(as_text=True)
    assert TEST_FILE_SECRET not in post_change_html

    denied_after_change = client.get(
        f"/files/{secret_group}/download",
        follow_redirects=True,
    )
    assert "权限不足" in denied_after_change.get_data(as_text=True)

    with app.app_context():
        _cleanup_test_data()

    print("[MODULE10] ABAC access control and permission management check passed")


if __name__ == "__main__":
    main()
