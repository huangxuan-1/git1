"""
tests/module12_security_check.py
功能：模块12安全回归脚本（SQL 注入、XSS、越权访问）。
执行方式：
    python -X faulthandler tests/module12_security_check.py
注意事项：
1. 依赖本地 MySQL 与已配置环境变量。
2. 脚本会创建并清理 module12_security_* 测试数据。
"""

from __future__ import annotations

import io
import sys
from pathlib import Path

from sqlalchemy import or_
from werkzeug.utils import secure_filename

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app import create_app
from app.models import SecretFile, User
from extensions import db
from utils.security_utils import hash_password

TEST_USER = "module12_security_user"
TEST_XSS_USER = "module12_security_xss_user"
RAW_XSS_FILE_NAME = "<script>alert(1)</script>.txt"
SANITIZED_XSS_FILE_NAME = secure_filename(RAW_XSS_FILE_NAME)
TEST_OWNER_FILE_NAME = "module12_security_owner_file.txt"
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
        仅用于测试场景。
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
    功能：清理模块12安全测试数据。
    参数：
        无。
    返回值：
        None
    注意事项：
        仅清理 module12_security_* 前缀数据与对应密钥文件。
    """
    stale_files = SecretFile.query.filter(
        or_(
            SecretFile.name == SANITIZED_XSS_FILE_NAME,
            SecretFile.name == TEST_OWNER_FILE_NAME,
            SecretFile.name.like("module12_security_%"),
        )
    ).all()
    stale_ids = [int(item.id) for item in stale_files]

    if stale_files:
        group_ids = list({item.file_group_id for item in stale_files})
        SecretFile.query.filter(SecretFile.file_group_id.in_(group_ids)).delete(
            synchronize_session=False
        )

    User.query.filter(
        User.username.in_([TEST_USER, TEST_XSS_USER])
    ).delete(synchronize_session=False)
    db.session.commit()

    for stale_id in stale_ids:
        key_path = PROJECT_ROOT / "keys" / f"{stale_id}.key"
        if key_path.exists():
            key_path.unlink()


def main() -> None:
    """
    功能：执行模块12安全测试。
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

        user = User(
            name="模块12安全测试用户",
            username=TEST_USER,
            password=hash_password("Module12@123"),
            security_level="初级",
            status="启用",
            login_fail_count=0,
        )
        db.session.add(user)
        db.session.commit()
        user_id = int(user.id)

    anonymous_client = app.test_client()
    sql_injection_response = anonymous_client.post(
        "/login",
        data={
            "account_type": "customer",
            "username": "admin' OR '1'='1",
            "password": "anything",
        },
        follow_redirects=True,
    )
    assert sql_injection_response.status_code == 200
    sql_login_html = sql_injection_response.get_data(as_text=True)
    assert "用户名或密码错误" in sql_login_html or "登录失败" in sql_login_html

    client = app.test_client()

    _set_session(
        client,
        account_id=1,
        account_type="administrator",
        username="admin",
        security_level="管理员",
    )

    upload_xss_response = client.post(
        "/files/upload",
        data={
            "csrf_token": TEST_CSRF_TOKEN,
            "level": "秘密",
            "secret_file": (io.BytesIO(b"module12-security-xss"), RAW_XSS_FILE_NAME),
        },
        content_type="multipart/form-data",
        follow_redirects=False,
    )
    assert upload_xss_response.status_code == 302

    files_page_html = client.get("/files", follow_redirects=True).get_data(as_text=True)
    assert RAW_XSS_FILE_NAME not in files_page_html

    search_xss_html = client.get(
        "/files?q=<script>alert(1)</script>",
        follow_redirects=True,
    ).get_data(as_text=True)
    assert "<script>alert(1)</script>" not in search_xss_html

    create_xss_user_response = client.post(
        "/admin/users/create",
        data={
            "name": "<img src=x onerror=alert(1)>",
            "username": TEST_XSS_USER,
            "password": "Module12@123",
            "security_level": "初级",
        },
        follow_redirects=False,
    )
    assert create_xss_user_response.status_code == 302

    permission_html = client.get("/abac/permissions", follow_redirects=True).get_data(as_text=True)
    assert "<img src=x onerror=alert(1)>" not in permission_html

    with app.app_context():
        xss_file = SecretFile.query.filter_by(name=SANITIZED_XSS_FILE_NAME, is_latest=True).first()
        assert xss_file is not None
        xss_group = xss_file.file_group_id

    owner_file_response = client.post(
        "/files/upload",
        data={
            "csrf_token": TEST_CSRF_TOKEN,
            "level": "秘密",
            "secret_file": (io.BytesIO(b"module12-owner-file"), TEST_OWNER_FILE_NAME),
        },
        content_type="multipart/form-data",
        follow_redirects=False,
    )
    assert owner_file_response.status_code == 302

    with app.app_context():
        owner_file = SecretFile.query.filter_by(name=TEST_OWNER_FILE_NAME, is_latest=True).first()
        assert owner_file is not None
        owner_group = owner_file.file_group_id

    audit_sql_filter_response = client.get(
        "/audit/logs?operation_type=' OR 1=1 --&operator_id=1 OR 1=1",
        follow_redirects=True,
    )
    assert audit_sql_filter_response.status_code == 200

    _set_session(
        client,
        account_id=user_id,
        account_type="customer",
        username=TEST_USER,
        security_level="初级",
    )

    denied_abac_page = client.get("/abac/permissions", follow_redirects=True)
    assert "权限不足" in denied_abac_page.get_data(as_text=True)

    denied_audit_page = client.get("/audit/logs", follow_redirects=True)
    assert "权限不足" in denied_audit_page.get_data(as_text=True)

    denied_level_change = client.post(
        f"/abac/files/{xss_group}/level",
        data={"level": "绝密"},
        follow_redirects=True,
    )
    assert "权限不足" in denied_level_change.get_data(as_text=True)

    denied_purge = client.post(
        f"/files/{xss_group}/purge",
        follow_redirects=True,
    )
    assert "权限不足" in denied_purge.get_data(as_text=True)

    denied_delete_other_file = client.post(
        f"/files/{owner_group}/delete",
        follow_redirects=True,
    )
    assert "权限不足" in denied_delete_other_file.get_data(as_text=True)

    with app.app_context():
        owner_latest = SecretFile.query.filter_by(file_group_id=owner_group, is_latest=True).first()
        assert owner_latest is not None
        assert owner_latest.is_deleted is False

        _cleanup_test_data()

    print("[MODULE12] security regression check passed")


if __name__ == "__main__":
    main()
