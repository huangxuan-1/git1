"""
tests/module8_runtime_check.py
功能：模块8运行级冒烟脚本（上传 -> 下载 -> 版本更新 -> 回收站 -> 彻底删除）。
执行方式：
    python -X faulthandler tests/module8_runtime_check.py
注意事项：
1. 依赖本地 MySQL 与已配置环境变量。
2. 脚本会创建并删除名为 module8_runtime_demo.txt 的测试文件。
"""

from __future__ import annotations

import io
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app import create_app
from app.models import SecretFile
from extensions import db

TEST_FILE_NAME = "module8_runtime_demo.txt"
TEST_CSRF_TOKEN = "test-csrf-token"


def main() -> None:
    """
    功能：执行模块8核心流程冒烟检查。
    参数：
        无。
    返回值：
        None
    注意事项：
        若任一步失败将抛出 AssertionError。
    """
    app = create_app()

    with app.app_context():
        SecretFile.query.filter(SecretFile.name == TEST_FILE_NAME).delete(
            synchronize_session=False
        )
        db.session.commit()

    client = app.test_client()

    with client.session_transaction() as sess:
        sess["account_id"] = 1
        sess["account_type"] = "administrator"
        sess["account_name"] = "admin"
        sess["username"] = "admin"
        sess["security_level"] = "管理员"
        sess["permissions"] = ["system:admin"]
        sess["csrf_token"] = TEST_CSRF_TOKEN

    upload_response = client.post(
        "/files/upload",
        data={
            "csrf_token": TEST_CSRF_TOKEN,
            "level": "秘密",
            "secret_file": (io.BytesIO(b"hello module8 v1"), TEST_FILE_NAME),
        },
        content_type="multipart/form-data",
        follow_redirects=False,
    )
    assert upload_response.status_code == 302

    with app.app_context():
        latest = SecretFile.query.filter_by(
            name=TEST_FILE_NAME,
            is_latest=True,
            is_deleted=False,
        ).first()
        assert latest is not None
        file_group_id = latest.file_group_id
        assert latest.version == "1.1"

    download_response = client.get(f"/files/{file_group_id}/download")
    assert download_response.status_code == 200
    assert b"hello module8 v1" in download_response.data

    update_response = client.post(
        f"/files/{file_group_id}/update",
        data={
            "csrf_token": TEST_CSRF_TOKEN,
            "name": TEST_FILE_NAME,
            "level": "机密",
            "major_version": "2",
            "secret_file": (io.BytesIO(b"hello module8 v2"), TEST_FILE_NAME),
        },
        content_type="multipart/form-data",
        follow_redirects=False,
    )
    assert update_response.status_code == 302

    history_response = client.get(f"/files/{file_group_id}/history")
    assert history_response.status_code == 200
    assert "2.1" in history_response.get_data(as_text=True)

    with app.app_context():
        latest_after_update = SecretFile.query.filter_by(
            file_group_id=file_group_id,
            is_latest=True,
        ).first()
        assert latest_after_update is not None
        assert latest_after_update.version == "2.1"

        version_count = SecretFile.query.filter_by(file_group_id=file_group_id).count()
        assert version_count == 2

    delete_response = client.post(
        f"/files/{file_group_id}/delete",
        follow_redirects=False,
    )
    assert delete_response.status_code == 302

    with app.app_context():
        recycle_count = SecretFile.query.filter_by(
            file_group_id=file_group_id,
            is_deleted=True,
        ).count()
        assert recycle_count == 2

    purge_response = client.post(
        f"/files/{file_group_id}/purge",
        follow_redirects=False,
    )
    assert purge_response.status_code == 302

    with app.app_context():
        final_count = SecretFile.query.filter_by(file_group_id=file_group_id).count()
        assert final_count == 0

    print("[MODULE8] upload/download/version/recycle/purge check passed")


if __name__ == "__main__":
    main()
