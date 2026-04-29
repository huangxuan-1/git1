"""
tests/module9_runtime_check.py
功能：模块9运行级冒烟脚本（独立密钥 + 自动加解密 + 手动加解密 + 版本场景）。
执行方式：
    python -X faulthandler tests/module9_runtime_check.py
注意事项：
1. 依赖本地 MySQL 与已配置环境变量。
2. 脚本会创建并删除 module9_runtime_demo.bin 测试文件。
"""

from __future__ import annotations

import io
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app import create_app
from app.models import AuditLog, SecretFile
from extensions import db

TEST_FILE_NAME = "module9_runtime_demo.bin"
TEST_BYTES_V1 = b"module9-demo-v1" * 128
TEST_BYTES_V2 = b"module9-demo-v2" * 96
TEST_CSRF_TOKEN = "test-csrf-token"


def _key_file_path(file_id: int) -> Path:
    """
    功能：构造文件记录对应的密钥文件路径。
    参数：
        file_id (int): 文件记录ID。
    返回值：
        Path: 密钥文件路径。
    注意事项：
        路径格式固定为 keys/<file_id>.key。
    """
    return PROJECT_ROOT / "keys" / f"{file_id}.key"


def main() -> None:
    """
    功能：执行模块9核心链路冒烟验证。
    参数：
        无。
    返回值：
        None
    注意事项：
        任一步失败会抛出 AssertionError。
    """
    app = create_app()

    with app.app_context():
        stale_records = SecretFile.query.filter(SecretFile.name == TEST_FILE_NAME).all()
        stale_ids = [int(item.id) for item in stale_records]
        SecretFile.query.filter(SecretFile.name == TEST_FILE_NAME).delete(synchronize_session=False)
        db.session.commit()

        for stale_id in stale_ids:
            stale_key = _key_file_path(stale_id)
            if stale_key.exists():
                stale_key.unlink()

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
            "secret_file": (io.BytesIO(TEST_BYTES_V1), TEST_FILE_NAME),
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
        v1_id = int(latest.id)
        assert latest.version == "1.1"
        assert latest.status == "已加密"

        key_file_v1 = _key_file_path(v1_id)
        assert key_file_v1.exists()
        key_content_before = key_file_v1.read_text(encoding="ascii").strip()

        # 明文不应直接出现在数据库密文字段中。
        assert TEST_BYTES_V1 not in bytes(latest.content or b"")

    auto_download_response = client.get(f"/files/{file_group_id}/download")
    assert auto_download_response.status_code == 200
    assert auto_download_response.data == TEST_BYTES_V1

    manual_decrypt_response = client.get(f"/files/{file_group_id}/manual/decrypt")
    assert manual_decrypt_response.status_code == 200
    assert manual_decrypt_response.data == TEST_BYTES_V1

    manual_encrypt_response = client.post(
        f"/files/{file_group_id}/manual/encrypt",
        follow_redirects=False,
    )
    assert manual_encrypt_response.status_code == 302

    with app.app_context():
        latest_after_manual_encrypt = SecretFile.query.filter_by(
            file_group_id=file_group_id,
            is_latest=True,
        ).first()
        assert latest_after_manual_encrypt is not None
        key_content_after = _key_file_path(int(latest_after_manual_encrypt.id)).read_text(
            encoding="ascii"
        ).strip()
        assert key_content_after != key_content_before

    update_response = client.post(
        f"/files/{file_group_id}/update",
        data={
            "csrf_token": TEST_CSRF_TOKEN,
            "name": TEST_FILE_NAME,
            "level": "机密",
            "major_version": "2",
            "secret_file": (io.BytesIO(TEST_BYTES_V2), TEST_FILE_NAME),
        },
        content_type="multipart/form-data",
        follow_redirects=False,
    )
    assert update_response.status_code == 302

    with app.app_context():
        latest_v2 = SecretFile.query.filter_by(file_group_id=file_group_id, is_latest=True).first()
        assert latest_v2 is not None
        assert latest_v2.version == "2.1"
        assert latest_v2.file_size == len(TEST_BYTES_V2)

        key_file_v2 = _key_file_path(int(latest_v2.id))
        assert key_file_v2.exists()

        history_v1 = (
            SecretFile.query.filter_by(file_group_id=file_group_id, major_version=1, minor_version=1)
            .order_by(SecretFile.id.asc())
            .first()
        )
        assert history_v1 is not None
        history_v1_id = int(history_v1.id)

    history_download_response = client.get(
        f"/files/{file_group_id}/download/{history_v1_id}"
    )
    assert history_download_response.status_code == 200
    assert history_download_response.data == TEST_BYTES_V1

    delete_response = client.post(
        f"/files/{file_group_id}/delete",
        follow_redirects=False,
    )
    assert delete_response.status_code == 302

    purge_response = client.post(
        f"/files/{file_group_id}/purge",
        follow_redirects=False,
    )
    assert purge_response.status_code == 302

    with app.app_context():
        assert SecretFile.query.filter_by(file_group_id=file_group_id).count() == 0

        key_v1 = _key_file_path(v1_id)
        key_v2 = _key_file_path(int(latest_v2.id))
        assert not key_v1.exists()
        assert not key_v2.exists()

        audit_count = AuditLog.query.filter(
            AuditLog.operation_type.in_(
                [
                    "文件加密存储",
                    "文件自动解密下载",
                    "文件手动解密",
                    "文件手动加密",
                    "文件加密更新",
                    "历史版本解密下载",
                ]
            )
        ).count()
        assert int(audit_count) >= 6

    print("[MODULE9] per-file-key encryption/decryption check passed")


if __name__ == "__main__":
    main()
