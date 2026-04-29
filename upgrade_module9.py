"""
upgrade_module9.py
功能：将模块8遗留的全局密钥文件数据迁移到模块9独立文件密钥机制。
执行效果：
1. 识别没有 keys/<file_id>.key 的 secret_file 记录。
2. 尝试按旧格式（Base64 + 全局 AES_KEY）解密，再按独立随机密钥重新加密。
3. 为每条记录生成 keys/<file_id>.key，并更新 content 为新密文字节。
注意事项：
1. 可重复执行，已迁移记录会自动跳过。
2. 若某条记录内容无法按旧格式解密，会输出警告并保留原数据不变。
"""

from __future__ import annotations

from sqlalchemy.exc import SQLAlchemyError

from app import create_app
from app.models import SecretFile
from app.services.file_crypto_service import FileCryptoService, FileCryptoServiceError
from extensions import db
from utils.aes_utils import AESCryptoError, AESUtil


def main() -> None:
    """
    功能：执行模块9迁移。
    参数：
        无。
    返回值：
        None
    注意事项：
        迁移过程遇到无法识别数据时会跳过该记录。
    """
    app = create_app()

    with app.app_context():
        key_dir = app.config["FILE_KEY_DIR"]
        chunk_size = int(app.config["FILE_CRYPTO_CHUNK_SIZE"])

        migrated = 0
        skipped = 0

        records = SecretFile.query.order_by(SecretFile.id.asc()).all()
        for record in records:
            key_path = FileCryptoService.build_key_file_path(int(record.id), key_dir)
            if key_path.exists():
                skipped += 1
                continue

            raw_blob = bytes(record.content or b"")
            try:
                legacy_text = raw_blob.decode("utf-8")
                plain_bytes = AESUtil.decrypt_bytes(legacy_text, app.config["AES_KEY"])
            except (UnicodeDecodeError, AESCryptoError):
                print(f"[SKIP] file_id={record.id} 无法按旧格式解密，已跳过")
                skipped += 1
                continue

            try:
                encrypted_blob, key_file = FileCryptoService.encrypt_for_record(
                    record_id=int(record.id),
                    plain_bytes=plain_bytes,
                    key_dir=key_dir,
                    chunk_size=chunk_size,
                )
                record.content = encrypted_blob
                record.status = "已加密"
                migrated += 1
                print(f"[OK] file_id={record.id} 已迁移，key={key_file}")
            except FileCryptoServiceError as exc:
                print(f"[FAIL] file_id={record.id} 迁移失败：{exc}")
                skipped += 1

        try:
            db.session.commit()
        except SQLAlchemyError as exc:
            db.session.rollback()
            print(f"迁移提交失败：{exc}")
            raise

        print(f"模块9迁移完成：migrated={migrated}, skipped={skipped}")


if __name__ == "__main__":
    main()
