"""
app/services/file_crypto_service.py
功能：提供模块9文件 AES-256-CBC 分块加解密与密钥文件安全管理能力。
注意事项：
1. 每个文件记录使用独立随机密钥（32字节）。
2. 密钥文件保存于项目根目录 keys 文件夹，命名格式为 文件ID.key。
3. 加解密按块处理，兼顾大文件与内存效率。
"""

from __future__ import annotations

import base64
import getpass
import os
import subprocess
from pathlib import Path

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class FileCryptoServiceError(Exception):
    """
    功能：文件加解密服务统一异常。
    参数：
        message (str): 异常说明。
    返回值：
        无。
    注意事项：
        路由层可捕获该异常并返回友好提示。
    """


class FileCryptoService:
    """
    功能：封装文件级 AES-256-CBC 加解密与密钥文件管理。
    参数：
        无。
    返回值：
        无。
    注意事项：
        所有方法均为静态方法，无需实例化。
    """

    @staticmethod
    def _validate_key(file_key: bytes) -> None:
        """
        功能：验证文件密钥是否合法。
        参数：
            file_key (bytes): 文件密钥。
        返回值：
            None
        注意事项：
            AES-256 固定要求 32 字节。
        """
        if not isinstance(file_key, bytes):
            raise FileCryptoServiceError("文件密钥类型错误，必须为 bytes。")
        if len(file_key) != 32:
            raise FileCryptoServiceError("文件密钥长度必须为 32 字节。")

    @staticmethod
    def _iter_chunks(binary_data: bytes, chunk_size: int):
        """
        功能：按固定大小迭代字节块。
        参数：
            binary_data (bytes): 输入字节串。
            chunk_size (int): 块大小。
        返回值：
            Iterator[bytes]: 分块迭代器。
        注意事项：
            chunk_size 最小为 4096。
        """
        block_size = max(4096, int(chunk_size or 4096))
        data_len = len(binary_data)
        for offset in range(0, data_len, block_size):
            yield binary_data[offset : offset + block_size]

    @staticmethod
    def _harden_windows_acl(target_path: Path, is_dir: bool) -> None:
        """
        功能：在 Windows 下收紧文件/目录 ACL。
        参数：
            target_path (Path): 目标路径。
            is_dir (bool): 是否目录。
        返回值：
            None
        注意事项：
            使用 icacls 最佳努力执行，失败时交由调用方继续。
        """
        if os.name != "nt":
            return

        current_user = getpass.getuser()
        grant_right = "(OI)(CI)F" if is_dir else "F"

        commands = [
            ["icacls", str(target_path), "/inheritance:r"],
            ["icacls", str(target_path), "/grant:r", f"{current_user}:{grant_right}"],
        ]

        for command in commands:
            subprocess.run(
                command,
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

    @staticmethod
    def ensure_key_directory(key_dir: str) -> Path:
        """
        功能：确保密钥目录存在并设置严格权限。
        参数：
            key_dir (str): 密钥目录路径。
        返回值：
            Path: 目录 Path 对象。
        注意事项：
            非 Windows 尝试设置 700 权限；Windows 使用 icacls 加固 ACL。
        """
        directory = Path(key_dir).resolve()
        directory.mkdir(parents=True, exist_ok=True)

        try:
            os.chmod(directory, 0o700)
        except OSError:
            pass

        try:
            FileCryptoService._harden_windows_acl(directory, is_dir=True)
        except Exception:
            pass

        return directory

    @staticmethod
    def build_key_file_path(file_id: int, key_dir: str) -> Path:
        """
        功能：生成文件密钥路径。
        参数：
            file_id (int): 文件记录 ID。
            key_dir (str): 密钥目录。
        返回值：
            Path: 密钥文件路径。
        注意事项：
            密钥文件名格式固定为 文件ID.key。
        """
        directory = FileCryptoService.ensure_key_directory(key_dir)
        return directory / f"{int(file_id)}.key"

    @staticmethod
    def generate_file_key() -> bytes:
        """
        功能：生成随机文件密钥。
        参数：
            无。
        返回值：
            bytes: 32 字节随机密钥。
        注意事项：
            使用系统随机源 os.urandom。
        """
        return os.urandom(32)

    @staticmethod
    def write_key_file(file_id: int, file_key: bytes, key_dir: str) -> str:
        """
        功能：将文件密钥写入 keys 目录。
        参数：
            file_id (int): 文件记录 ID。
            file_key (bytes): 32 字节密钥。
            key_dir (str): 密钥目录。
        返回值：
            str: 密钥文件绝对路径。
        注意事项：
            采用临时文件 + 原子替换，避免写入中断导致损坏。
        """
        FileCryptoService._validate_key(file_key)
        target_path = FileCryptoService.build_key_file_path(file_id, key_dir)
        temp_path = target_path.with_suffix(".tmp")

        encoded_key = base64.b64encode(file_key).decode("ascii")
        try:
            with temp_path.open("w", encoding="ascii", newline="") as key_file:
                key_file.write(encoded_key)

            os.replace(temp_path, target_path)

            try:
                os.chmod(target_path, 0o600)
            except OSError:
                pass

            try:
                FileCryptoService._harden_windows_acl(target_path, is_dir=False)
            except Exception:
                pass

            return str(target_path)
        except Exception as exc:
            try:
                if temp_path.exists():
                    temp_path.unlink()
            except OSError:
                pass
            raise FileCryptoServiceError(f"密钥文件写入失败：{exc}") from exc

    @staticmethod
    def load_key_file(file_id: int, key_dir: str) -> bytes:
        """
        功能：读取并校验文件密钥。
        参数：
            file_id (int): 文件记录 ID。
            key_dir (str): 密钥目录。
        返回值：
            bytes: 32 字节文件密钥。
        注意事项：
            文件不存在或格式非法时抛出异常。
        """
        key_path = FileCryptoService.build_key_file_path(file_id, key_dir)
        if not key_path.exists():
            raise FileCryptoServiceError(f"未找到文件密钥：{key_path.name}")

        try:
            encoded = key_path.read_text(encoding="ascii").strip()
            decoded = base64.b64decode(encoded, validate=True)
            FileCryptoService._validate_key(decoded)
            return decoded
        except FileCryptoServiceError:
            raise
        except Exception as exc:
            raise FileCryptoServiceError("密钥文件读取失败或内容损坏。") from exc

    @staticmethod
    def delete_key_file(file_id: int, key_dir: str) -> None:
        """
        功能：删除文件密钥文件。
        参数：
            file_id (int): 文件记录 ID。
            key_dir (str): 密钥目录。
        返回值：
            None
        注意事项：
            若文件不存在则忽略，不抛异常。
        """
        key_path = FileCryptoService.build_key_file_path(file_id, key_dir)
        try:
            if key_path.exists():
                key_path.unlink()
        except OSError as exc:
            raise FileCryptoServiceError(f"删除密钥文件失败：{exc}") from exc

    @staticmethod
    def encrypt_bytes(plain_bytes: bytes, file_key: bytes, chunk_size: int) -> bytes:
        """
        功能：按块执行 AES-256-CBC 加密。
        参数：
            plain_bytes (bytes): 明文数据。
            file_key (bytes): 32字节文件密钥。
            chunk_size (int): 分块大小。
        返回值：
            bytes: 密文字节（结构：IV + CipherText）。
        注意事项：
            使用 PKCS7 填充，输出可直接存入 LONGBLOB。
        """
        FileCryptoService._validate_key(file_key)
        if not isinstance(plain_bytes, bytes):
            raise FileCryptoServiceError("加密输入必须为 bytes。")

        try:
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(file_key), modes.CBC(iv))
            encryptor = cipher.encryptor()
            padder = padding.PKCS7(algorithms.AES.block_size).padder()

            output = bytearray(iv)
            for chunk in FileCryptoService._iter_chunks(plain_bytes, chunk_size):
                padded_chunk = padder.update(chunk)
                if padded_chunk:
                    output.extend(encryptor.update(padded_chunk))

            final_padded = padder.finalize()
            output.extend(encryptor.update(final_padded))
            output.extend(encryptor.finalize())
            return bytes(output)
        except Exception as exc:
            raise FileCryptoServiceError(f"文件加密失败：{exc}") from exc

    @staticmethod
    def decrypt_bytes(encrypted_blob: bytes, file_key: bytes, chunk_size: int) -> bytes:
        """
        功能：按块执行 AES-256-CBC 解密。
        参数：
            encrypted_blob (bytes): 密文字节（IV + CipherText）。
            file_key (bytes): 32字节文件密钥。
            chunk_size (int): 分块大小。
        返回值：
            bytes: 解密后的明文字节。
        注意事项：
            当密文非法或密钥不匹配时会抛出异常。
        """
        FileCryptoService._validate_key(file_key)
        if not isinstance(encrypted_blob, bytes):
            raise FileCryptoServiceError("解密输入必须为 bytes。")
        if len(encrypted_blob) <= 16:
            raise FileCryptoServiceError("密文长度非法，无法解密。")

        try:
            iv = encrypted_blob[:16]
            cipher_payload = encrypted_blob[16:]

            cipher = Cipher(algorithms.AES(file_key), modes.CBC(iv))
            decryptor = cipher.decryptor()
            unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()

            output = bytearray()
            for chunk in FileCryptoService._iter_chunks(cipher_payload, chunk_size):
                decrypted_chunk = decryptor.update(chunk)
                if decrypted_chunk:
                    output.extend(unpadder.update(decrypted_chunk))

            final_chunk = decryptor.finalize()
            if final_chunk:
                output.extend(unpadder.update(final_chunk))

            output.extend(unpadder.finalize())
            return bytes(output)
        except Exception as exc:
            raise FileCryptoServiceError(f"文件解密失败：{exc}") from exc

    @staticmethod
    def encrypt_for_record(
        record_id: int,
        plain_bytes: bytes,
        key_dir: str,
        chunk_size: int,
    ) -> tuple[bytes, str]:
        """
        功能：为指定文件记录生成新密钥并加密内容。
        参数：
            record_id (int): 文件记录 ID。
            plain_bytes (bytes): 明文。
            key_dir (str): 密钥目录。
            chunk_size (int): 分块大小。
        返回值：
            tuple[bytes, str]: (密文字节, 密钥文件路径)。
        注意事项：
            适用于上传新文件、保存新版本或手动重新加密。
        """
        file_key = FileCryptoService.generate_file_key()
        encrypted_blob = FileCryptoService.encrypt_bytes(plain_bytes, file_key, chunk_size)
        key_path = FileCryptoService.write_key_file(record_id, file_key, key_dir)
        return encrypted_blob, key_path

    @staticmethod
    def decrypt_for_record(
        record_id: int,
        encrypted_blob: bytes,
        key_dir: str,
        chunk_size: int,
    ) -> bytes:
        """
        功能：使用指定记录对应密钥解密文件内容。
        参数：
            record_id (int): 文件记录 ID。
            encrypted_blob (bytes): 密文字节。
            key_dir (str): 密钥目录。
            chunk_size (int): 分块大小。
        返回值：
            bytes: 明文字节。
        注意事项：
            要求 keys 目录中存在对应 文件ID.key。
        """
        file_key = FileCryptoService.load_key_file(record_id, key_dir)
        return FileCryptoService.decrypt_bytes(encrypted_blob, file_key, chunk_size)
