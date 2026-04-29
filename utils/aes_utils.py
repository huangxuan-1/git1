"""
utils/aes_utils.py
功能：提供 AES-256-CBC 加密与解密能力，支持字符串和二进制数据。
注意事项：
1. 密钥必须为 32 字节。
2. 每次加密均自动生成随机 IV，并将 IV 与密文一起返回。
3. 当前实现未内置消息认证码，后续可叠加 HMAC 做完整性保护。
"""

import base64
import os
from typing import Union

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class AESCryptoError(Exception):
    """
    功能：AES 工具统一异常类型。
    参数：
        message (str): 异常描述信息。
    返回值：
        无。
    注意事项：
        业务层可捕获该异常并返回统一友好提示。
    """


class AESUtil:
    """
    功能：AES-256-CBC 加解密工具类。
    参数：
        无。
    返回值：
        无。
    注意事项：
        所有方法均为静态方法，无需实例化。
    """

    @staticmethod
    def _validate_key(key: bytes) -> None:
        """
        功能：校验 AES 密钥长度是否合法。
        参数：
            key (bytes): 待校验密钥。
        返回值：
            None
        注意事项：
            AES-256 固定要求 32 字节密钥。
        """
        if not isinstance(key, bytes):
            raise AESCryptoError("AES 密钥类型错误，必须为 bytes。")
        if len(key) != 32:
            raise AESCryptoError("AES-256 密钥长度必须为 32 字节。")

    @staticmethod
    def encrypt_data(data: Union[str, bytes], key: bytes) -> str:
        """
        功能：对字符串或二进制数据进行 AES-256-CBC 加密。
        参数：
            data (Union[str, bytes]): 待加密数据。
            key (bytes): 32 字节 AES 密钥。
        返回值：
            str: Base64 编码后的密文（包含 16 字节随机 IV）。
        注意事项：
            返回值结构为 Base64(IV + CipherText)。
        """
        try:
            AESUtil._validate_key(key)

            if isinstance(data, str):
                plain_bytes = data.encode("utf-8")
            elif isinstance(data, bytes):
                plain_bytes = data
            else:
                raise AESCryptoError("加密数据类型错误，仅支持 str 或 bytes。")

            iv = os.urandom(16)
            padder = padding.PKCS7(algorithms.AES.block_size).padder()
            padded_data = padder.update(plain_bytes) + padder.finalize()

            cipher = Cipher(
                algorithms.AES(key),
                modes.CBC(iv),
                backend=default_backend(),
            )
            encryptor = cipher.encryptor()
            cipher_bytes = encryptor.update(padded_data) + encryptor.finalize()

            payload = iv + cipher_bytes
            return base64.b64encode(payload).decode("utf-8")
        except AESCryptoError:
            raise
        except Exception as exc:
            raise AESCryptoError("AES 加密失败，请检查输入数据与密钥。") from exc

    @staticmethod
    def decrypt_data(
        encrypted_data: str,
        key: bytes,
        return_bytes: bool = False,
    ) -> Union[str, bytes]:
        """
        功能：对 Base64 密文进行 AES-256-CBC 解密。
        参数：
            encrypted_data (str): Base64 密文（格式为 IV + CipherText）。
            key (bytes): 32 字节 AES 密钥。
            return_bytes (bool): 是否返回二进制结果，默认返回字符串。
        返回值：
            Union[str, bytes]: 解密后的明文。
        注意事项：
            当 return_bytes=False 时，明文必须是有效 UTF-8 文本。
        """
        try:
            AESUtil._validate_key(key)

            if not isinstance(encrypted_data, str) or not encrypted_data.strip():
                raise AESCryptoError("密文不能为空，且必须为 Base64 字符串。")

            payload = base64.b64decode(encrypted_data, validate=True)
            if len(payload) <= 16:
                raise AESCryptoError("密文长度非法，无法完成解密。")

            iv = payload[:16]
            cipher_bytes = payload[16:]

            cipher = Cipher(
                algorithms.AES(key),
                modes.CBC(iv),
                backend=default_backend(),
            )
            decryptor = cipher.decryptor()
            padded_plain = decryptor.update(cipher_bytes) + decryptor.finalize()

            unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
            plain_bytes = unpadder.update(padded_plain) + unpadder.finalize()

            if return_bytes:
                return plain_bytes

            return plain_bytes.decode("utf-8")
        except AESCryptoError:
            raise
        except UnicodeDecodeError as exc:
            raise AESCryptoError(
                "解密成功但明文不是 UTF-8 文本，请使用二进制模式读取。"
            ) from exc
        except Exception as exc:
            raise AESCryptoError("AES 解密失败，请检查密文与密钥是否匹配。") from exc

    @staticmethod
    def encrypt_string(plain_text: str, key: bytes) -> str:
        """
        功能：加密字符串数据。
        参数：
            plain_text (str): 待加密字符串。
            key (bytes): 32 字节 AES 密钥。
        返回值：
            str: Base64 密文。
        注意事项：
            该方法是 encrypt_data 的语义化封装。
        """
        return AESUtil.encrypt_data(plain_text, key)

    @staticmethod
    def decrypt_string(encrypted_data: str, key: bytes) -> str:
        """
        功能：解密字符串密文。
        参数：
            encrypted_data (str): Base64 密文。
            key (bytes): 32 字节 AES 密钥。
        返回值：
            str: 解密后的字符串明文。
        注意事项：
            若明文不是 UTF-8 文本将抛出 AESCryptoError。
        """
        return AESUtil.decrypt_data(encrypted_data, key, return_bytes=False)

    @staticmethod
    def encrypt_bytes(binary_data: bytes, key: bytes) -> str:
        """
        功能：加密二进制数据。
        参数：
            binary_data (bytes): 待加密的二进制内容。
            key (bytes): 32 字节 AES 密钥。
        返回值：
            str: Base64 密文。
        注意事项：
            适用于图片、文件片段等二进制内容。
        """
        return AESUtil.encrypt_data(binary_data, key)

    @staticmethod
    def decrypt_bytes(encrypted_data: str, key: bytes) -> bytes:
        """
        功能：解密二进制密文。
        参数：
            encrypted_data (str): Base64 密文。
            key (bytes): 32 字节 AES 密钥。
        返回值：
            bytes: 解密后的二进制内容。
        注意事项：
            返回值不会进行 UTF-8 解码。
        """
        result = AESUtil.decrypt_data(encrypted_data, key, return_bytes=True)
        if not isinstance(result, bytes):
            raise AESCryptoError("二进制解密结果类型异常。")
        return result
