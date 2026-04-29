"""
app/services/__init__.py
功能：业务服务层包初始化文件。
注意事项：
1. 服务层用于封装可复用的业务逻辑。
2. 路由层仅负责参数接收和响应返回。
"""

from app.services.face_service import (
    FACE_MATCH_THRESHOLD,
    FaceServiceError,
    FaceVerificationResult,
    FaceVerificationService,
)
from app.services.abac_service import ABACService, ABACServiceError
from app.services.audit_log_service import AuditLogService, AuditLogServiceError
from app.services.file_crypto_service import FileCryptoService, FileCryptoServiceError
from app.services.fingerprint_service import (
    FINGERPRINT_MATCH_THRESHOLD,
    FingerprintMatchResult,
    FingerprintServiceError,
    FingerprintTemplate,
    FingerprintVerificationService,
)

__all__ = [
    "FaceServiceError",
    "FaceVerificationService",
    "FaceVerificationResult",
    "FACE_MATCH_THRESHOLD",
    "ABACService",
    "ABACServiceError",
    "AuditLogService",
    "AuditLogServiceError",
    "FileCryptoService",
    "FileCryptoServiceError",
    "FingerprintServiceError",
    "FingerprintVerificationService",
    "FingerprintTemplate",
    "FingerprintMatchResult",
    "FINGERPRINT_MATCH_THRESHOLD",
]
