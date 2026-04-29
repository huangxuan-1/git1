"""
routes 包初始化文件。
功能：存放后续业务蓝图与路由处理函数。
"""

from app.routes.auth_routes import admin_required, auth_bp, login_required
from app.routes.abac_routes import abac_bp
from app.routes.audit_routes import audit_bp
from app.routes.face_routes import customer_required, face_bp
from app.routes.file_routes import file_bp
from app.routes.fingerprint_routes import fingerprint_bp

__all__ = [
	"abac_bp",
	"audit_bp",
	"auth_bp",
	"face_bp",
	"file_bp",
	"fingerprint_bp",
	"login_required",
	"admin_required",
	"customer_required",
]
