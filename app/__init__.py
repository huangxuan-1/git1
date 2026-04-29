"""
app/__init__.py
功能：Flask 应用工厂，负责应用创建、扩展初始化、会话策略与基础路由注册。
注意事项：
1. 所有脚本应通过 from app import create_app 获取应用实例。
2. 本模块不包含具体业务蓝图，后续模块可在此扩展。
"""

import secrets

from flask import Flask, flash, jsonify, redirect, request, session, url_for
from jinja2 import select_autoescape
from werkzeug.exceptions import RequestEntityTooLarge

from config import Config
from extensions import db


def create_app() -> Flask:
	"""
	功能：创建并初始化 Flask 应用实例。
	参数：
		无。
	返回值：
		Flask: 已完成配置的 Flask 应用对象。
	注意事项：
		若扩展初始化失败，会抛出 RuntimeError 便于定位问题。
	"""
	app = Flask(
		__name__,
		template_folder="templates",
		static_folder="static",
	)
	app.config.from_object(Config)
	app.jinja_env.autoescape = select_autoescape(
		enabled_extensions=("html", "htm", "xml"),
		default_for_string=True,
		default=True,
	)

	try:
		db.init_app(app)
	except Exception as exc:
		raise RuntimeError("数据库扩展初始化失败，请检查配置。") from exc

	_register_template_helpers(app)
	_register_request_hooks(app)
	_register_routes(app)
	return app


def _register_template_helpers(app: Flask) -> None:
	"""
	功能：注册模板辅助函数。
	参数：
		app (Flask): Flask 应用实例。
	返回值：
		None
	注意事项：
		用于在模板中统一输出 CSRF 令牌。
	"""

	@app.context_processor
	def _inject_csrf_token():
		def csrf_token() -> str:
			token = session.get("csrf_token")
			if token:
				return str(token)

			new_token = secrets.token_urlsafe(32)
			session["csrf_token"] = new_token
			return new_token

		return {"csrf_token": csrf_token}


def _register_request_hooks(app: Flask) -> None:
	"""
	功能：注册请求钩子，统一设置会话策略与基础安全响应头。
	参数：
		app (Flask): Flask 应用实例。
	返回值：
		None
	注意事项：
		这里配置的是全局安全策略，后续模块应保持兼容。
	"""

	@app.before_request
	def _set_session_policy() -> None:
		"""
		功能：将当前请求的会话标记为永久会话。
		参数：
			无。
		返回值：
			None
		注意事项：
			实际生命周期由配置项 PERMANENT_SESSION_LIFETIME 控制。
		"""
		session.permanent = True
		if "csrf_token" not in session:
			session["csrf_token"] = secrets.token_urlsafe(32)

	@app.after_request
	def _set_security_headers(response):
		"""
		功能：统一追加基础安全响应头，降低常见 Web 攻击风险。
		参数：
			response (Response): 当前请求响应对象。
		返回值：
			Response: 添加安全头后的响应对象。
		注意事项：
			若后续模块有更严格 CSP 需求，可在此函数中集中维护。
		"""
		response.headers["X-Content-Type-Options"] = "nosniff"
		response.headers["X-Frame-Options"] = "SAMEORIGIN"
		response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
		# CSP 允许加载 MediaPipe CDN 资源（用于人脸活体检测）
		response.headers["Content-Security-Policy"] = (
			"default-src 'self'; "
			"img-src 'self' data: https:; "
			"style-src 'self' 'unsafe-inline'; "
			"script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
			"connect-src 'self' https://cdn.jsdelivr.net"
		)
		return response

	@app.errorhandler(RequestEntityTooLarge)
	def _handle_request_entity_too_large(_error):
		"""
		功能：处理上传体积超限异常并返回友好提示。
		参数：
			_error: 触发的异常对象。
		返回值：
			Response: JSON 或页面重定向响应。
		注意事项：
			文件路由下优先返回统一"文件过大"提示。
		"""
		message = "文件过大，单文件最大 100MB。"
		accept_header = (request.headers.get("Accept", "") or "").lower()
		requested_with = request.headers.get("X-Requested-With", "")
		wants_json = "application/json" in accept_header or requested_with == "XMLHttpRequest"

		if request.path.startswith("/files"):
			if wants_json:
				return jsonify({"status": "error", "message": message}), 413
			flash(message, "danger")
			return redirect(url_for("file.file_list_page"))

		if wants_json:
			return jsonify({"status": "error", "message": message}), 413
		return (
			jsonify({"status": "error", "message": message}),
			413,
		)


def _register_routes(app: Flask) -> None:
	"""
	功能：注册基础路由与业务蓝图。
	参数：
		app (Flask): Flask 应用实例。
	返回值：
		None
	注意事项：
		系统入口统一重定向到登录页。
	"""

	from app.routes import abac_bp, audit_bp, auth_bp, face_bp, file_bp, fingerprint_bp
	from app.services.secret_file_schema_service import SecretFileSchemaService
	from app.services.user_schema_service import UserSchemaService
	from app.services.audit_log_service import AuditLogService, AuditLogServiceError

	app.register_blueprint(abac_bp)
	app.register_blueprint(audit_bp)
	app.register_blueprint(auth_bp)
	app.register_blueprint(face_bp)
	app.register_blueprint(file_bp)
	app.register_blueprint(fingerprint_bp)

	with app.app_context():
		try:
			UserSchemaService.ensure_user_id_schema()
		except Exception as exc:
			app.logger.warning("customer 用户ID字段迁移失败: %s", exc)

		try:
			UserSchemaService.ensure_login_security_schema()
		except Exception as exc:
			app.logger.warning("登录锁定字段补齐失败: %s", exc)

		try:
			UserSchemaService.ensure_face_feature_schema()
		except Exception as exc:
			app.logger.warning("customer 人脸特征字段补齐失败: %s", exc)

		try:
			SecretFileSchemaService.ensure_hierarchy_schema()
		except Exception as exc:
			app.logger.warning("secret_file 层级字段补齐失败: %s", exc)

		try:
			UserSchemaService.ensure_soft_delete_schema()
		except Exception as exc:
			app.logger.warning("customer 回收站字段补齐失败: %s", exc)

		try:
			AuditLogService.ensure_immutable_triggers()
		except AuditLogServiceError as exc:
			app.logger.warning("审计日志触发器初始化失败: %s", exc)

	@app.route("/", methods=["GET"])
	def index():
		"""
		功能：系统入口统一重定向到登录页。
		参数：
			无。
		返回值：
			Response: 登录页重定向响应。
		注意事项：
			网页应用入口固定由登录页开始，避免进入测试/初始化页面。
		"""
		return redirect(url_for("auth.login"))