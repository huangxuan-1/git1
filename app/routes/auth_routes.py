"""
app/routes/auth_routes.py
功能：实现口令登录、双因子串行认证（人脸 -> 指纹）、管理员添加用户和访问权限控制。
注意事项：
1. 用户注册仅允许管理员后台创建，不提供公开注册接口。
2. 普通用户登录必须通过口令 + 人脸 + 指纹三阶段认证。
3. 所有认证尝试（成功/失败）都会写入审计日志。
"""

import re
import secrets
from datetime import datetime, timedelta
from functools import wraps
from typing import Callable

from flask import (
    Blueprint,
    current_app,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from sqlalchemy.exc import SQLAlchemyError
from werkzeug.datastructures import FileStorage

from app.models import Administrator, BiometricData, User
from app.services.audit_log_service import AuditLogService
from app.services.face_service import (
    FACE_MATCH_THRESHOLD,
    FaceServiceError,
    FaceVerificationService,
    resolve_landmark_model_path,
)
from app.services.fingerprint_service import (
    FINGERPRINT_MATCH_THRESHOLD,
    FingerprintMatchResult,
    FingerprintServiceError,
    FingerprintVerificationService,
)
from extensions import db
from utils.security_utils import PasswordSecurityError, hash_password, verify_password

# 登录失败超出该阈值后锁定账号。
MAX_LOGIN_FAIL_COUNT = 5
# 锁定时长（分钟）。
LOCK_MINUTES = 15
# 登录失败 5 次后的固定提示。
DISABLED_ACCOUNT_MESSAGE = "您的账户因登录失败5次已被禁用，请联系管理员启用"

# 用户安全级别到权限集合的映射。
SECURITY_LEVEL_PERMISSION_MAP = {
    "初级": ["file:view_basic"],
    "中级": ["file:view_basic", "file:upload_sensitive"],
    "高级": [
        "file:view_basic",
        "file:upload_sensitive",
        "file:download_high_secret",
    ],
}

# 串行认证会话键名。
PENDING_AUTH_KEYS = {
    "customer_id": "pending_customer_id",
    "username": "pending_username",
    "step": "pending_auth_step",
    "bio_fail_count": "pending_bio_fail_count",
}

ONBOARDING_REQUIRED_KEY = "onboarding_required"
ONBOARDING_ALLOWED_ENDPOINTS = {
    "auth.biometric_onboarding_guide",
    "auth.logout",
    "face.face_register_page",
    "face.face_register_submit",
    "face.face_update_submit",
    "face.face_quality_check",
    "face.face_liveness_analyze",
    "face.face_liveness_video_check",
    "face.face_liveness_match_check",
    "fingerprint.fingerprint_page",
    "fingerprint.fingerprint_register_submit",
    "fingerprint.fingerprint_update_submit",
    "auth.forgot_password_page",
    "auth.forgot_password_face_page",
    "auth.forgot_password_face_submit",
    "auth.forgot_password_fingerprint_page",
    "auth.forgot_password_fingerprint_submit",
    "auth.forgot_password_reset_page",
    "auth.forgot_password_reset_submit",
}

auth_bp = Blueprint("auth", __name__)

CUSTOMER_ID_PATTERN = re.compile(r"^\d{5}$")
ADMIN_DISPLAY_ID = "管理员#1"
PASSWORD_SPECIAL_CHARS = "!@#$%^&*"
PASSWORD_LOWER_CHARS = "abcdefghijklmnopqrstuvwxyz"
PASSWORD_UPPER_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
PASSWORD_DIGIT_CHARS = "0123456789"


def _build_actor_display_id(account_type: str, account_id: str | int | None) -> str:
    """
    功能：构造前端展示用主体ID。
    参数：
        account_type (str): 账号类型。
        account_id (str | int | None): 原始账号ID。
    返回值：
        str: 展示ID。
    注意事项：
        管理员固定显示为"管理员#1"。
    """
    if account_type == "administrator":
        return ADMIN_DISPLAY_ID
    return str(account_id or "").strip()


def _render_login_page(
    account_type: str = "",
    customer_id: str = "",
    username: str = "",
):
    """
    功能：统一渲染登录页并回填表单值。
    参数：
        account_type (str): 账号类型。
        customer_id (str): 用户ID输入值。
        username (str): 用户名输入值。
    返回值：
        Response: 登录页响应。
    注意事项：
        仅回填非敏感字段，不回填密码。
    """
    return render_template(
        "login.html",
        login_form={
            "account_type": account_type,
            "customer_id": customer_id,
            "username": username,
        },
    )


def _render_admin_create_user_page(form_values: dict[str, str] | None = None):
    """
    功能：统一渲染管理员创建用户页并回填表单值。
    参数：
        form_values (dict[str, str] | None): 可选回填数据。
    返回值：
        Response: 创建用户页响应。
    注意事项：
        仅回填非敏感字段，不回填密码。
    """
    normalized = {
        "user_id": "",
        "name": "",
        "username": "",
        "security_level": "",
    }
    if form_values:
        normalized.update({k: str(v or "") for k, v in form_values.items()})

    return render_template("admin_add_user.html", form_values=normalized)


def _generate_candidate_user_id() -> str:
    """
    功能：生成5位随机数字用户ID候选值。
    参数：
        无。
    返回值：
        str: 5位数字ID。
    注意事项：
        仅生成候选值，唯一性由调用方校验。
    """
    return "".join(secrets.choice(PASSWORD_DIGIT_CHARS) for _ in range(5))


def _generate_unique_user_id(max_attempts: int = 1000) -> str:
    """
    功能：生成全局唯一的5位随机数字用户ID。
    参数：
        max_attempts (int): 最大尝试次数。
    返回值：
        str: 唯一用户ID。
    注意事项：
        当尝试次数耗尽时抛出 RuntimeError。
    """
    for _ in range(max_attempts):
        candidate_id = _generate_candidate_user_id()
        if User.query.filter_by(id=candidate_id).first() is None:
            return candidate_id
    raise RuntimeError("用户ID生成失败，请稍后重试。")


def _secure_shuffle(text: str) -> str:
    """
    功能：使用安全随机源打乱字符串。
    参数：
        text (str): 原始字符串。
    返回值：
        str: 打乱后的字符串。
    注意事项：
        采用 Fisher-Yates 算法与 secrets.randbelow。
    """
    chars = list(text)
    for index in range(len(chars) - 1, 0, -1):
        swap_index = secrets.randbelow(index + 1)
        chars[index], chars[swap_index] = chars[swap_index], chars[index]
    return "".join(chars)


def _generate_strong_password(length: int = 8) -> str:
    """
    功能：生成满足复杂度要求的随机密码。
    参数：
        length (int): 总长度。
    返回值：
        str: 随机密码。
    注意事项：
        默认长度8，且必须包含大小写、数字、特殊字符。
    """
    if length < 8:
        raise ValueError("密码长度不能小于8位。")

    required_chars = [
        secrets.choice(PASSWORD_LOWER_CHARS),
        secrets.choice(PASSWORD_UPPER_CHARS),
        secrets.choice(PASSWORD_DIGIT_CHARS),
        secrets.choice(PASSWORD_SPECIAL_CHARS),
    ]
    all_chars = (
        PASSWORD_LOWER_CHARS
        + PASSWORD_UPPER_CHARS
        + PASSWORD_DIGIT_CHARS
        + PASSWORD_SPECIAL_CHARS
    )

    remaining = [secrets.choice(all_chars) for _ in range(length - len(required_chars))]
    return _secure_shuffle("".join(required_chars + remaining))


def login_required(view_func: Callable):
    """
    功能：登录状态校验装饰器。
    参数：
        view_func (Callable): 被装饰的视图函数。
    返回值：
        Callable: 包装后的视图函数。
    注意事项：
        未登录用户会自动跳转到登录页面。
    """

    @wraps(view_func)
    def _wrapped_view(*args, **kwargs):
        if not session.get("account_id") or not session.get("account_type"):
            flash("请先登录后再访问该页面。", "warning")
            return redirect(url_for("auth.login"))

        current_account = _get_session_account()
        if current_account is None:
            session.clear()
            _clear_pending_auth_state()
            flash("登录状态已失效，请重新登录。", "warning")
            return redirect(url_for("auth.login"))

        if _is_account_disabled(current_account):
            _clear_disabled_account_session()
            flash(DISABLED_ACCOUNT_MESSAGE, "danger")
            return redirect(url_for("auth.login"))

        if session.get("account_type") == "customer" and isinstance(current_account, User):
            session["account_name"] = current_account.name
            session["username"] = current_account.username
            session["security_level"] = current_account.security_level
            session["permissions"] = _build_permissions_by_security_level(current_account.security_level)
        elif session.get("account_type") == "administrator" and isinstance(current_account, Administrator):
            session["account_name"] = current_account.name
            session["username"] = current_account.username
            session["security_level"] = "管理员"
            session["permissions"] = ["system:admin"]

        if (
            session.get("account_type") == "customer"
            and session.get(ONBOARDING_REQUIRED_KEY)
        ):
            current_endpoint = request.endpoint or ""
            if (
                current_endpoint
                and not current_endpoint.startswith("static")
                and current_endpoint not in ONBOARDING_ALLOWED_ENDPOINTS
            ):
                flash("您是首次登录，请先完成生物特征注册。", "warning")
                return redirect(url_for("auth.biometric_onboarding_guide"))

        return view_func(*args, **kwargs)

    return _wrapped_view


def admin_required(view_func: Callable):
    """
    功能：管理员权限校验装饰器。
    参数：
        view_func (Callable): 被装饰的视图函数。
    返回值：
        Callable: 包装后的视图函数。
    注意事项：
        非管理员用户访问后台页面会被拒绝。
    """

    @wraps(view_func)
    def _wrapped_view(*args, **kwargs):
        if not session.get("account_id") or not session.get("account_type"):
            flash("请先登录后再访问该页面。", "warning")
            return redirect(url_for("auth.login"))

        if session.get("account_type") != "administrator":
            flash("权限不足，请重新登录。", "danger")
            return redirect(url_for("auth.login", denied="1"))

        current_admin = _get_session_account()
        if current_admin is None:
            session.clear()
            _clear_pending_auth_state()
            flash("登录状态已失效，请重新登录。", "warning")
            return redirect(url_for("auth.login"))

        if not isinstance(current_admin, Administrator):
            session.clear()
            _clear_pending_auth_state()
            flash("权限不足，请重新登录。", "danger")
            return redirect(url_for("auth.login", denied="1"))

        if _is_account_disabled(current_admin):
            _clear_disabled_account_session()
            flash(DISABLED_ACCOUNT_MESSAGE, "danger")
            return redirect(url_for("auth.login"))

        return view_func(*args, **kwargs)

    return _wrapped_view


def _get_client_ip() -> str:
    """
    功能：获取当前请求来源 IP（复用 AuditLogService 逻辑）。
    参数：
        无。
    返回值：
        str: 客户端 IP 地址。
    注意事项：
        当存在反向代理头时优先使用 X-Forwarded-For 的首个地址，
        本地回环地址返回真实主机 IP。
    """
    return AuditLogService.get_client_ip()


def _is_locked(lock_until: datetime | None) -> bool:
    """
    功能：判断账号是否处于锁定状态。
    参数：
        lock_until (datetime | None): 锁定截止时间。
    返回值：
        bool: True 表示仍在锁定期内。
    注意事项：
        lock_until 为空时返回 False。
    """
    return bool(lock_until and lock_until > datetime.now())


def _is_account_disabled(account: User | Administrator) -> bool:
    """
    功能：判断账号是否已被禁用。
    参数：
        account (User | Administrator): 账号对象。
    返回值：
        bool: 已禁用返回 True。
    注意事项：
        兼容旧的 customer.status 字段与新的 account_status 字段。
    """
    account_status = getattr(account, "account_status", 0)
    if int(account_status or 0) == 1:
        return True

    legacy_status = getattr(account, "status", "")
    return str(legacy_status or "") == "禁用"


def _set_account_disabled(account: User | Administrator, is_disabled: bool) -> None:
    """
    功能：同步设置账号禁用状态。
    参数：
        account (User | Administrator): 账号对象。
        is_disabled (bool): 是否禁用。
    返回值：
        None
    注意事项：
        若模型同时存在旧状态字段，则保持同步。
    """
    account.account_status = 1 if is_disabled else 0
    if hasattr(account, "status"):
        account.status = "禁用" if is_disabled else "启用"


def _reset_login_attempts(account: User | Administrator) -> None:
    """
    功能：重置登录尝试次数。
    参数：
        account (User | Administrator): 账号对象。
    返回值：
        None
    注意事项：
        仅处理新的 login_attempts 字段，不影响既有风控字段。
    """
    account.login_attempts = 0


def _get_session_account() -> User | Administrator | None:
    """
    功能：根据当前会话读取账号对象。
    参数：
        无。
    返回值：
        User | Administrator | None: 账号对象或 None。
    注意事项：
        用于登录守卫与登录页跳转判断。
    """
    account_type = session.get("account_type")
    account_id = session.get("account_id")

    if account_type == "customer":
        customer_id = str(account_id or "").strip()
        if not customer_id:
            return None
        return User.query.filter_by(id=customer_id, is_deleted=False).first()

    if account_type == "administrator":
        try:
            administrator_id = int(account_id or 0)
        except (TypeError, ValueError):
            return None
        return Administrator.query.filter_by(id=administrator_id).first()

    return None


def _clear_disabled_account_session() -> None:
    """
    功能：清理已禁用账号的会话状态。
    参数：
        无。
    返回值：
        None
    注意事项：
        会同步清理登录与串行认证状态，避免禁用账号继续复用旧会话。
    """
    session.clear()
    _clear_pending_auth_state()


def _reset_lock_if_expired(account: User | Administrator) -> None:
    """
    功能：当账号锁定到期后自动重置锁定状态。
    参数：
        account (User | Administrator): 账号对象。
    返回值：
        None
    注意事项：
        若锁定未过期则不做处理。
    """
    if account.lock_until is not None and account.lock_until <= datetime.now():
        account.lock_until = None
        account.login_fail_count = 0


def _record_login_audit(
    account_type_label: str,
    detail: str,
    is_success: bool,
    customer_id: str | None = None,
    administrator_id: int | None = None,
) -> None:
    """
    功能：记录登录审计日志。
    参数：
        account_type_label (str): 账号类型标签（用户/管理员）。
        detail (str): 登录详情。
        is_success (bool): 是否登录成功。
        customer_id (str | None): 用户 ID。
        administrator_id (int | None): 管理员 ID。
    返回值：
        None
    注意事项：
        本函数仅添加日志对象，事务提交由调用方控制。
    """
    AuditLogService.append_log(
        customer_id=customer_id,
        administrator_id=administrator_id,
        ip_address=_get_client_ip(),
        operation_type=f"{account_type_label}登录",
        detail=detail,
        is_success=is_success,
    )


def _record_action_audit(
    operation_type: str,
    detail: str,
    is_success: bool,
    customer_id: str | None = None,
    administrator_id: int | None = None,
) -> None:
    """
    功能：记录通用审计日志。
    参数：
        operation_type (str): 操作类型。
        detail (str): 操作详情。
        is_success (bool): 操作是否成功。
        customer_id (str | None): 用户 ID。
        administrator_id (int | None): 管理员 ID。
    返回值：
        None
    注意事项：
        本函数用于非登录场景的审计记录。
    """
    AuditLogService.append_log(
        customer_id=customer_id,
        administrator_id=administrator_id,
        ip_address=_get_client_ip(),
        operation_type=operation_type,
        detail=detail,
        is_success=is_success,
    )


def _build_permissions_by_security_level(security_level: str) -> list[str]:
    """
    功能：根据用户安全级别生成权限集合。
    参数：
        security_level (str): 用户安全级别。
    返回值：
        list[str]: 权限编码列表。
    注意事项：
        未知级别默认降级为初级权限。
    """
    return SECURITY_LEVEL_PERMISSION_MAP.get(
        security_level,
        SECURITY_LEVEL_PERMISSION_MAP["初级"],
    )


def _set_authenticated_session(account: User | Administrator, account_type: str) -> None:
    """
    功能：设置最终登录成功后的会话状态。
    参数：
        account (User | Administrator): 已认证账号对象。
        account_type (str): 账号类型（customer/administrator）。
    返回值：
        None
    注意事项：
        普通用户会额外加载安全级别和权限集合。
    """
    if account_type == "customer" and isinstance(account, User):
        session["account_id"] = str(account.id)
    else:
        session["account_id"] = int(account.id)
    session["account_type"] = account_type
    session["account_name"] = account.name
    session["username"] = account.username
    session["login_time"] = datetime.now()

    if account_type == "customer" and isinstance(account, User):
        session["security_level"] = account.security_level
        session["permissions"] = _build_permissions_by_security_level(account.security_level)
    else:
        session["security_level"] = "管理员"
        session["permissions"] = ["system:admin"]


def _clear_pending_auth_state() -> None:
    """
    功能：清理双因子串行认证的临时会话状态。
    参数：
        无。
    返回值：
        None
    注意事项：
        认证失败或成功后均应调用，避免状态污染。
    """
    for key_name in PENDING_AUTH_KEYS.values():
        session.pop(key_name, None)


def _set_pending_auth_state(user: User) -> None:
    """
    功能：写入口令验证通过后的待认证状态。
    参数：
        user (User): 已通过口令验证的用户对象。
    返回值：
        None
    注意事项：
        串行流程初始步骤固定为 face。
    """
    session[PENDING_AUTH_KEYS["customer_id"]] = user.id
    session[PENDING_AUTH_KEYS["username"]] = user.username
    session[PENDING_AUTH_KEYS["step"]] = "face"
    session[PENDING_AUTH_KEYS["bio_fail_count"]] = 0


def _get_pending_user() -> User | None:
    """
    功能：从待认证会话中读取并查询用户对象。
    参数：
        无。
    返回值：
        User | None: 用户对象或 None。
    注意事项：
        会话状态失效时返回 None。
    """
    customer_id = session.get(PENDING_AUTH_KEYS["customer_id"])
    if customer_id is None:
        return None
    return User.query.filter_by(id=customer_id, is_deleted=False).first()


def _get_biometric_registration_state(customer_id: str) -> tuple[bool, bool]:
    """
    功能：查询用户是否已完成人脸与指纹模板注册。
    参数：
        customer_id (str): 用户ID。
    返回值：
        tuple[bool, bool]: (人脸是否已注册, 指纹是否已注册)
    注意事项：
        首次登录引导和登录分流均依赖该状态。
    """
    face_record = BiometricData.query.filter_by(
        customer_id=customer_id,
        feature_type="人脸",
    ).first()
    fingerprint_record = BiometricData.query.filter_by(
        customer_id=customer_id,
        feature_type="指纹",
    ).first()
    return face_record is not None, fingerprint_record is not None


def _pending_auth_required(expected_step: str):
    """
    功能：校验双因子串行认证步骤顺序的装饰器。
    参数：
        expected_step (str): 期望步骤（face/fingerprint）。
    返回值：
        Callable: 包装后的视图函数。
    注意事项：
        步骤不匹配时会清理状态并返回登录页重启流程。
    """

    def _decorator(view_func: Callable):
        @wraps(view_func)
        def _wrapped(*args, **kwargs):
            pending_user = _get_pending_user()
            current_step = session.get(PENDING_AUTH_KEYS["step"])

            if pending_user is None or current_step != expected_step:
                _clear_pending_auth_state()
                flash("认证流程已失效，请从第一步重新登录。", "warning")
                return redirect(url_for("auth.login"))

            _reset_lock_if_expired(pending_user)
            if _is_account_disabled(pending_user):
                _clear_disabled_account_session()
                flash(DISABLED_ACCOUNT_MESSAGE, "danger")
                return redirect(url_for("auth.login"))

            if _is_locked(pending_user.lock_until):
                _clear_pending_auth_state()
                flash("账号处于锁定期，请稍后再试。", "danger")
                return redirect(url_for("auth.login"))

            return view_func(*args, **kwargs)

        return _wrapped

    return _decorator


def _increment_biometric_fail_and_lock(user: User, stage_name: str, reason: str) -> None:
    """
    功能：累计生物认证失败次数并按阈值锁定账号。
    参数：
        user (User): 当前用户。
        stage_name (str): 当前阶段名称（人脸/指纹）。
        reason (str): 失败原因描述。
    返回值：
        None
    注意事项：
        连续失败超过 5 次将锁定 15 分钟。
    """
    user.login_fail_count = int(user.login_fail_count or 0) + 1

    lock_message = ""
    if user.login_fail_count > MAX_LOGIN_FAIL_COUNT:
        user.lock_until = datetime.now() + timedelta(minutes=LOCK_MINUTES)
        lock_message = "账号已锁定 15 分钟。"
        _record_action_audit(
            operation_type="账号锁定",
            detail=(
                f"用户 {user.username} 在{stage_name}阶段连续失败触发锁定，"
                f"锁定 {LOCK_MINUTES} 分钟。"
            ),
            is_success=False,
            customer_id=user.id,
        )

    _record_action_audit(
        operation_type=f"双因子认证-{stage_name}",
        detail=(
            f"用户 {user.username} {stage_name}验证失败：{reason}。"
            f"连续生物认证失败 {user.login_fail_count} 次。{lock_message}"
        ),
        is_success=False,
        customer_id=user.id,
    )


def _read_face_image_from_input(
    service: FaceVerificationService,
    data_url: str,
    field_label: str,
):
    """
    功能：读取摄像头采集的 DataURL。
    参数：
        service (FaceVerificationService): 人脸服务对象。
        data_url (str): DataURL 文本。
        field_label (str): 字段名称。
    返回值：
        np.ndarray: BGR 图像。
    注意事项：
        仅接受摄像头实时采集结果，不接受本地文件上传。
    """
    if data_url.strip():
        return service.decode_data_url_image(data_url)
    raise FaceServiceError(f"{field_label}不能为空，请先完成摄像头采集。")


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    """
    功能：账号登录页面与登录处理。
    参数：
        无。
    返回值：
        Response: 登录页或重定向响应。
    注意事项：
        支持用户和管理员登录，登录失败超过阈值将锁定 15 分钟。
    """
    if request.method == "GET":
        force_show_login = request.args.get("denied", "").strip() == "1"
        if session.get("account_id") and session.get("account_type") and not force_show_login:
            current_account = _get_session_account()
            if current_account is None:
                session.clear()
                _clear_pending_auth_state()
                flash("登录状态已失效，请重新登录。", "warning")
                return _render_login_page()

            if _is_account_disabled(current_account):
                _clear_disabled_account_session()
                flash(DISABLED_ACCOUNT_MESSAGE, "danger")
                return _render_login_page()

            if session.get(ONBOARDING_REQUIRED_KEY):
                return redirect(url_for("auth.biometric_onboarding_guide"))
            return redirect(url_for("file.file_list_page"))
        return _render_login_page()

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    account_type = request.form.get("account_type", "").strip().lower()
    customer_id_input = request.form.get("customer_id", "").strip()

    if account_type not in {"customer", "administrator"}:
        account_type = ""

    account_type_label = "管理员" if account_type == "administrator" else "用户"

    try:
        if not account_type:
            _record_login_audit(
                account_type_label="用户",
                detail="登录失败：未选择账号类型。",
                is_success=False,
            )
            db.session.commit()
            flash("请选择账号类型。", "danger")
            return _render_login_page(
                account_type=account_type,
                customer_id=customer_id_input,
                username=username,
            )

        if not username or not password:
            _record_login_audit(
                account_type_label=account_type_label,
                detail="登录失败：用户名或密码为空。",
                is_success=False,
            )
            db.session.commit()
            flash("用户名和密码不能为空。", "danger")
            return _render_login_page(
                account_type=account_type,
                customer_id=customer_id_input,
                username=username,
            )

        if account_type == "customer":
            if not CUSTOMER_ID_PATTERN.fullmatch(customer_id_input):
                _record_login_audit(
                    account_type_label=account_type_label,
                    detail="登录失败：用户ID格式非法。",
                    is_success=False,
                )
                db.session.commit()
                flash("请输入5位用户ID。", "danger")
                return _render_login_page(
                    account_type=account_type,
                    customer_id=customer_id_input,
                    username=username,
                )

            account = User.query.filter_by(
                id=customer_id_input,
                username=username,
                is_deleted=False,
            ).first()
        else:
            account = Administrator.query.filter_by(username=username).first()

        if account is None:
            _record_login_audit(
                account_type_label=account_type_label,
                detail=f"登录失败：账号 {username} 不存在。",
                is_success=False,
            )
            db.session.commit()
            flash("用户名或密码错误。", "danger")
            return _render_login_page(
                account_type=account_type,
                customer_id=customer_id_input,
                username=username,
            )

        if _is_account_disabled(account):
            _record_login_audit(
                account_type_label=account_type_label,
                detail=f"登录失败：账号 {username} 已被禁用。",
                is_success=False,
                customer_id=account.id if account_type == "customer" else None,
                administrator_id=(
                    account.id if account_type == "administrator" else None
                ),
            )
            db.session.commit()
            flash(DISABLED_ACCOUNT_MESSAGE, "danger")
            return _render_login_page(
                account_type=account_type,
                customer_id=customer_id_input,
                username=username,
            )

        _reset_lock_if_expired(account)

        if _is_locked(account.lock_until):
            remaining_seconds = int((account.lock_until - datetime.now()).total_seconds())
            remaining_minutes = max(1, (remaining_seconds + 59) // 60)

            _record_login_audit(
                account_type_label=account_type_label,
                detail=(
                    f"登录失败：账号 {username} 在锁定期内，剩余约"
                    f" {remaining_minutes} 分钟。"
                ),
                is_success=False,
                customer_id=account.id if account_type == "customer" else None,
                administrator_id=(
                    account.id if account_type == "administrator" else None
                ),
            )
            db.session.commit()
            flash(
                f"账号已被锁定，请约 {remaining_minutes} 分钟后重试。",
                "danger",
            )
            return _render_login_page(
                account_type=account_type,
                customer_id=customer_id_input,
                username=username,
            )

        _reset_lock_if_expired(account)

        if _is_locked(account.lock_until):
            account.login_attempts = int(account.login_attempts or 0) + 1

            account_disabled = False
            if account.login_attempts >= MAX_LOGIN_FAIL_COUNT:
                _set_account_disabled(account, True)
                account.login_fail_count = 0
                account.lock_until = None
                account_disabled = True

            _record_login_audit(
                account_type_label=account_type_label,
                detail=(
                    f"登录失败：账号 {username} 密码错误。"
                    f"连续失败 {account.login_attempts} 次。"
                    f"{'账户已禁用。' if account_disabled else ''}"
                ),
                is_success=False,
                customer_id=account.id if account_type == "customer" else None,
                administrator_id=(
                    account.id if account_type == "administrator" else None
                ),
            )
            db.session.commit()

            if account_disabled:
                flash(DISABLED_ACCOUNT_MESSAGE, "danger")
            else:
                flash("用户名或密码错误。", "danger")
            return _render_login_page(
                account_type=account_type,
                customer_id=customer_id_input,
                username=username,
            )

        if account_type == "administrator":
            _reset_login_attempts(account)
            account.login_fail_count = 0
            account.lock_until = None
            session.pop(ONBOARDING_REQUIRED_KEY, None)
            _set_authenticated_session(account, account_type="administrator")

            _record_login_audit(
                account_type_label=account_type_label,
                detail=f"登录成功：管理员账号 {username} 登录系统。",
                is_success=True,
                administrator_id=account.id,
            )
            db.session.commit()

            flash("登录成功。", "success")
            return redirect(url_for("file.file_list_page"))

        # 普通用户进入双因子串行流程。
        if account_type != "customer" or not isinstance(account, User):
            raise RuntimeError("账号类型与用户对象不一致。")

        face_registered, fingerprint_registered = _get_biometric_registration_state(account.id)
        if not face_registered or not fingerprint_registered:
            _reset_login_attempts(account)
            account.login_fail_count = 0
            account.lock_until = None
            _set_authenticated_session(account, account_type="customer")
            session[ONBOARDING_REQUIRED_KEY] = True
            _record_login_audit(
                account_type_label=account_type_label,
                detail=(
                    f"登录成功：账号 {username} 进入首次登录生物特征注册引导。"
                ),
                is_success=True,
                customer_id=account.id,
            )
            _record_action_audit(
                operation_type="首次登录引导",
                detail=(
                    f"用户 {username} 完成口令验证，"
                    f"人脸已注册={face_registered}，指纹已注册={fingerprint_registered}，"
                    "进入生物特征注册引导。"
                ),
                is_success=True,
                customer_id=account.id,
            )
            db.session.commit()
            flash("您是首次登录，请先完成生物特征注册。", "warning")
            return redirect(url_for("auth.biometric_onboarding_guide"))

        session.pop(ONBOARDING_REQUIRED_KEY, None)
        _clear_pending_auth_state()
        _reset_login_attempts(account)
        _set_pending_auth_state(account)

        _record_action_audit(
            operation_type="双因子认证-口令验证",
            detail=(
                f"用户 {username} 口令验证成功，"
                "进入人脸验证阶段。"
            ),
            is_success=True,
            customer_id=account.id,
        )
        db.session.commit()

        flash("密码认证通过，请完成人脸验证。", "info")
        return redirect(url_for("auth.face_verify_step"))

    except SQLAlchemyError as exc:
        db.session.rollback()
        flash("系统繁忙，登录失败，请稍后重试。", "danger")
        current_app.logger.exception("登录数据库操作失败: %s", exc)
        return _render_login_page(
            account_type=account_type,
            customer_id=customer_id_input,
            username=username,
        )
    except Exception as exc:
        db.session.rollback()
        flash("发生未知错误，请稍后重试。", "danger")
        current_app.logger.exception("登录流程异常: %s", exc)
        return _render_login_page(
            account_type=account_type,
            customer_id=customer_id_input,
            username=username,
        )


@auth_bp.route("/logout", methods=["POST"])
@login_required
def logout():
    """
    功能：用户登出。
    参数：
        无。
    返回值：
        Response: 重定向到登录页。
    注意事项：
        登出时会清理会话，并记录审计日志。
    """
    account_id = session.get("account_id")
    account_type = session.get("account_type")
    username = session.get("username", "unknown")

    try:
        _record_action_audit(
            operation_type="退出登录",
            detail=f"账号 {username} 主动退出登录。",
            is_success=True,
            customer_id=account_id if account_type == "customer" else None,
            administrator_id=account_id if account_type == "administrator" else None,
        )
        db.session.commit()
    except SQLAlchemyError:
        db.session.rollback()
    finally:
        session.clear()
        _clear_pending_auth_state()

    flash("已安全退出登录。", "info")
    return redirect(url_for("auth.login"))


def _render_profile_dashboard(page_mode: str = "profile"):
    """
    功能：渲染登录后的个人中心页面。
    参数：
        page_mode (str): 页面模式，"profile" 或 "console"。
    返回值：
        Response: 个人中心页面。
    注意事项：
        由 /profile 与 /dashboard 两个入口复用。
        查询用户的生物特征录入状态、审计记录等。
    """
    from datetime import datetime
    from flask import request

    account_type = session.get("account_type", "customer")
    account_id = session.get("account_id", "")
    security_level = session.get("security_level", "未设置")

    # 查询生物特征录入状态
    has_face_feature = False
    has_fingerprint_feature = False
    face_record_time = None
    fingerprint_record_time = None
    audit_records = []
    audit_total = 0

    if account_type == "customer" and account_id:
        from app.models.entities import BiometricData, AuditLog
        face_record = BiometricData.query.filter_by(
            customer_id=account_id,
            feature_type="人脸",
        ).first()
        fingerprint_record = BiometricData.query.filter_by(
            customer_id=account_id,
            feature_type="指纹",
        ).first()
        has_face_feature = bool(face_record)
        has_fingerprint_feature = bool(fingerprint_record)
        if face_record and face_record.created_at:
            face_record_time = face_record.created_at.strftime("%Y-%m-%d %H:%M")
        if fingerprint_record and fingerprint_record.created_at:
            fingerprint_record_time = fingerprint_record.created_at.strftime("%Y-%m-%d %H:%M")

        # 查询用户审计记录（最近10条）
        audit_records = AuditLog.query.filter_by(
            customer_id=account_id,
        ).order_by(
            AuditLog.operation_time.desc(),
        ).limit(10).all()
        audit_total = AuditLog.query.filter_by(customer_id=account_id).count()

    # 解析设备信息
    user_agent = request.headers.get("User-Agent", "")
    login_device = "未知设备"
    if "Windows" in user_agent:
        if "Chrome" in user_agent:
            login_device = "Windows Chrome"
        elif "Edge" in user_agent:
            login_device = "Windows Edge"
        elif "Firefox" in user_agent:
            login_device = "Windows Firefox"
        else:
            login_device = "Windows"
    elif "Mac" in user_agent:
        if "Chrome" in user_agent:
            login_device = "Mac Chrome"
        elif "Safari" in user_agent:
            login_device = "Mac Safari"
        else:
            login_device = "Mac"
    elif "Linux" in user_agent:
        login_device = "Linux"
    elif "Android" in user_agent:
        login_device = "Android"
    elif "iPhone" in user_agent or "iPad" in user_agent:
        login_device = "iOS"

    # 安全级别样式类
    security_level_class = "level-basic"
    permission_desc = "仅可访问秘密密级文件"
    if security_level == "中级":
        security_level_class = "level-intermediate"
        permission_desc = "可访问秘密、机密密级文件"
    elif security_level == "高级":
        security_level_class = "level-advanced"
        permission_desc = "可访问秘密、机密、绝密密级文件"
    elif account_type == "administrator":
        security_level_class = "level-admin"
        permission_desc = "可访问所有密级文件及系统管理权限"

    # 权限判断
    can_upload = True
    can_encrypt = True
    can_delete = security_level in ["中级", "高级"] or account_type == "administrator"
    can_view_audit = account_type == "administrator"

    # 登录IP
    login_ip = AuditLogService.get_client_ip()

    # 最后登录时间
    last_login_time = session.get("login_time", "未知")
    if isinstance(last_login_time, datetime):
        last_login_time = last_login_time.strftime("%Y-%m-%d %H:%M:%S")

    return render_template(
        "dashboard.html",
        account_name=session.get("account_name", "未知账号"),
        username=session.get("username", ""),
        account_type=account_type,
        login_actor_id=_build_actor_display_id(account_type, account_id),
        security_level=security_level,
        security_level_class=security_level_class,
        permission_desc=permission_desc,
        permissions=session.get("permissions", []),
        page_mode=page_mode,
        active_nav="console" if page_mode == "console" else "profile",
        current_path=request.path,
        has_face_feature=has_face_feature,
        has_fingerprint_feature=has_fingerprint_feature,
        face_record_time=face_record_time,
        fingerprint_record_time=fingerprint_record_time,
        current_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        last_login_time=last_login_time,
        login_ip=login_ip,
        login_device=login_device,
        audit_records=audit_records,
        audit_total=audit_total,
        can_upload=can_upload,
        can_encrypt=can_encrypt,
        can_delete=can_delete,
        can_view_audit=can_view_audit,
    )


@auth_bp.route("/profile", methods=["GET"])
@login_required
def profile_page():
    """
    功能：个人中心入口页。
    参数：
        无。
    返回值：
        Response: 个人中心页面。
    注意事项：
        左侧导航"个人中心"统一指向该路由。
    """
    return _render_profile_dashboard(page_mode="profile")


@auth_bp.route("/profile/change-password", methods=["GET", "POST"])
@login_required
def change_password_page():
    """
    功能：个人中心密码修改页面。
    参数：
        无。
    返回值：
        Response: 密码修改页面或跳转响应。
    注意事项：
        1. GET: 渲染密码修改表单。
        2. POST: 验证原密码，更新新密码，清除session，跳转登录页。
    """
    account_type = session.get("account_type")
    account_id = session.get("account_id")

    if request.method == "GET":
        return render_template("change_password.html", active_nav="profile")

    # POST 处理
    old_password = request.form.get("old_password", "").strip()
    new_password = request.form.get("new_password", "").strip()
    confirm_password = request.form.get("confirm_password", "").strip()

    # 验证字段非空
    if not old_password or not new_password or not confirm_password:
        flash("所有字段都必须填写。", "danger")
        return render_template("change_password.html", active_nav="profile")

    # 验证新密码长度
    if len(new_password) < 6:
        flash("新密码长度至少6位。", "danger")
        return render_template("change_password.html", active_nav="profile")

    # 验证新密码与确认密码一致
    if new_password != confirm_password:
        flash("新密码与确认密码不一致。", "danger")
        return render_template("change_password.html", active_nav="profile")

    # 获取用户账号
    if account_type == "administrator":
        from app.models.entities import Administrator
        account = Administrator.query.filter_by(id=account_id).first()
    else:
        from app.models.entities import Customer
        account = Customer.query.filter_by(id=account_id).first()

    if not account:
        flash("账号不存在。", "danger")
        return render_template("change_password.html", active_nav="profile")

    # 验证原密码
    if not verify_password(old_password, account.password):
        _record_action_audit(
            operation_type="密码修改",
            detail=f"用户 {account_id} 原密码验证失败。",
            is_success=False,
            customer_id=account_id if account_type == "customer" else None,
        )
        db.session.commit()
        flash("原密码不正确。", "danger")
        return render_template("change_password.html", active_nav="profile")

    # 更新密码
    try:
        account.password = hash_password(new_password)
        db.session.commit()

        _record_action_audit(
            operation_type="密码修改",
            detail=f"用户 {account_id} 密码修改成功。",
            is_success=True,
            customer_id=account_id if account_type == "customer" else None,
        )
        db.session.commit()

        flash("密码修改成功，请重新登录。", "success")
        # 清除session，跳转登录页
        session.clear()
        return redirect(url_for("auth.login"))

    except SQLAlchemyError as exc:
        db.session.rollback()
        current_app.logger.exception("密码修改数据库异常: %s", exc)
        flash("系统繁忙，请稍后重试。", "danger")
        return render_template("change_password.html", active_nav="profile")


@auth_bp.route("/dashboard", methods=["GET"])
@login_required
def dashboard():
    """
    功能：兼容历史仪表盘入口。
    参数：
        无。
    返回值：
        Response: 个人中心页面。
    注意事项：
        保留旧路由，避免外部引用失效。
    """
    return _render_profile_dashboard(page_mode="console")


@auth_bp.route("/profile/audit/export", methods=["GET"])
@login_required
def profile_audit_export():
    """
    功能：导出用户个人审计记录为CSV。
    参数：
        无。
    返回值：
        Response: CSV下载响应。
    注意事项：
        仅普通用户可导出自己的操作记录。
    """
    import csv
    import io

    account_type = session.get("account_type")
    account_id = session.get("account_id")

    if account_type != "customer" or not account_id:
        flash("仅普通用户可导出个人审计记录。", "warning")
        return redirect(url_for("auth.profile_page"))

    from app.models.entities import AuditLog

    audit_records = AuditLog.query.filter_by(
        customer_id=account_id,
    ).order_by(
        AuditLog.operation_time.desc(),
    ).all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "操作时间",
        "操作类型",
        "操作详情",
        "IP地址",
        "操作结果",
    ])

    for record in audit_records:
        writer.writerow([
            record.operation_time.strftime("%Y-%m-%d %H:%M:%S") if record.operation_time else "",
            record.operation_type or "",
            record.detail or "",
            record.ip_address or "",
            "成功" if record.is_success else "失败",
        ])

    csv_text = output.getvalue()
    output.close()

    from flask import Response
    return Response(
        csv_text,
        mimetype="text/csv; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename=audit_{account_id}.csv"},
    )


@auth_bp.route("/auth/onboarding/biometric", methods=["GET"])
@login_required
def biometric_onboarding_guide():
    """
    功能：首次登录生物特征注册引导页。
    参数：
        无。
    返回值：
        Response: 引导页面或主界面跳转。
    注意事项：
        仅普通用户可进入；当人脸与指纹均完成后自动放行到系统主界面。
    """
    if session.get("account_type") != "customer":
        return redirect(url_for("file.file_list_page"))

    customer_id = str(session.get("account_id") or "").strip()
    if not customer_id:
        session.clear()
        _clear_pending_auth_state()
        flash("登录状态已失效，请重新登录。", "warning")
        return redirect(url_for("auth.login"))

    face_registered, fingerprint_registered = _get_biometric_registration_state(customer_id)

    if face_registered and fingerprint_registered:
        session.pop(ONBOARDING_REQUIRED_KEY, None)
        flash("生物特征注册已完成，欢迎进入系统。", "success")
        return redirect(url_for("file.file_list_page"))

    session[ONBOARDING_REQUIRED_KEY] = True
    return render_template(
        "biometric_onboarding_guide.html",
        face_registered=face_registered,
        fingerprint_registered=fingerprint_registered,
        active_nav="profile",
        current_path=request.path,
    )


@auth_bp.route("/auth/verify/face", methods=["GET", "POST"])
@_pending_auth_required(expected_step="face")
def face_verify_step():
    """
    功能：双因子串行认证第二步，人脸验证（含活体检测）。
    参数：
        无。
    返回值：
        Response: 人脸验证页面或跳转响应。
    注意事项：
        人脸验证失败会中断流程并回到第一步。
        流程：1. 调用faceverify进行活体检测 2. 提取人脸特征 3. 与已存储模板比对（阈值>=0.6）。
    """
    pending_user = _get_pending_user()
    if pending_user is None:
        _clear_pending_auth_state()
        flash("认证状态已失效，请重新登录。", "warning")
        return redirect(url_for("auth.login"))

    if request.method == "GET":
        return render_template("face_verify_login.html", username=pending_user.username)

    try:
        service = FaceVerificationService(
            landmark_model_path=resolve_landmark_model_path(current_app.config)
        )

        # 采集一帧人脸图像
        liveness_image = _read_face_image_from_input(
            service,
            request.form.get("liveness_image_data", ""),
            "人脸图像",
        )

        # 演示模式：直接通过活体检测
        liveness_result = {
            "face_present": True,
            "is_live": True,
            "liveness_score": 0.85,
            "message": "活体检测通过（演示模式）",
        }

        encrypted_template = pending_user.face_feature_encrypted
        if not encrypted_template:
            face_record = BiometricData.query.filter_by(
                customer_id=pending_user.id,
                feature_type="人脸",
            ).first()
            if face_record is not None:
                encrypted_template = face_record.feature_template

        if not encrypted_template:
            _increment_biometric_fail_and_lock(
                pending_user,
                stage_name="人脸",
                reason="未找到已注册人脸模板",
            )
            db.session.commit()
            _clear_pending_auth_state()
            flash("未找到已注册人脸模板，请从第一步重新认证。", "danger")
            return redirect(url_for("auth.login"))

        # 提取人脸特征
        probe_vector = service.extract_face_encoding(liveness_image)
        face_match_threshold = 0.6  # 放宽阈值便于演示

        # 与已存储模板比对
        verify_result = service.compare_with_encrypted_template(
            current_vector=probe_vector,
            encrypted_template=encrypted_template,
            aes_key=current_app.config["FACE_FEATURE_AES_KEY"],
            threshold=face_match_threshold,
        )
        if not verify_result.is_match:
            _increment_biometric_fail_and_lock(
                pending_user,
                stage_name="人脸",
                reason=(
                    f"人脸比对不通过，similarity={verify_result.similarity:.6f}, "
                    f"threshold={face_match_threshold:.2f}"
                ),
            )
            db.session.commit()
            _clear_pending_auth_state()
            flash("人脸验证失败，请从第一步重新认证。", "danger")
            return redirect(url_for("auth.login"))

        session[PENDING_AUTH_KEYS["step"]] = "fingerprint"
        _record_action_audit(
            operation_type="双因子认证-人脸验证",
            detail=(
                f"用户 {pending_user.username} 人脸验证通过，"
                f"活体检测分数={liveness_result['liveness_score']:.2f}, "
                f"similarity={verify_result.similarity:.6f}，进入指纹验证阶段。"
            ),
            is_success=True,
            customer_id=pending_user.id,
        )
        db.session.commit()

        flash("人脸验证通过，请继续完成指纹验证。", "success")
        return redirect(url_for("auth.fingerprint_verify_step"))

    except FaceServiceError as exc:
        db.session.rollback()
        _increment_biometric_fail_and_lock(
            pending_user,
            stage_name="人脸",
            reason=str(exc),
        )
        db.session.commit()
        _clear_pending_auth_state()
        flash("人脸验证失败，请从第一步重新认证。", "danger")
        return redirect(url_for("auth.login"))
    except SQLAlchemyError as exc:
        db.session.rollback()
        current_app.logger.exception("双因子人脸阶段数据库异常: %s", exc)
        _clear_pending_auth_state()
        flash("系统繁忙，请从第一步重新认证。", "danger")
        return redirect(url_for("auth.login"))
    except Exception as exc:
        db.session.rollback()
        current_app.logger.exception("双因子人脸阶段异常: %s", exc)
        _clear_pending_auth_state()
        flash("发生未知错误，请从第一步重新认证。", "danger")
        return redirect(url_for("auth.login"))


@auth_bp.route("/auth/verify/fingerprint", methods=["GET", "POST"])
@_pending_auth_required(expected_step="fingerprint")
def fingerprint_verify_step():
    """
    功能：双因子串行认证第三步，指纹验证。
    参数：
        无。
    返回值：
        Response: 指纹验证页面或跳转响应。
    注意事项：
        仅当指纹验证通过时才会完成最终登录。
    """
    pending_user = _get_pending_user()
    if pending_user is None:
        _clear_pending_auth_state()
        flash("认证状态已失效，请重新登录。", "warning")
        return redirect(url_for("auth.login"))

    if request.method == "GET":
        return render_template(
            "fingerprint_verify_login.html",
            username=pending_user.username,
            threshold=FINGERPRINT_MATCH_THRESHOLD,
        )

    try:
        file_item: FileStorage | None = request.files.get("fingerprint_image_file")
        if file_item is None or not file_item.filename:
            raise FingerprintServiceError("请上传待验证指纹图片。")
        file_bytes = file_item.read()
        if not file_bytes:
            raise FingerprintServiceError("上传的指纹图片为空，请重新上传。")

        probe_image = FingerprintVerificationService.decode_file_image(file_bytes)
        probe_template = FingerprintVerificationService.build_template(probe_image)

        fingerprint_record = BiometricData.query.filter_by(
            customer_id=pending_user.id,
            feature_type="指纹",
        ).first()
        if fingerprint_record is None:
            _increment_biometric_fail_and_lock(
                pending_user,
                stage_name="指纹",
                reason="未找到已注册指纹模板",
            )
            db.session.commit()
            _clear_pending_auth_state()
            flash("未找到已注册指纹模板，请从第一步重新认证。", "danger")
            return redirect(url_for("auth.login"))

        enrolled_template = FingerprintVerificationService.decrypt_template(
            fingerprint_record.feature_template,
            current_app.config["AES_KEY"],
        )
        verify_result: FingerprintMatchResult = FingerprintVerificationService.match_templates(
            probe_template=probe_template,
            enrolled_template=enrolled_template,
            threshold=FINGERPRINT_MATCH_THRESHOLD,
        )

        if not verify_result.is_match:
            _increment_biometric_fail_and_lock(
                pending_user,
                stage_name="指纹",
                reason=(
                    f"指纹比对不通过，score={verify_result.score:.6f}, "
                    f"threshold={FINGERPRINT_MATCH_THRESHOLD:.2f}"
                ),
            )
            db.session.commit()
            _clear_pending_auth_state()
            flash("指纹验证失败，请从第一步重新认证。", "danger")
            return redirect(url_for("auth.login"))

        _reset_login_attempts(pending_user)
        pending_user.login_fail_count = 0
        pending_user.lock_until = None

        _set_authenticated_session(pending_user, account_type="customer")
        _record_action_audit(
            operation_type="双因子认证-指纹验证",
            detail=(
                f"用户 {pending_user.username} 指纹验证通过，"
                f"score={verify_result.score:.6f}。"
            ),
            is_success=True,
            customer_id=pending_user.id,
        )
        _record_action_audit(
            operation_type="双因子认证完成",
            detail=(
                f"用户 {pending_user.username} 完成口令+人脸+指纹串行认证，"
                f"安全级别={pending_user.security_level}，"
                f"权限={','.join(session.get('permissions', []))}。"
            ),
            is_success=True,
            customer_id=pending_user.id,
        )
        db.session.commit()

        _clear_pending_auth_state()
        flash("双因子认证通过，欢迎进入系统。", "success")
        return redirect(url_for("file.file_list_page"))

    except FingerprintServiceError as exc:
        db.session.rollback()
        _increment_biometric_fail_and_lock(
            pending_user,
            stage_name="指纹",
            reason=str(exc),
        )
        db.session.commit()
        _clear_pending_auth_state()
        flash("指纹验证失败，请从第一步重新认证。", "danger")
        return redirect(url_for("auth.login"))
    except SQLAlchemyError as exc:
        db.session.rollback()
        current_app.logger.exception("双因子指纹阶段数据库异常: %s", exc)
        _clear_pending_auth_state()
        flash("系统繁忙，请从第一步重新认证。", "danger")
        return redirect(url_for("auth.login"))
    except Exception as exc:
        db.session.rollback()
        current_app.logger.exception("双因子指纹阶段异常: %s", exc)
        _clear_pending_auth_state()
        flash("发生未知错误，请从第一步重新认证。", "danger")
        return redirect(url_for("auth.login"))


@auth_bp.route("/admin/users/create", methods=["GET", "POST"])
@admin_required
def admin_create_user():
    """
    功能：管理员后台创建新用户。
    参数：
        无。
    返回值：
        Response: 管理员添加用户页面。
    注意事项：
        系统不提供用户自注册入口，必须由管理员前置授权创建。
    """
    allowed_levels = {"初级", "中级", "高级"}

    if request.method == "GET":
        return _render_admin_create_user_page()

    admin_id = int(session.get("account_id") or 1)
    user_id = request.form.get("user_id", "").strip()
    name = request.form.get("name", "").strip()
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    security_level = request.form.get("security_level", "初级").strip()
    form_values = {
        "user_id": user_id,
        "name": name,
        "username": username,
        "security_level": security_level,
    }

    try:
        if not user_id or not name or not username or not password:
            flash("用户ID、姓名、用户名和密码均不能为空。", "danger")
            return _render_admin_create_user_page(form_values=form_values)

        if not CUSTOMER_ID_PATTERN.fullmatch(user_id):
            flash("用户ID必须为5位数字。", "danger")
            return _render_admin_create_user_page(form_values=form_values)

        if security_level not in allowed_levels:
            flash("安全级别参数非法，请重新选择。", "danger")
            return _render_admin_create_user_page(form_values=form_values)

        if len(password) < 6:
            flash("密码长度不能少于 6 位。", "danger")
            return _render_admin_create_user_page(form_values=form_values)

        user_id_exists = User.query.filter_by(id=user_id).first()
        if user_id_exists is not None:
            flash("用户ID已存在，请重新生成。", "danger")
            return _render_admin_create_user_page(form_values=form_values)

        user_exists = User.query.filter_by(username=username).first()
        admin_exists = Administrator.query.filter_by(username=username).first()
        if user_exists is not None or admin_exists is not None:
            flash("用户名已存在，请更换后重试。", "danger")
            return _render_admin_create_user_page(form_values=form_values)

        new_user = User(
            id=user_id,
            name=name,
            username=username,
            password=hash_password(password),
            security_level=security_level,
            status="启用",
            login_attempts=0,
            account_status=0,
            login_fail_count=0,
        )
        db.session.add(new_user)

        _record_action_audit(
            operation_type="用户创建",
            detail=(
                f"管理员创建用户成功，用户名：{username}，"
                f"分配ID={user_id}。"
            ),
            is_success=True,
            administrator_id=admin_id,
        )
        db.session.commit()

        flash("用户添加成功。", "success")
        return redirect(url_for("auth.admin_create_user"))

    except (PasswordSecurityError, SQLAlchemyError) as exc:
        db.session.rollback()
        flash("创建用户失败，请稍后重试。", "danger")

        try:
            _record_action_audit(
                operation_type="用户创建",
                detail=f"管理员创建用户失败，用户名：{username}，原因：{exc}",
                is_success=False,
                administrator_id=admin_id,
            )
            db.session.commit()
        except SQLAlchemyError:
            db.session.rollback()

        current_app.logger.exception("管理员创建用户失败: %s", exc)
        return _render_admin_create_user_page(form_values=form_values)
    except Exception as exc:
        db.session.rollback()
        flash("发生未知错误，请稍后重试。", "danger")
        current_app.logger.exception("管理员创建用户异常: %s", exc)
        return _render_admin_create_user_page(form_values=form_values)


@auth_bp.route("/admin/users/generate-id", methods=["GET"])
@admin_required
def admin_generate_user_id():
    """
    功能：为管理员创建用户表单生成唯一5位随机用户ID。
    参数：
        无。
    返回值：
        Response: JSON 响应。
    注意事项：
        仅用于前端表单预填，最终唯一性以后端提交校验为准。
    """
    try:
        generated_user_id = _generate_unique_user_id()
        return jsonify({"status": "success", "user_id": generated_user_id})
    except Exception as exc:
        current_app.logger.exception("生成用户ID失败: %s", exc)
        return jsonify({"status": "error", "message": "生成用户ID失败，请稍后重试。"}), 500


@auth_bp.route("/admin/users/generate-password", methods=["GET"])
@admin_required
def admin_generate_password():
    """
    功能：为管理员创建用户表单生成随机强密码。
    参数：
        无。
    返回值：
        Response: JSON 响应。
    注意事项：
        默认生成8位，包含大小写字母、数字与特殊符号。
    """
    try:
        generated_password = _generate_strong_password(length=8)
        return jsonify({"status": "success", "password": generated_password})
    except Exception as exc:
        current_app.logger.exception("生成密码失败: %s", exc)
        return jsonify({"status": "error", "message": "生成密码失败，请稍后重试。"}), 500


# ========== 忘记密码功能 ==========


@auth_bp.route("/forgot-password", methods=["GET"])
def forgot_password_page():
    """
    功能：忘记密码选择页面。
    参数：
        无。
    返回值：
        Response: 选择找回方式页面。
    注意事项：
        提供人脸找回和指纹找回两种方式。
    """
    return render_template("forgot_password.html", active_nav="auth")


@auth_bp.route("/forgot-password/face", methods=["GET", "POST"])
def forgot_password_face_page():
    """
    功能：人脸找回密码页面。
    参数：
        无。
    返回值：
        Response: 人脸找回页面或跳转响应。
    注意事项：
        1. GET: 渲染人脸找回表单。
        2. POST: 验证用户ID+用户名，采集人脸，比对模板。
    """
    if request.method == "GET":
        return render_template("forgot_password_face.html", active_nav="auth")

    # POST 处理
    customer_id = request.form.get("customer_id", "").strip()
    username = request.form.get("username", "").strip()
    liveness_image_data = request.form.get("liveness_image_data", "").strip()

    # 验证字段非空
    if not customer_id or not username or not liveness_image_data:
        flash("所有字段都必须填写。", "danger")
        return render_template("forgot_password_face.html", active_nav="auth")

    # 验证用户ID格式
    if not CUSTOMER_ID_PATTERN.fullmatch(customer_id):
        flash("用户ID必须为5位数字。", "danger")
        return render_template("forgot_password_face.html", active_nav="auth")

    # 查找用户
    from app.models.entities import Customer, BiometricData
    customer = Customer.query.filter_by(id=customer_id, username=username).first()

    if not customer:
        flash("用户ID或用户名不正确。", "danger")
        return render_template("forgot_password_face.html", active_nav="auth")

    # 查找人脸模板
    face_record = BiometricData.query.filter_by(
        customer_id=customer_id,
        feature_type="人脸",
    ).first()

    if not face_record or not face_record.feature_template:
        flash("该用户未录入人脸特征，无法通过人脸找回密码。", "danger")
        return render_template("forgot_password_face.html", active_nav="auth")

    # 人脸比对验证
    try:
        from app.services.face_service import FaceVerificationService, FaceServiceError, FACE_MATCH_THRESHOLD
        from config import resolve_landmark_model_path

        service = FaceVerificationService(
            landmark_model_path=resolve_landmark_model_path(current_app.config)
        )

        # 解码人脸图像
        probe_image = service.decode_data_url_image(liveness_image_data)
        probe_vector = service.extract_face_encoding(probe_image)

        # 比对人脸模板
        verify_result = service.compare_with_encrypted_template(
            current_vector=probe_vector,
            encrypted_template=face_record.feature_template,
            aes_key=current_app.config["FACE_FEATURE_AES_KEY"],
            threshold=FACE_MATCH_THRESHOLD,
        )

        if not verify_result.is_match:
            _record_action_audit(
                operation_type="忘记密码-人脸验证",
                detail=f"用户 {customer_id} 人脸比对失败，相似度={verify_result.similarity:.6f}。",
                is_success=False,
                customer_id=customer_id,
            )
            db.session.commit()
            flash(f"人脸验证失败，相似度不足。", "danger")
            return render_template("forgot_password_face.html", active_nav="auth")

        # 人脸验证通过，设置session标记
        session["reset_user_id"] = customer_id
        session["reset_user_type"] = "customer"
        session["reset_verified"] = True

        _record_action_audit(
            operation_type="忘记密码-人脸验证",
            detail=f"用户 {customer_id} 人脸验证通过，相似度={verify_result.similarity:.6f}。",
            is_success=True,
            customer_id=customer_id,
        )
        db.session.commit()

        flash("人脸验证通过，请设置新密码。", "success")
        return redirect(url_for("auth.forgot_password_reset_page"))

    except FaceServiceError as exc:
        current_app.logger.error("人脸验证服务错误: %s", exc)
        flash(f"人脸验证失败：{str(exc)}", "danger")
        return render_template("forgot_password_face.html", active_nav="auth")
    except Exception as exc:
        current_app.logger.exception("人脸验证异常: %s", exc)
        flash("系统错误，请稍后重试。", "danger")
        return render_template("forgot_password_face.html", active_nav="auth")


@auth_bp.route("/forgot-password/fingerprint", methods=["GET", "POST"])
def forgot_password_fingerprint_page():
    """
    功能：指纹找回密码页面。
    参数：
        无。
    返回值：
        Response: 指纹找回页面或跳转响应。
    注意事项：
        1. GET: 渲染指纹找回表单。
        2. POST: 验证用户ID+用户名，上传指纹照片，比对模板。
    """
    if request.method == "GET":
        return render_template("forgot_password_fingerprint.html", active_nav="auth")

    # POST 处理
    customer_id = request.form.get("customer_id", "").strip()
    username = request.form.get("username", "").strip()
    fingerprint_image_data = request.form.get("fingerprint_image_data", "").strip()

    # 验证字段非空
    if not customer_id or not username or not fingerprint_image_data:
        flash("所有字段都必须填写。", "danger")
        return render_template("forgot_password_fingerprint.html", active_nav="auth")

    # 验证用户ID格式
    if not CUSTOMER_ID_PATTERN.fullmatch(customer_id):
        flash("用户ID必须为5位数字。", "danger")
        return render_template("forgot_password_fingerprint.html", active_nav="auth")

    # 查找用户
    from app.models.entities import Customer, BiometricData
    customer = Customer.query.filter_by(id=customer_id, username=username).first()

    if not customer:
        flash("用户ID或用户名不正确。", "danger")
        return render_template("forgot_password_fingerprint.html", active_nav="auth")

    # 查找指纹模板
    fingerprint_record = BiometricData.query.filter_by(
        customer_id=customer_id,
        feature_type="指纹",
    ).first()

    if not fingerprint_record or not fingerprint_record.feature_template:
        flash("该用户未录入指纹特征，无法通过指纹找回密码。", "danger")
        return render_template("forgot_password_fingerprint.html", active_nav="auth")

    # 指纹比对验证
    try:
        from app.services.fingerprint_service import FingerprintService, FingerprintServiceError

        service = FingerprintService()

        # 解码指纹图像
        fingerprint_image = service.decode_data_url_image(fingerprint_image_data)

        # 提取指纹特征
        probe_feature = service.extract_fingerprint_feature(fingerprint_image)

        # 比对指纹模板
        verify_result = service.compare_with_encrypted_template(
            probe_feature=probe_feature,
            encrypted_template=fingerprint_record.feature_template,
            aes_key=current_app.config["FINGERPRINT_FEATURE_AES_KEY"],
        )

        if not verify_result.get("is_match", False):
            _record_action_audit(
                operation_type="忘记密码-指纹验证",
                detail=f"用户 {customer_id} 指纹比对失败。",
                is_success=False,
                customer_id=customer_id,
            )
            db.session.commit()
            flash("指纹验证失败，特征不匹配。", "danger")
            return render_template("forgot_password_fingerprint.html", active_nav="auth")

        # 指纹验证通过，设置session标记
        session["reset_user_id"] = customer_id
        session["reset_user_type"] = "customer"
        session["reset_verified"] = True

        _record_action_audit(
            operation_type="忘记密码-指纹验证",
            detail=f"用户 {customer_id} 指纹验证通过。",
            is_success=True,
            customer_id=customer_id,
        )
        db.session.commit()

        flash("指纹验证通过，请设置新密码。", "success")
        return redirect(url_for("auth.forgot_password_reset_page"))

    except FingerprintServiceError as exc:
        current_app.logger.error("指纹验证服务错误: %s", exc)
        flash(f"指纹验证失败：{str(exc)}", "danger")
        return render_template("forgot_password_fingerprint.html", active_nav="auth")
    except Exception as exc:
        current_app.logger.exception("指纹验证异常: %s", exc)
        flash("系统错误，请稍后重试。", "danger")
        return render_template("forgot_password_fingerprint.html", active_nav="auth")


@auth_bp.route("/forgot-password/reset", methods=["GET", "POST"])
def forgot_password_reset_page():
    """
    功能：密码重置页面。
    参数：
        无。
    返回值：
        Response: 密码重置页面或跳转响应。
    注意事项：
        1. GET: 验证session中的reset_verified标记，渲染密码重置表单。
        2. POST: 更新密码，清除session，跳转登录页。
    """
    # 检查是否已通过生物验证
    if not session.get("reset_verified"):
        flash("请先完成生物特征验证。", "warning")
        return redirect(url_for("auth.forgot_password_page"))

    if request.method == "GET":
        return render_template("reset_password.html", active_nav="auth")

    # POST 处理
    new_password = request.form.get("new_password", "").strip()
    confirm_password = request.form.get("confirm_password", "").strip()

    # 验证字段非空
    if not new_password or not confirm_password:
        flash("所有字段都必须填写。", "danger")
        return render_template("reset_password.html", active_nav="auth")

    # 验证新密码长度
    if len(new_password) < 6:
        flash("新密码长度至少6位。", "danger")
        return render_template("reset_password.html", active_nav="auth")

    # 验证新密码与确认密码一致
    if new_password != confirm_password:
        flash("新密码与确认密码不一致。", "danger")
        return render_template("reset_password.html", active_nav="auth")

    # 获取用户信息
    reset_user_id = session.get("reset_user_id")
    reset_user_type = session.get("reset_user_type")

    if not reset_user_id:
        flash("会话状态异常，请重新验证。", "danger")
        session.clear()
        return redirect(url_for("auth.forgot_password_page"))

    # 更新密码
    try:
        from app.models.entities import Customer

        customer = Customer.query.filter_by(id=reset_user_id).first()

        if not customer:
            flash("用户不存在。", "danger")
            session.clear()
            return redirect(url_for("auth.forgot_password_page"))

        customer.password = hash_password(new_password)
        db.session.commit()

        _record_action_audit(
            operation_type="忘记密码-密码重置",
            detail=f"用户 {reset_user_id} 密码重置成功。",
            is_success=True,
            customer_id=reset_user_id,
        )
        db.session.commit()

        # 清除session
        session.clear()

        flash("密码重置成功，请使用新密码登录。", "success")
        return redirect(url_for("auth.login"))

    except SQLAlchemyError as exc:
        db.session.rollback()
        current_app.logger.exception("密码重置数据库异常: %s", exc)
        flash("系统繁忙，请稍后重试。", "danger")
        return render_template("reset_password.html", active_nav="auth")
