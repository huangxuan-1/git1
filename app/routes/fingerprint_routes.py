"""
app/routes/fingerprint_routes.py
功能：实现指纹注册、更新、比对与审计日志写入。
注意事项：
1. 本模块仅支持本地图片上传方式，不依赖硬件采集器。
2. 指纹模板保存前必须进行 AES-256-CBC 加密。
"""

from __future__ import annotations

from functools import wraps

from flask import (
    Blueprint,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from sqlalchemy.exc import SQLAlchemyError
from werkzeug.datastructures import FileStorage

from app.models import BiometricData
from app.routes.auth_routes import ONBOARDING_REQUIRED_KEY, login_required
from app.services.audit_log_service import AuditLogService
from app.services.fingerprint_service import (
    FINGERPRINT_MATCH_THRESHOLD,
    FingerprintMatchResult,
    FingerprintServiceError,
    FingerprintTemplate,
    FingerprintVerificationService,
)
from extensions import db

fingerprint_bp = Blueprint("fingerprint", __name__)


def customer_required(view_func):
    """
    功能：限制仅普通用户访问指纹模块。
    参数：
        view_func: 被装饰视图函数。
    返回值：
        Callable: 包装后的视图函数。
    注意事项：
        管理员访问时会跳转回控制台页面。
    """

    @wraps(view_func)
    def _wrapped(*args, **kwargs):
        if not session.get("account_id") or not session.get("account_type"):
            flash("请先登录后再访问该页面。", "warning")
            return redirect(url_for("auth.login"))

        if session.get("account_type") != "customer":
            flash("权限不足，请重新登录。", "danger")
            return redirect(url_for("auth.login", denied="1"))
        return view_func(*args, **kwargs)

    return _wrapped


def _record_audit(operation_type: str, detail: str, is_success: bool, customer_id: str) -> None:
    """
    功能：记录指纹模块审计日志。
    参数：
        operation_type (str): 操作类型。
        detail (str): 操作描述。
        is_success (bool): 操作是否成功。
        customer_id (str): 当前用户 ID。
    返回值：
        None
    注意事项：
        调用后需由业务函数控制事务提交。
    """
    AuditLogService.append_log(
        customer_id=customer_id,
        operation_type=operation_type,
        detail=detail,
        is_success=is_success,
        ip_address=AuditLogService.get_client_ip(),
    )


def _read_uploaded_fingerprint(field_name: str) -> bytes:
    """
    功能：读取上传的指纹图片文件内容。
    参数：
        field_name (str): 表单字段名。
    返回值：
        bytes: 指纹图片字节流。
    注意事项：
        上传文件缺失或为空时抛出 FingerprintServiceError。
    """
    file_item: FileStorage | None = request.files.get(field_name)
    if file_item is None or not file_item.filename:
        raise FingerprintServiceError("请先上传指纹图片后再提交。")

    file_bytes = file_item.read()
    if not file_bytes:
        raise FingerprintServiceError("上传的指纹图片为空，请重新选择文件。")

    return file_bytes


def _build_template_from_upload(field_name: str) -> FingerprintTemplate:
    """
    功能：从上传文件生成指纹模板。
    参数：
        field_name (str): 上传字段名。
    返回值：
        FingerprintTemplate: 提取后的指纹模板。
    注意事项：
        内部会执行预处理、细化和 minutiae 提取。
    """
    file_bytes = _read_uploaded_fingerprint(field_name)
    image_bgr = FingerprintVerificationService.decode_file_image(file_bytes)
    return FingerprintVerificationService.build_template(image_bgr)


def _save_fingerprint_feature(action_name: str):
    """
    功能：统一处理指纹注册与更新（演示模式）。
    参数：
        action_name (str): 操作名称（指纹注册/指纹更新）。
    返回值：
        Response: 页面跳转响应。
    注意事项：
        演示模式下直接通过，不进行实际的指纹特征提取。
    """
    customer_id = str(session.get("account_id") or "").strip()

    try:
        if session.get(ONBOARDING_REQUIRED_KEY):
            face_record = BiometricData.query.filter_by(
                customer_id=customer_id,
                feature_type="人脸",
            ).first()
            if face_record is None:
                flash("请先完成第一步：人脸录入。", "warning")
                return redirect(url_for("face.face_register_page"))

        # 演示模式：创建模拟指纹模板
        demo_template = FingerprintTemplate(
            minutiae=[
                {"x": 0.25, "y": 0.3, "type": "ending", "angle": 0.5},
                {"x": 0.35, "y": 0.4, "type": "ending", "angle": 1.2},
                {"x": 0.45, "y": 0.5, "type": "bifurcation", "angle": 0.8},
                {"x": 0.55, "y": 0.6, "type": "ending", "angle": 2.1},
                {"x": 0.65, "y": 0.7, "type": "bifurcation", "angle": 1.5},
            ],
            width=300,
            height=400,
        )
        encrypted_template = FingerprintVerificationService.encrypt_template(
            demo_template,
            current_app.config["AES_KEY"],
        )

        feature_record = BiometricData.query.filter_by(
            customer_id=customer_id,
            feature_type="指纹",
        ).first()

        operation_type = action_name
        if feature_record is None:
            feature_record = BiometricData(
                customer_id=customer_id,
                feature_type="指纹",
                feature_template=encrypted_template,
            )
            db.session.add(feature_record)
        else:
            feature_record.feature_template = encrypted_template
            operation_type = "指纹更新"

        _record_audit(
            operation_type=operation_type,
            detail=(
                f"用户 {customer_id} 指纹模板保存成功（演示模式）。"
            ),
            is_success=True,
            customer_id=customer_id,
        )
        db.session.commit()

        if session.get(ONBOARDING_REQUIRED_KEY):
            session.pop(ONBOARDING_REQUIRED_KEY, None)
            flash("生物特征注册已完成，正在进入系统主界面。", "success")
            return redirect(url_for("file.file_list_page"))

        flash("指纹模板保存成功。", "success")
        return redirect(url_for("fingerprint.fingerprint_page"))

    except FingerprintServiceError as exc:
        db.session.rollback()
        try:
            _record_audit(
                operation_type=action_name,
                detail=f"操作失败：{exc}",
                is_success=False,
                customer_id=customer_id,
            )
            db.session.commit()
        except SQLAlchemyError:
            db.session.rollback()

        flash(str(exc), "danger")
        return redirect(url_for("fingerprint.fingerprint_page"))
    except SQLAlchemyError as exc:
        db.session.rollback()
        current_app.logger.exception("指纹模板存储失败: %s", exc)
        flash("数据库操作失败，请稍后重试。", "danger")
        return redirect(url_for("fingerprint.fingerprint_page"))
    except Exception as exc:
        db.session.rollback()
        current_app.logger.exception("指纹保存异常: %s", exc)
        flash("发生未知错误，请稍后重试。", "danger")
        return redirect(url_for("fingerprint.fingerprint_page"))


@fingerprint_bp.route("/fingerprint", methods=["GET"])
@login_required
@customer_required
def fingerprint_page():
    """
    功能：渲染指纹注册和比对页面。
    参数：
        无。
    返回值：
        Response: 指纹页面响应。
    注意事项：
        页面仅支持上传本地图片。
    """
    customer_id = str(session.get("account_id") or "").strip()
    onboarding_required = bool(session.get(ONBOARDING_REQUIRED_KEY))
    if onboarding_required:
        face_record = BiometricData.query.filter_by(
            customer_id=customer_id,
            feature_type="人脸",
        ).first()
        if face_record is None:
            flash("请先完成第一步：人脸录入。", "warning")
            return redirect(url_for("face.face_register_page"))

    record = BiometricData.query.filter_by(
        customer_id=customer_id,
        feature_type="指纹",
    ).first()
    return render_template(
        "fingerprint_register.html",
        has_fingerprint_feature=record is not None,
        match_threshold=FINGERPRINT_MATCH_THRESHOLD,
        verify_result=None,
        onboarding_required=onboarding_required,
    )


@fingerprint_bp.route("/fingerprint/register", methods=["POST"])
@login_required
@customer_required
def fingerprint_register_submit():
    """
    功能：提交指纹注册请求。
    参数：
        无。
    返回值：
        Response: 页面跳转响应。
    注意事项：
        同一用户仅保留一条指纹模板记录。
    """
    return _save_fingerprint_feature("指纹注册")


@fingerprint_bp.route("/fingerprint/update", methods=["POST"])
@login_required
@customer_required
def fingerprint_update_submit():
    """
    功能：提交指纹更新请求。
    参数：
        无。
    返回值：
        Response: 页面跳转响应。
    注意事项：
        更新会覆盖已有指纹模板。
    """
    return _save_fingerprint_feature("指纹更新")


@fingerprint_bp.route("/fingerprint/verify", methods=["POST"])
@login_required
@customer_required
def fingerprint_verify_submit():
    """
    功能：执行指纹模板比对。
    参数：
        无。
    返回值：
        Response: 指纹页面响应（含比对结果）。
    注意事项：
        匹配阈值固定为 0.7，防止误识别。
    """
    customer_id = str(session.get("account_id") or "").strip()

    try:
        stored_record = BiometricData.query.filter_by(
            customer_id=customer_id,
            feature_type="指纹",
        ).first()
        if stored_record is None:
            _record_audit(
                operation_type="指纹比对",
                detail="比对失败：用户尚未注册指纹模板。",
                is_success=False,
                customer_id=customer_id,
            )
            db.session.commit()
            flash("尚未注册指纹模板，请先完成注册。", "warning")
            return redirect(url_for("fingerprint.fingerprint_page"))

        probe_template = _build_template_from_upload("verify_fingerprint_image_file")
        enrolled_template = FingerprintVerificationService.decrypt_template(
            stored_record.feature_template,
            current_app.config["AES_KEY"],
        )

        verify_result: FingerprintMatchResult = FingerprintVerificationService.match_templates(
            probe_template=probe_template,
            enrolled_template=enrolled_template,
            threshold=FINGERPRINT_MATCH_THRESHOLD,
        )

        _record_audit(
            operation_type="指纹比对",
            detail=(
                f"用户 {customer_id} 执行指纹比对，"
                f"score={verify_result.score:.6f}，阈值={FINGERPRINT_MATCH_THRESHOLD:.2f}，"
                f"matched_points={verify_result.matched_points}。"
            ),
            is_success=verify_result.is_match,
            customer_id=customer_id,
        )
        db.session.commit()

        if verify_result.is_match:
            flash("指纹比对通过。", "success")
        else:
            flash("指纹比对未通过，检测到非同一指纹。", "danger")

        return render_template(
            "fingerprint_register.html",
            has_fingerprint_feature=True,
            match_threshold=FINGERPRINT_MATCH_THRESHOLD,
            verify_result=verify_result,
            onboarding_required=bool(session.get(ONBOARDING_REQUIRED_KEY)),
        )

    except FingerprintServiceError as exc:
        db.session.rollback()
        try:
            _record_audit(
                operation_type="指纹比对",
                detail=f"比对失败：{exc}",
                is_success=False,
                customer_id=customer_id,
            )
            db.session.commit()
        except SQLAlchemyError:
            db.session.rollback()

        flash(str(exc), "danger")
        return redirect(url_for("fingerprint.fingerprint_page"))
    except SQLAlchemyError as exc:
        db.session.rollback()
        current_app.logger.exception("指纹比对数据库异常: %s", exc)
        flash("数据库操作失败，请稍后重试。", "danger")
        return redirect(url_for("fingerprint.fingerprint_page"))
    except Exception as exc:
        db.session.rollback()
        current_app.logger.exception("指纹比对异常: %s", exc)
        flash("发生未知错误，请稍后重试。", "danger")
        return redirect(url_for("fingerprint.fingerprint_page"))
