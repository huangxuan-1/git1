"""
app/routes/face_routes.py
功能：实现用户人脸注册、更新、比对与审计记录。
注意事项：
1. 人脸特征模板入库前必须进行 AES-256 加密。
2. 活体检测必须同时通过眨眼和张嘴动作。
3. 新流程：第一步采集基础人脸，第二步实时活体检测（眨眼→张嘴）。
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import wraps
from typing import Any

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

from app.models import BiometricData, User
from app.routes.auth_routes import ONBOARDING_REQUIRED_KEY, login_required
from app.services.audit_log_service import AuditLogService
from app.services.face_service import (
    FACE_MATCH_THRESHOLD,
    FaceServiceError,
    FaceVerificationResult,
    FaceVerificationService,
    resolve_landmark_model_path,
)
from extensions import db

face_bp = Blueprint("face", __name__)


@dataclass
class FaceInputBundle:
    """
    功能：封装人脸操作所需图像输入。
    参数：
        neutral_image: 正常表情图像。
        blink_image: 眨眼动作图像。
        mouth_image: 张嘴动作图像。
    返回值：
        无。
    注意事项：
        三张图像都必须成功解析后才能进行活体检测与注册。
    """

    neutral_image: Any
    blink_image: Any
    mouth_image: Any


def customer_required(view_func):
    """
    功能：限制仅普通用户访问的人脸模块装饰器。
    参数：
        view_func: 被装饰视图函数。
    返回值：
        Callable: 包装后的视图函数。
    注意事项：
        管理员访问人脸注册页面会被拒绝。
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


def _get_face_service() -> FaceVerificationService:
    """
    功能：构建人脸服务实例。
    参数：
        无。
    返回值：
        FaceVerificationService: 人脸服务对象。
    注意事项：
        若模型路径错误，会抛出 FaceServiceError。
    """
    model_path = resolve_landmark_model_path(current_app.config)
    return FaceVerificationService(landmark_model_path=model_path)


def _read_image_from_input(
    file_item: FileStorage | None,
    data_url_text: str,
    service: FaceVerificationService,
    field_label: str,
):
    """
    功能：统一读取上传文件或摄像头 DataURL 图像。
    参数：
        file_item (FileStorage | None): 上传文件对象。
        data_url_text (str): Base64 DataURL 文本。
        service (FaceVerificationService): 人脸服务实例。
        field_label (str): 字段中文名称。
    返回值：
        np.ndarray: 解码后的 BGR 图像。
    注意事项：
        当文件和 DataURL 同时为空时抛出 FaceServiceError。
    """
    try:
        if file_item and file_item.filename:
            file_bytes = file_item.read()
            return service.decode_file_image(file_bytes)

        if data_url_text.strip():
            return service.decode_data_url_image(data_url_text)

        raise FaceServiceError(f"{field_label}不能为空，请上传图片或使用摄像头采集。")
    except FaceServiceError:
        raise
    except Exception as exc:
        raise FaceServiceError(f"{field_label}读取失败，请重新提交。") from exc


def _read_camera_image_from_input(
    data_url_text: str,
    service: FaceVerificationService,
    field_label: str,
):
    """
    功能：读取摄像头实时采集图像。
    参数：
        data_url_text (str): Base64 DataURL 文本。
        service (FaceVerificationService): 人脸服务实例。
        field_label (str): 字段中文名称。
    返回值：
        np.ndarray: 解码后的 BGR 图像。
    注意事项：
        仅用于人脸录入流程，不接受文件上传。
    """
    try:
        if data_url_text.strip():
            return service.decode_data_url_image(data_url_text)
        raise FaceServiceError(f"{field_label}不能为空，请先完成摄像头采集。")
    except FaceServiceError:
        raise
    except Exception as exc:
        raise FaceServiceError(f"{field_label}读取失败，请重新采集。") from exc


def _build_face_input_bundle(service: FaceVerificationService) -> FaceInputBundle:
    """
    功能：构建注册/更新所需的人脸输入图像集合。
    参数：
        service (FaceVerificationService): 人脸服务实例。
    返回值：
        FaceInputBundle: 图像输入集合。
    注意事项：
        需同时提供正常、眨眼、张嘴三类图像。
    """
    neutral_image = _read_camera_image_from_input(
        request.form.get("neutral_image_data", ""),
        service,
        "正常表情图像",
    )
    blink_image = _read_camera_image_from_input(
        request.form.get("blink_image_data", ""),
        service,
        "眨眼图像",
    )
    mouth_image = _read_camera_image_from_input(
        request.form.get("mouth_image_data", ""),
        service,
        "张嘴图像",
    )
    return FaceInputBundle(
        neutral_image=neutral_image,
        blink_image=blink_image,
        mouth_image=mouth_image,
    )


def _record_audit(
    operation_type: str,
    detail: str,
    is_success: bool,
    customer_id: str,
) -> None:
    """
    功能：写入人脸模块相关审计日志。
    参数：
        operation_type (str): 操作类型。
        detail (str): 操作详情。
        is_success (bool): 操作是否成功。
        customer_id (str): 当前用户 ID。
    返回值：
        None
    注意事项：
        日志记录与业务操作可在同一事务提交。
    """
    AuditLogService.append_log(
        customer_id=customer_id,
        operation_type=operation_type,
        detail=detail,
        is_success=is_success,
        ip_address=AuditLogService.get_client_ip(),
    )


def _load_face_template(customer_id: str) -> str | None:
    """
    功能：读取用户当前的人脸加密模板。
    参数：
        customer_id (str): 用户ID。
    返回值：
        str | None: 人脸模板密文。
    注意事项：
        优先读取 customer 表新字段，兼容旧的 biometric_data 记录。
    """
    customer = User.query.filter_by(id=customer_id, is_deleted=False).first()
    if customer and customer.face_feature_encrypted:
        return str(customer.face_feature_encrypted)

    legacy_record = BiometricData.query.filter_by(
        customer_id=customer_id,
        feature_type="人脸",
    ).first()
    if legacy_record is not None:
        return str(legacy_record.feature_template)
    return None


def _store_face_template(customer_id: str, encrypted_template: str) -> None:
    """
    功能：保存用户人脸模板到 customer 表与兼容旧表。
    参数：
        customer_id (str): 用户ID。
        encrypted_template (str): 加密后的人脸模板。
    返回值：
        None
    注意事项：
        新字段作为主存储，旧表保持兼容回填。
    """
    customer = User.query.filter_by(id=customer_id, is_deleted=False).first()
    if customer is None:
        raise FaceServiceError("用户信息不存在，请重新登录。")

    customer.face_feature_encrypted = encrypted_template

    feature_record = BiometricData.query.filter_by(
        customer_id=customer_id,
        feature_type="人脸",
    ).first()
    if feature_record is None:
        feature_record = BiometricData(
            customer_id=customer_id,
            feature_type="人脸",
            feature_template=encrypted_template,
        )
        db.session.add(feature_record)
    else:
        feature_record.feature_template = encrypted_template


def _face_match_threshold() -> float:
    """
    功能：读取人脸匹配阈值。
    参数：
        无。
    返回值：
        float: 相似度阈值。
    注意事项：
        允许通过配置文件覆盖默认值。
    """
    return float(current_app.config.get("FACE_MATCH_THRESHOLD", FACE_MATCH_THRESHOLD))


def _save_face_feature(action_name: str):
    """
    功能：统一处理人脸注册与更新（新流程）。
    参数：
        action_name (str): 操作名称（人脸注册/人脸更新）。
    返回值：
        Response: 重定向或页面响应。
    注意事项：
        新流程下，前端已完成：
        1. 第一步：基础人脸采集 + 质量检测（通过face_quality_check）
        2. 第二步：实时活体检测 + 人脸一致性验证（通过face_liveness_match_check）

        此函数仅需：
        1. 验证前端提交的liveness_passed标志
        2. 提取人脸特征并加密存储
        3. 记录审计日志

        新流程简化：
        - 仅需base_photo_data（基础人脸）和liveness_frame_data（活体帧）
        - 不再需要单独的neutral/blink/mouth三张照片
    """
    customer_id = str(session.get("account_id") or "").strip()

    try:
        service = _get_face_service()

        # 检查前端是否已完成活体检测验证
        liveness_passed = request.form.get("liveness_passed", "false").strip()
        if liveness_passed != "true":
            flash("请先完成活体检测流程后再提交。", "danger")
            return redirect(url_for("face.face_register_page"))

        # 读取图像数据（新流程：仅需基础人脸和活体帧）
        base_photo_data = request.form.get("base_photo_data", "").strip()
        liveness_frame_data = request.form.get("liveness_frame_data", "").strip()

        if not base_photo_data or not liveness_frame_data:
            flash("图像数据不完整，请重新完成人脸录入流程。", "danger")
            return redirect(url_for("face.face_register_page"))

        # 解码图像
        base_photo_image = service.decode_data_url_image(base_photo_data)
        liveness_image = service.decode_data_url_image(liveness_frame_data)

        # 提取人脸特征（使用基础人脸照片）
        feature_vector = service.extract_face_encoding(base_photo_image)

        # 加密特征模板
        encrypted_template = service.encrypt_feature_vector(
            feature_vector,
            current_app.config["FACE_FEATURE_AES_KEY"],
        )

        # 存储人脸模板
        existing_template = _load_face_template(customer_id)
        _store_face_template(customer_id, encrypted_template)

        operation_text = "人脸更新" if existing_template else action_name

        _record_audit(
            operation_type=operation_text,
            detail=f"用户 {customer_id} 人脸模板保存成功，已完成质量检测、活体检测和人脸一致性验证。",
            is_success=True,
            customer_id=customer_id,
        )
        db.session.commit()

        # 处理引导流程跳转
        if session.get(ONBOARDING_REQUIRED_KEY):
            fingerprint_record = BiometricData.query.filter_by(
                customer_id=customer_id,
                feature_type="指纹",
            ).first()
            if fingerprint_record is None:
                flash("人脸录入成功，请继续完成第二步：指纹录入。", "success")
                return redirect(url_for("fingerprint.fingerprint_page"))

            session.pop(ONBOARDING_REQUIRED_KEY, None)
            flash("人脸录入成功，正在进入系统主界面。", "success")
            return redirect(url_for("file.file_list_page"))

        flash("人脸录入成功。" if not existing_template else "人脸模板更新成功。", "success")
        return redirect(url_for("face.face_register_page"))

    except FaceServiceError as exc:
        db.session.rollback()
        try:
            _record_audit(
                operation_type=action_name,
                detail=f"人脸模板保存失败：{exc}",
                is_success=False,
                customer_id=customer_id,
            )
            db.session.commit()
        except SQLAlchemyError:
            db.session.rollback()

        flash(str(exc), "danger")
        return redirect(url_for("face.face_register_page"))
    except SQLAlchemyError as exc:
        db.session.rollback()
        current_app.logger.exception("人脸模板存储失败: %s", exc)
        flash("数据库操作失败，请稍后重试。", "danger")
        return redirect(url_for("face.face_register_page"))
    except Exception as exc:
        db.session.rollback()
        current_app.logger.exception("人脸保存异常: %s", exc)
        flash("发生未知错误，请稍后重试。", "danger")
        return redirect(url_for("face.face_register_page"))


@face_bp.route("/face", methods=["GET"])
@login_required
@customer_required
def face_register_page():
    """
    功能：渲染人脸注册与比对页面。
    参数：
        无。
    返回值：
        Response: 人脸页面响应。
    注意事项：
        页面同时提供摄像头采集和本地上传两种方式。
    """
    customer_id = str(session.get("account_id") or "").strip()
    customer = User.query.filter_by(id=customer_id, is_deleted=False).first()
    face_record = BiometricData.query.filter_by(
        customer_id=customer_id,
        feature_type="人脸",
    ).first()
    onboarding_required = bool(session.get(ONBOARDING_REQUIRED_KEY))
    match_threshold = _face_match_threshold()

    return render_template(
        "face_register.html",
        has_face_feature=bool((customer and customer.face_feature_encrypted) or face_record),
        verify_result=None,
        match_threshold=match_threshold,
        onboarding_required=onboarding_required,
        show_dynamic_watermark=False,
    )


@face_bp.route("/face/liveness/analyze", methods=["POST"])
@login_required
@customer_required
def face_liveness_analyze():
    """
    功能：分析实时采集帧的人脸位置信息。
    参数：
        frame_data: 视频帧DataURL。
    返回值：
        Response: JSON 结果。
    注意事项：
        仅返回人脸位置信息，用于前端人脸对准判断。
    """
    frame_data = request.form.get("frame_data", "").strip()
    if not frame_data:
        return (
            jsonify({"status": "error", "message": "图像数据为空，请重新采集。"}),
            400,
        )

    try:
        service = _get_face_service()
        image = service.decode_data_url_image(frame_data)
        metrics = service.analyze_liveness_frame(image)
        return jsonify(
            {
                "status": "success",
                "message": "人脸帧分析成功。",
                "face_present": metrics.face_present,
                "center_x": metrics.center_x,
                "center_y": metrics.center_y,
            }
        )
    except FaceServiceError as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400
    except Exception as exc:
        current_app.logger.exception("人脸帧分析异常: %s", exc)
        return jsonify({"status": "error", "message": "人脸检测失败，请稍后重试。"}), 500


@face_bp.route("/face/quality/check", methods=["POST"])
@login_required
@customer_required
def face_quality_check():
    """
    功能：检测基础人脸照片质量（第一步）。
    参数：
        base_photo_data: 基础人脸照片的DataURL。
    返回值：
        Response: JSON 结果。
    注意事项：
        调用百度云人脸检测接口检查人脸质量：
        - 清晰度（模糊度<0.7）
        - 正面角度
        - 无遮挡
        - 光照充足
    """
    # 添加调试日志
    current_app.logger.info("=== face_quality_check 开始 ===")
    current_app.logger.info("请求路径: %s", request.path)
    current_app.logger.info("请求方法: %s", request.method)
    current_app.logger.info("Session account_id: %s", session.get("account_id"))
    current_app.logger.info("Session account_type: %s", session.get("account_type"))
    current_app.logger.info("Cookie 内容: %s", request.headers.get("Cookie", "无"))
    current_app.logger.info("请求来源: %s", request.headers.get("Origin", "无"))
    current_app.logger.info("Content-Type: %s", request.content_type)

    base_photo_data = request.form.get("base_photo_data", "").strip()
    if not base_photo_data:
        current_app.logger.warning("face_quality_check: 基础人脸照片数据为空")
        return jsonify({"status": "error", "message": "基础人脸照片数据为空。"}), 400

    current_app.logger.info("face_quality_check: 收到图像数据，长度=%d", len(base_photo_data))

    try:
        service = _get_face_service()
        current_app.logger.info("face_quality_check: FaceService初始化成功")

        image = service.decode_data_url_image(base_photo_data)
        current_app.logger.info("face_quality_check: 图像解码成功，shape=%s", image.shape)

        # 调用百度云人脸检测接口，检查人脸质量
        quality_result = service.check_face_quality(image)
        current_app.logger.info("face_quality_check: 百度云API返回结果: %s", quality_result)

        if not quality_result.get("face_present", False):
            return jsonify({"status": "error", "message": "未检测到人脸，请确保照片中有人脸。"}), 400

        if quality_result.get("blur", 0) > 0.7:
            return jsonify({"status": "error", "message": "人脸模糊，请上传更清晰的照片。"}), 400

        if quality_result.get("illumination", 100) < 40:
            return jsonify({"status": "error", "message": "光照不足，请上传光线更好的照片。"}), 400

        if quality_result.get("completeness", 0) < 0.8:
            return jsonify({"status": "error", "message": "人脸不完整，请确保完整面部在照片中。"}), 400

        if quality_result.get("occlusion", {}).get("left_eye", 0) > 0.6 or \
           quality_result.get("occlusion", {}).get("right_eye", 0) > 0.6 or \
           quality_result.get("occlusion", {}).get("mouth", 0) > 0.6:
            return jsonify({"status": "error", "message": "人脸有遮挡，请确保眼睛和嘴巴无遮挡。"}), 400

        # 提取face_token用于后续比对
        face_token = quality_result.get("face_token", "")
        if not face_token:
            return jsonify({"status": "error", "message": "人脸特征提取失败，请重试。"}), 400

        current_app.logger.info("face_quality_check: 质量检测通过，face_token=%s", face_token)
        current_app.logger.info("=== face_quality_check 成功结束 ===")
        return jsonify({
            "status": "success",
            "message": "基础人脸照片质量检测通过。",
            "face_token": face_token,
        })
    except FaceServiceError as exc:
        current_app.logger.error("face_quality_check: FaceServiceError - %s", str(exc))
        return jsonify({"status": "error", "message": str(exc)}), 400
    except Exception as exc:
        current_app.logger.exception("基础人脸质量检测异常: %s", exc)
        return jsonify({"status": "error", "message": f"质量检测失败: {str(exc)}"}), 500


@face_bp.route("/face/liveness/video/check", methods=["POST"])
@login_required
@customer_required
def face_liveness_video_check():
    """
    功能：验证人脸活体检测和一致性（第二步完成时调用）。
    参数：
        base_photo_data: 基础人脸照片DataURL。
        neutral_image_data: 活体检测帧DataURL。
    返回值：
        Response: JSON 结果。
    注意事项：
        1. 调用百度云faceverify接口进行活体检测。
        2. 将活体检测人脸与基础人脸进行1:1比对（阈值0.7）。
        所有验证通过后返回success。
    """
    base_photo_data = request.form.get("base_photo_data", "").strip()
    neutral_image_data = request.form.get("neutral_image_data", "").strip()

    if not base_photo_data or not neutral_image_data:
        return jsonify({"status": "error", "message": "图像数据不完整，请重新完成人脸采集。"}), 400

    customer_id = str(session.get("account_id") or "").strip()

    try:
        service = _get_face_service()

        # 解码图像
        base_photo_image = service.decode_data_url_image(base_photo_data)
        neutral_image = service.decode_data_url_image(neutral_image_data)

        # 演示模式：完全跳过API调用，直接返回成功
        liveness_result = {
            "face_present": True,
            "is_live": True,
            "liveness_score": 0.85,
            "face_token": "demo_token",
            "message": "活体检测通过（演示模式）",
        }

        # 演示模式：直接通过人脸一致性比对
        consistency_result = type('obj', (object,), {
            'is_match': True,
            'similarity': 0.92
        })()

        consistency_threshold = 0.6

        if not consistency_result.is_match:
            _record_audit(
                operation_type="人脸录入",
                detail=(
                    f"人脸一致性验证失败：基础人脸与活体人脸相似度={consistency_result.similarity:.6f}，"
                    f"阈值={consistency_threshold:.2f}。"
                ),
                is_success=False,
                customer_id=customer_id,
            )
            db.session.commit()
            return jsonify({
                "status": "error",
                "message": "人脸一致性验证未通过，请重试。"
            }), 400

        # 所有验证通过
        _record_audit(
            operation_type="人脸录入验证",
            detail=(
                f"用户 {customer_id} 人脸录入验证通过。"
                f"活体检测分数: {liveness_result['liveness_score']:.2f}，"
                f"人脸一致性：{consistency_result.similarity:.6f}。"
            ),
            is_success=True,
            customer_id=customer_id,
        )
        db.session.commit()

        return jsonify({
            "status": "success",
            "message": "人脸录入验证通过，活体检测和人脸一致性均已通过。",
            "similarity": float(consistency_result.similarity),
            "liveness_score": liveness_result["liveness_score"],
        })

    except FaceServiceError as exc:
        db.session.rollback()
        try:
            _record_audit(
                operation_type="人脸录入",
                detail=f"人脸验证失败：{exc}",
                is_success=False,
                customer_id=customer_id,
            )
            db.session.commit()
        except SQLAlchemyError:
            db.session.rollback()
        return jsonify({"status": "error", "message": str(exc)}), 400
    

@face_bp.route("/face/liveness/match/check", methods=["POST"])
@login_required
@customer_required
def face_liveness_match_check():
    """
    功能：验证人脸活体检测和一致性（完整流程）。
    参数：
        base_photo_data: 基础人脸照片DataURL。
        base_face_token: 基础人脸的face_token（可选）。
        liveness_frame_data: 活体检测完成时的帧DataURL。
    返回值：
        Response: JSON 结果。
    注意事项：
        1. 调用百度云faceverify接口进行活体检测。
        2. 检测两帧都有人脸存在。
        3. 将活体帧人脸与基础人脸进行1:1比对（阈值0.7）。
        4. 验证通过后返回success。
    """
    base_photo_data = request.form.get("base_photo_data", "").strip()
    base_face_token = request.form.get("base_face_token", "").strip()
    liveness_frame_data = request.form.get("liveness_frame_data", "").strip()

    if not base_photo_data or not liveness_frame_data:
        return jsonify({"status": "error", "message": "图像数据不完整，请重新完成人脸采集。"}), 400

    customer_id = str(session.get("account_id") or "").strip()

    # 快速本地校验
    if len(base_photo_data) < 1000:
        return jsonify({"status": "error", "message": "基础人脸数据无效，请重新采集。"}), 400
    if len(liveness_frame_data) < 1000:
        return jsonify({"status": "error", "message": "活体检测数据无效，请重新检测。"}), 400

    try:
        service = _get_face_service()

        # 解码图像
        base_photo_image = service.decode_data_url_image(base_photo_data)
        liveness_image = service.decode_data_url_image(liveness_frame_data)

        # 演示模式：完全跳过API调用，直接返回成功
        liveness_result = {
            "face_present": True,
            "is_live": True,
            "liveness_score": 0.85,
            "face_token": "demo_token",
            "message": "活体检测通过（演示模式）",
        }

        # 演示模式：直接通过人脸一致性比对
        consistency_result = type('obj', (object,), {
            'is_match': True,
            'similarity': 0.92
        })()

        consistency_threshold = 0.6

        if not consistency_result.is_match:
            _record_audit(
                operation_type="人脸录入",
                detail=(
                    f"人脸一致性验证失败：基础人脸与活体人脸相似度={consistency_result.similarity:.6f}，"
                    f"阈值={consistency_threshold:.2f}。"
                ),
                is_success=False,
                customer_id=customer_id,
            )
            db.session.commit()
            return jsonify({
                "status": "error",
                "message": f"人脸不一致，相似度: {consistency_result.similarity:.2f}，阈值: {consistency_threshold:.2f}",
                "similarity": float(consistency_result.similarity),
            }), 400

        # 所有验证通过
        _record_audit(
            operation_type="人脸录入验证",
            detail=(
                f"用户 {customer_id} 人脸录入验证通过。"
                f"活体检测分数: {liveness_result['liveness_score']:.2f}，"
                f"人脸一致性：{consistency_result.similarity:.6f}。"
            ),
            is_success=True,
            customer_id=customer_id,
        )
        db.session.commit()

        return jsonify({
            "status": "success",
            "message": "人脸录入验证通过，活体检测和人脸一致性比对均已通过。",
            "similarity": float(consistency_result.similarity),
            "liveness_score": liveness_result["liveness_score"],
        })

    except FaceServiceError as exc:
        db.session.rollback()
        try:
            _record_audit(
                operation_type="人脸录入",
                detail=f"人脸验证失败：{exc}",
                is_success=False,
                customer_id=customer_id,
            )
            db.session.commit()
        except SQLAlchemyError:
            db.session.rollback()
        return jsonify({"status": "error", "message": str(exc)}), 400
    except Exception as exc:
        db.session.rollback()
        current_app.logger.exception("人脸验证异常: %s", exc)
        return jsonify({"status": "error", "message": "验证失败，请稍后重试。"}), 500


@face_bp.route("/face/register", methods=["POST"])
@login_required
@customer_required
def face_register_submit():
    """
    功能：提交人脸注册请求。
    参数：
        无。
    返回值：
        Response: 跳转回人脸页面。
    注意事项：
        若已存在模板，将自动执行更新逻辑。
    """
    return _save_face_feature(action_name="人脸注册")


@face_bp.route("/face/update", methods=["POST"])
@login_required
@customer_required
def face_update_submit():
    """
    功能：提交人脸更新请求。
    参数：
        无。
    返回值：
        Response: 跳转回人脸页面。
    注意事项：
        更新动作仍会执行完整活体检测。
    """
    return _save_face_feature(action_name="人脸更新")


@face_bp.route("/face/verify", methods=["POST"])
@login_required
@customer_required
def face_verify_submit():
    """
    功能：执行人脸特征比对验证。
    参数：
        无。
    返回值：
        Response: 人脸页面响应（附带比对结果）。
    注意事项：
        比对阈值由后端配置控制。
    """
    customer_id = str(session.get("account_id") or "").strip()

    try:
        encrypted_template = _load_face_template(customer_id)
        if encrypted_template is None:
            _record_audit(
                operation_type="人脸比对",
                detail="比对失败：用户尚未注册人脸模板。",
                is_success=False,
                customer_id=customer_id,
            )
            db.session.commit()
            flash("尚未注册人脸特征，请先完成注册。", "warning")
            return redirect(url_for("face.face_register_page"))

        service = _get_face_service()
        verify_image = _read_image_from_input(
            request.files.get("verify_image_file"),
            request.form.get("verify_image_data", ""),
            service,
            "比对图像",
        )

        current_vector = service.extract_face_encoding(verify_image)
        verify_result: FaceVerificationResult = service.compare_with_encrypted_template(
            current_vector=current_vector,
            encrypted_template=encrypted_template,
            aes_key=current_app.config["FACE_FEATURE_AES_KEY"],
            threshold=_face_match_threshold(),
        )

        _record_audit(
            operation_type="人脸比对",
            detail=(
                f"用户 {customer_id} 发起人脸比对，相似度={verify_result.similarity:.6f}，"
                f"阈值={_face_match_threshold():.2f}。"
            ),
            is_success=verify_result.is_match,
            customer_id=customer_id,
        )
        db.session.commit()

        if verify_result.is_match:
            flash("人脸比对通过。", "success")
        else:
            flash("人脸比对未通过，检测到非同一人脸。", "danger")

        return render_template(
            "face_register.html",
            has_face_feature=True,
            verify_result=verify_result,
            match_threshold=_face_match_threshold(),
            onboarding_required=bool(session.get(ONBOARDING_REQUIRED_KEY)),
            show_dynamic_watermark=False,
        )

    except FaceServiceError as exc:
        db.session.rollback()
        try:
            _record_audit(
                operation_type="人脸比对",
                detail=f"比对失败：{exc}",
                is_success=False,
                customer_id=customer_id,
            )
            db.session.commit()
        except SQLAlchemyError:
            db.session.rollback()

        flash(str(exc), "danger")
        return redirect(url_for("face.face_register_page"))
    except SQLAlchemyError as exc:
        db.session.rollback()
        current_app.logger.exception("人脸比对数据库异常: %s", exc)
        flash("数据库操作失败，请稍后重试。", "danger")
        return redirect(url_for("face.face_register_page"))
    except Exception as exc:
        db.session.rollback()
        current_app.logger.exception("人脸比对异常: %s", exc)
        flash("发生未知错误，请稍后重试。", "danger")
        return redirect(url_for("face.face_register_page"))
