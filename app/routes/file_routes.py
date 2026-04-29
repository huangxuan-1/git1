"""
app/routes/file_routes.py
功能：实现涉密文件上传下载、版本控制、回收站与模块9文件加解密能力。
注意事项：
1. 所有上传/更新文件均自动 AES-256-CBC 加密后存入 secret_file.content（LONGBLOB）。
2. 每条文件记录使用独立随机密钥，密钥文件保存为 keys/<file_id>.key。
3. 下载时自动解密；同时提供手动加密与手动解密操作。
"""

from __future__ import annotations

import io
import mimetypes
from hmac import compare_digest
from datetime import datetime
from urllib.parse import quote
from uuid import uuid4

from flask import Blueprint, current_app, flash, jsonify, redirect, render_template, request, send_file, session, url_for
from sqlalchemy import and_
from sqlalchemy.exc import SQLAlchemyError
from werkzeug.datastructures import FileStorage
from werkzeug.utils import secure_filename

from app.models import SecretFile, User
from app.routes.auth_routes import admin_required, login_required
from app.services.abac_service import ABACService
from app.services.audit_log_service import AuditLogService
from app.services.file_crypto_service import FileCryptoService, FileCryptoServiceError
from extensions import db
from utils.aes_utils import AESCryptoError, AESUtil

file_bp = Blueprint("file", __name__)

ALLOWED_SECRET_LEVELS = ABACService.ALLOWED_FILE_LEVELS
DEFAULT_MAX_UPLOAD_SIZE = 100 * 1024 * 1024


def _get_client_ip() -> str:
    """
    功能：获取客户端 IP（复用 AuditLogService 逻辑）。
    参数：
        无。
    返回值：
        str: 客户端 IP。
    注意事项：
        优先使用 X-Forwarded-For 头首个值，本地回环地址返回真实主机 IP。
    """
    return AuditLogService.get_client_ip()


def _current_actor() -> tuple[str | int, str, str, str]:
    """
    功能：读取当前登录主体信息。
    参数：
        无。
    返回值：
        tuple[str | int, str, str, str]: (主体ID, account_type, 主体中文类型, 用户名)
    注意事项：
        依赖登录模块写入的会话键。
    """
    account_type = session.get("account_type", "customer")
    if account_type == "administrator":
        account_id = int(session.get("account_id") or 1)
    else:
        account_id = str(session.get("account_id") or "").strip()
    actor_type_label = "管理员" if account_type == "administrator" else "用户"
    username = session.get("username", "unknown")
    return account_id, account_type, actor_type_label, username


def _is_admin() -> bool:
    """
    功能：判断当前账号是否管理员。
    参数：
        无。
    返回值：
        bool: 管理员返回 True。
    注意事项：
        account_type 来源于登录会话。
    """
    return session.get("account_type") == "administrator"


def _can_access_level(secret_level: str) -> bool:
    """
    功能：判断当前主体是否有权限访问指定密级。
    参数：
        secret_level (str): 文件密级。
    返回值：
        bool: 有权限返回 True。
    注意事项：
        管理员默认可访问全部密级。
    """
    return ABACService.can_access_file_level(
        account_type=session.get("account_type", "customer"),
        security_level=session.get("security_level", "初级"),
        file_level=secret_level,
    )


def _can_contain_level(parent_level: str, child_level: str) -> bool:
    """
    功能：判断父级目录密级是否可容纳子级密级。
    参数：
        parent_level (str): 父级密级。
        child_level (str): 子级密级。
    返回值：
        bool: 可容纳返回 True。
    注意事项：
        父级密级必须高于或等于子级密级。
    """
    return ABACService.can_contain_level(parent_level, child_level)


def _record_file_audit(
    operation_type: str,
    detail: str,
    is_success: bool,
    customer_id: str | None = None,
    administrator_id: int | None = None,
    file_id: int | None = None,
) -> None:
    """
    功能：写入文件模块审计日志。
    参数：
        operation_type (str): 操作类型。
        detail (str): 操作详情。
        is_success (bool): 是否成功。
        customer_id (str | None): 用户ID。
        administrator_id (int | None): 管理员ID。
    返回值：
        None
    注意事项：
        事务提交由调用方控制。
    """
    AuditLogService.append_log(
        customer_id=customer_id,
        administrator_id=administrator_id,
        file_id=file_id,
        ip_address=_get_client_ip(),
        operation_type=operation_type,
        detail=detail,
        is_success=is_success,
    )


def _wants_json_response() -> bool:
    """
    功能：判断当前请求是否期望 JSON 响应。
    参数：
        无。
    返回值：
        bool: 期望 JSON 返回 True。
    注意事项：
        兼容 XMLHttpRequest 与 Accept 头协商。
    """
    accept_header = (request.headers.get("Accept", "") or "").lower()
    requested_with = request.headers.get("X-Requested-With", "")
    return "application/json" in accept_header or requested_with == "XMLHttpRequest"


def _respond_file_action(
    message: str,
    category: str,
    is_success: bool,
    redirect_endpoint: str,
    status_code: int,
    endpoint_values: dict | None = None,
):
    """
    功能：按请求类型返回 JSON 或页面跳转结果。
    参数：
        message (str): 响应提示。
        category (str): flash 类别。
        is_success (bool): 是否成功。
        redirect_endpoint (str): 页面模式下跳转端点。
        status_code (int): JSON 模式 HTTP 状态码。
    返回值：
        Response: JSON 或重定向响应。
    注意事项：
        页面模式沿用 flash + redirect，不改变现有流程。
    """
    if _wants_json_response():
        return (
            jsonify(
                {
                    "status": "success" if is_success else "error",
                    "message": message,
                }
            ),
            status_code,
        )

    flash(message, category)
    return redirect(url_for(redirect_endpoint, **(endpoint_values or {})))


def _is_csrf_token_valid() -> bool:
    """
    功能：校验文件上传类请求的 CSRF 令牌。
    参数：
        无。
    返回值：
        bool: 令牌通过返回 True。
    注意事项：
        支持表单字段 csrf_token 与请求头 X-CSRF-Token。
    """
    session_token = str(session.get("csrf_token", "") or "")
    request_token = (request.form.get("csrf_token", "") or "").strip()
    if not request_token:
        request_token = (request.headers.get("X-CSRF-Token", "") or "").strip()

    if not session_token or not request_token:
        return False

    return compare_digest(session_token, request_token)


def _max_upload_file_size() -> int:
    """
    功能：读取上传文件大小上限。
    参数：
        无。
    返回值：
        int: 允许的最大单文件字节数。
    注意事项：
        未配置时默认 100MB。
    """
    return int(current_app.config.get("MAX_UPLOAD_FILE_SIZE", DEFAULT_MAX_UPLOAD_SIZE))


def _format_file_size(size_bytes: int) -> str:
    """
    功能：格式化文件大小文本。
    参数：
        size_bytes (int): 字节数。
    返回值：
        str: 人类可读大小。
    注意事项：
        仅用于界面显示。
    """
    if size_bytes < 1024:
        return f"{size_bytes} B"
    if size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    if size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f} MB"
    return f"{size_bytes / (1024 * 1024 * 1024):.1f} GB"


def _build_explorer_items(files: list[SecretFile]) -> list[dict[str, str]]:
    """
    功能：构造基础壳层资源管理器展示数据。
    参数：
        files (list[SecretFile]): 文件记录。
    返回值：
        list[dict[str, str]]: 展示项列表。
    注意事项：
        仅输出元信息，不包含密文与密钥数据。
    """
    items: list[dict[str, str]] = []
    for file_record in files:
        items.append(
            {
                "name": file_record.name,
                "type": "文件夹" if bool(file_record.is_folder) else "文件",
                "size": "--" if bool(file_record.is_folder) else _format_file_size(int(file_record.file_size or 0)),
                "uploaded": file_record.uploaded_at.strftime("%Y-%m-%d %H:%M"),
                "level": file_record.level,
            }
        )
    return items


def _can_manage_file(file_record: SecretFile) -> bool:
    """
    功能：判断当前主体是否可管理目标文件。
    参数：
        file_record (SecretFile): 文件记录。
    返回值：
        bool: 可管理返回 True。
    注意事项：
        管理员可管理全部文件，用户仅可管理自己上传的文件。
    """
    account_id, account_type, actor_type_label, _ = _current_actor()
    if account_type == "administrator":
        return True

    return (
        str(file_record.uploader_id or "") == str(account_id)
        and str(file_record.uploader_type) == actor_type_label
    )


def _safe_parent_id(raw_value: str | None, default: int = 0) -> int:
    """
    功能：安全解析 parent_id 参数。
    参数：
        raw_value (str | None): 原始 parent_id 文本。
        default (int): 解析失败时默认值。
    返回值：
        int: 解析后的目录 ID（最小为 0）。
    注意事项：
        非法值统一回退到根目录 0。
    """
    if raw_value is None:
        return max(0, int(default))

    try:
        value = int(raw_value)
    except (TypeError, ValueError):
        return max(0, int(default))

    return value if value > 0 else 0


def _normalize_folder_name(raw_name: str) -> str:
    """
    功能：规范化文件夹名称并剔除危险字符。
    参数：
        raw_name (str): 原始输入。
    返回值：
        str: 规范化后的名称。
    注意事项：
        仅做基础安全收敛，保留中文与空格。
    """
    normalized = str(raw_name or "").strip()
    normalized = normalized.replace("/", " ").replace("\\", " ")
    normalized = " ".join(normalized.split())
    if normalized in {".", ".."}:
        return ""
    return normalized[:255]


def _get_active_folder_or_none(folder_id: int) -> SecretFile | None:
    """
    功能：查询当前有效文件夹记录（最新版本、未删除）。
    参数：
        folder_id (int): 文件夹记录 ID。
    返回值：
        SecretFile | None: 文件夹记录或 None。
    注意事项：
        仅返回 is_folder=True 的记录。
    """
    if folder_id <= 0:
        return None

    return SecretFile.query.filter_by(
        id=int(folder_id),
        is_latest=True,
        is_deleted=False,
        is_folder=True,
    ).first()


def _build_breadcrumbs(current_parent_id: int) -> list[dict[str, int | str]]:
    """
    功能：构造目录面包屑路径。
    参数：
        current_parent_id (int): 当前目录 ID。
    返回值：
        list[dict[str, int | str]]: 从根目录到当前目录的节点列表。
    注意事项：
        遇到脏数据环路时会自动终止，避免死循环。
    """
    breadcrumbs: list[dict[str, int | str]] = [{"id": 0, "name": "根目录"}]
    if current_parent_id <= 0:
        return breadcrumbs

    stack: list[dict[str, int | str]] = []
    visited: set[int] = set()
    cursor_id = int(current_parent_id)

    while cursor_id > 0 and cursor_id not in visited:
        visited.add(cursor_id)
        folder = _get_active_folder_or_none(cursor_id)
        if folder is None:
            break

        stack.append({"id": int(folder.id), "name": folder.name})
        cursor_id = int(folder.parent_id or 0)

    stack.reverse()
    breadcrumbs.extend(stack)
    return breadcrumbs


def _build_parent_path_text(parent_id: int) -> str:
    """
    功能：将父目录 ID 转换为路径文本。
    参数：
        parent_id (int): 父目录 ID。
    返回值：
        str: 路径文本（以根目录起始）。
    注意事项：
        仅用于回收站"原位置"展示与记录。
    """
    breadcrumbs = _build_breadcrumbs(parent_id)
    if not breadcrumbs:
        return "根目录"
    return "/".join([str(crumb["name"]) for crumb in breadcrumbs]) or "根目录"


def _resolve_item_icon_type(item: SecretFile) -> str:
    """
    功能：根据文件类型映射 WPS 风格图标类型。
    参数：
        item (SecretFile): 目录项记录。
    返回值：
        str: 图标类型编码。
    注意事项：
        文件夹优先返回 folder。
    """
    if bool(item.is_folder):
        return "folder"

    file_name = str(item.name or "").lower()
    if file_name.endswith((".doc", ".docx")):
        return "word"
    if file_name.endswith((".xls", ".xlsx")):
        return "excel"
    if file_name.endswith((".ppt", ".pptx")):
        return "ppt"
    if file_name.endswith(".pdf"):
        return "pdf"
    return "file"


def _folder_tree_accessible_for_current_user(root_folder_id: int) -> bool:
    """
    功能：判断当前用户是否可删除整个文件夹树。
    参数：
        root_folder_id (int): 根文件夹 ID。
    返回值：
        bool: 可访问全部子项返回 True。
    注意事项：
        管理员默认返回 True。
    """
    if _is_admin():
        return True

    root_folder = _get_active_folder_or_none(root_folder_id)
    if root_folder is None or not _can_access_level(root_folder.level):
        return False

    pending: list[int] = [int(root_folder_id)]
    visited: set[int] = set()

    while pending:
        current_folder_id = pending.pop()
        if current_folder_id in visited:
            continue
        visited.add(current_folder_id)

        children = SecretFile.query.filter_by(
            parent_id=current_folder_id,
            is_latest=True,
            is_deleted=False,
        ).all()

        for child in children:
            if not _can_access_level(child.level):
                return False
            if bool(child.is_folder):
                pending.append(int(child.id))

    return True


def _can_delete_item_by_abac(item: SecretFile) -> bool:
    """
    功能：按照 ABAC 规则判断目录项是否可删除。
    参数：
        item (SecretFile): 目录项记录。
    返回值：
        bool: 可删除返回 True。
    注意事项：
        文件夹删除会校验其子树全部密级权限。
    """
    if _is_admin():
        return True

    if not _can_access_level(item.level):
        return False

    if bool(item.is_folder):
        return _folder_tree_accessible_for_current_user(int(item.id))

    return True


def _collect_folder_tree_group_ids(root_folder_id: int) -> set[str]:
    """
    功能：收集文件夹树中所有需要级联软删除的 file_group_id。
    参数：
        root_folder_id (int): 根文件夹 ID。
    返回值：
        set[str]: 文件分组 ID 集合。
    注意事项：
        仅采集未删除且最新版本的可见目录树节点。
    """
    group_ids: set[str] = set()
    pending: list[int] = [int(root_folder_id)]
    visited: set[int] = set()

    while pending:
        current_folder_id = pending.pop()
        if current_folder_id in visited:
            continue
        visited.add(current_folder_id)

        folder_item = _get_active_folder_or_none(current_folder_id)
        if folder_item is None:
            continue

        group_ids.add(str(folder_item.file_group_id))

        children = SecretFile.query.filter_by(
            parent_id=current_folder_id,
            is_latest=True,
            is_deleted=False,
        ).all()
        for child in children:
            group_ids.add(str(child.file_group_id))
            if bool(child.is_folder):
                pending.append(int(child.id))

    return group_ids


def _collect_deleted_folder_tree_group_ids(root_folder_id: int) -> set[str]:
    """
    功能：收集回收站中文件夹树的分组 ID。
    参数：
        root_folder_id (int): 根文件夹记录 ID。
    返回值：
        set[str]: 回收站内文件分组 ID 集合。
    注意事项：
        仅采集 is_latest=True 且 is_deleted=True 的目录树节点。
    """
    root_folder = SecretFile.query.filter_by(
        id=int(root_folder_id),
        is_latest=True,
        is_deleted=True,
        is_folder=True,
    ).first()
    if root_folder is None:
        return set()

    group_ids: set[str] = {str(root_folder.file_group_id)}
    pending: list[int] = [int(root_folder_id)]
    visited: set[int] = set()

    while pending:
        current_folder_id = pending.pop()
        if current_folder_id in visited:
            continue
        visited.add(current_folder_id)

        children = SecretFile.query.filter_by(
            parent_id=current_folder_id,
            is_latest=True,
            is_deleted=True,
        ).all()
        for child in children:
            group_ids.add(str(child.file_group_id))
            if bool(child.is_folder):
                pending.append(int(child.id))

    return group_ids


def _soft_delete_file_groups(
    group_path_map: dict[str, str],
    actor_id: str | int,
    actor_type_label: str,
) -> int:
    """
    功能：按分组批量软删除目录项并记录原位置。
    参数：
        group_path_map (dict[str, str]): file_group_id 到原位置路径的映射。
        actor_id (str | int): 执行人 ID。
        actor_type_label (str): 执行人类型（用户/管理员）。
    返回值：
        int: 影响记录总数。
    注意事项：
        同一分组的全部历史版本会同步标记为已删除。
    """
    deleted_at = datetime.now()
    affected_rows = 0

    for file_group_id, original_path in group_path_map.items():
        affected_rows += (
            SecretFile.query.filter_by(file_group_id=file_group_id).update(
                {
                    SecretFile.is_deleted: True,
                    SecretFile.deleted_at: deleted_at,
                    SecretFile.deleted_by_id: actor_id,
                    SecretFile.deleted_by_type: actor_type_label,
                    SecretFile.original_path: (original_path or "根目录")[:255],
                },
                synchronize_session=False,
            )
        )

    return affected_rows


def _restore_file_groups(group_ids: set[str]) -> tuple[int, bool]:
    """
    功能：按分组从回收站恢复文件或文件夹。
    参数：
        group_ids (set[str]): 需要恢复的文件分组集合。
    返回值：
        tuple[int, bool]: (影响记录数, 是否发生父目录回退到根目录)。
    注意事项：
        当原父目录已不存在且不在本次恢复集合内时，会回退到根目录。
    """
    if not group_ids:
        return 0, False

    latest_items = (
        SecretFile.query.filter(
            SecretFile.file_group_id.in_(group_ids),
            SecretFile.is_latest.is_(True),
            SecretFile.is_deleted.is_(True),
        )
        .order_by(SecretFile.id.asc())
        .all()
    )
    if not latest_items:
        return 0, False

    restoring_folder_ids = {int(item.id) for item in latest_items if bool(item.is_folder)}
    affected_rows = 0
    fallback_to_root = False

    for latest_item in latest_items:
        target_parent_id = int(latest_item.parent_id or 0)
        if target_parent_id > 0 and target_parent_id not in restoring_folder_ids:
            parent_folder = _get_active_folder_or_none(target_parent_id)
            if parent_folder is None or not _can_contain_level(parent_folder.level, latest_item.level):
                target_parent_id = 0
                fallback_to_root = True

        affected_rows += (
            SecretFile.query.filter_by(file_group_id=str(latest_item.file_group_id)).update(
                {
                    SecretFile.is_deleted: False,
                    SecretFile.deleted_at: None,
                    SecretFile.deleted_by_id: None,
                    SecretFile.deleted_by_type: None,
                    SecretFile.parent_id: target_parent_id,
                    SecretFile.original_path: None,
                },
                synchronize_session=False,
            )
        )

    return affected_rows, fallback_to_root


def _purge_file_groups(group_ids: set[str]) -> tuple[int, list[int]]:
    """
    功能：按分组彻底删除文件记录并返回需清理的密钥记录 ID。
    参数：
        group_ids (set[str]): 待删除分组集合。
    返回值：
        tuple[int, list[int]]: (删除记录数, 需清理密钥的 record_id 列表)。
    注意事项：
        文件夹记录不会产生密钥文件。
    """
    if not group_ids:
        return 0, []

    recycle_versions = SecretFile.query.filter(SecretFile.file_group_id.in_(group_ids)).all()
    if not recycle_versions:
        return 0, []

    key_record_ids = [int(item.id) for item in recycle_versions if not bool(item.is_folder)]
    deleted_rows = SecretFile.query.filter(SecretFile.file_group_id.in_(group_ids)).delete(
        synchronize_session=False
    )
    return int(deleted_rows or 0), key_record_ids


def _build_directory_items_payload(items: list[SecretFile]) -> list[dict[str, object]]:
    """
    功能：将目录项记录转换为前端资源管理器展示数据。
    参数：
        items (list[SecretFile]): 当前目录项记录。
    返回值：
        list[dict[str, object]]: 目录项展示数据。
    注意事项：
        数据仅包含界面所需元信息，不包含密文内容。
    """
    payload: list[dict[str, object]] = []
    for item in items:
        is_folder = bool(item.is_folder)
        can_download = (not is_folder) and _can_access_level(item.level)
        can_delete = _can_delete_item_by_abac(item)
        payload.append(
            {
                "id": int(item.id),
                "file_group_id": item.file_group_id,
                "name": item.name,
                "level": item.level,
                "status": item.status or "未加密",
                "is_folder": is_folder,
                "icon_type": _resolve_item_icon_type(item),
                "size_text": "--" if is_folder else _format_file_size(int(item.file_size or 0)),
                "uploaded_text": item.uploaded_at.strftime("%Y-%m-%d %H:%M:%S"),
                "can_download": can_download,
                "can_delete": can_delete,
            }
        )

    return payload


def _get_latest_file_or_none(file_group_id: str) -> SecretFile | None:
    """
    功能：获取文件分组的最新版本。
    参数：
        file_group_id (str): 文件分组ID。
    返回值：
        SecretFile | None: 最新版本记录。
    注意事项：
        最新版本依据 is_latest 标记。
    """
    return (
        SecretFile.query.filter_by(file_group_id=file_group_id, is_latest=True)
        .order_by(SecretFile.id.desc())
        .first()
    )


def _parse_upload_datetime_filter(raw_value: str, *, end_of_day: bool = False) -> datetime | None:
    """
    功能：解析文件上传时间筛选参数。
    参数：
        raw_value (str): 原始日期字符串。
        end_of_day (bool): 是否转换为当天结束时间。
    返回值：
        datetime | None: 解析后的时间对象。
    注意事项：
        非法日期会被忽略，并记录调试日志。
    """
    value = (raw_value or "").strip()
    if not value:
        return None

    try:
        parsed = datetime.strptime(value, "%Y-%m-%d")
    except ValueError:
        current_app.logger.warning("文件列表上传时间筛选参数格式非法：%s", raw_value)
        return None

    if end_of_day:
        return parsed.replace(hour=23, minute=59, second=59, microsecond=999999)
    return parsed


def _log_query_sql(query, label: str) -> None:
    """
    功能：输出查询语句与参数，便于调试筛选条件。
    参数：
        query: SQLAlchemy 查询对象。
        label (str): 日志标签。
    返回值：
        None。
    注意事项：
        仅用于调试日志，不影响查询执行。
    """
    try:
        bind = db.session.get_bind()
        dialect = bind.dialect if bind is not None else db.engine.dialect
        compiled = query.statement.compile(
            dialect=dialect,
            compile_kwargs={"literal_binds": False},
        )
        current_app.logger.debug("%s SQL: %s", label, compiled)
        current_app.logger.debug("%s 参数: %s", label, compiled.params)
    except Exception as exc:  # pragma: no cover - 仅用于调试日志兜底
        current_app.logger.debug("%s SQL 日志输出失败：%s", label, exc)


def _apply_search_filters(
    base_query,
    q: str,
    level: str,
    upload_start: str,
    upload_end: str,
    status: str = "",
):
    """
    功能：为文件查询追加搜索条件。
    参数：
        base_query: 原始查询对象。
        q (str): 文件名关键字。
        level (str): 密级过滤。
        upload_start (str): 上传时间起始日期。
        upload_end (str): 上传时间结束日期。
        status (str): 加密状态过滤。
    返回值：
        Query: 过滤后的查询对象。
    注意事项：
        支持文件名关键字、密级、加密状态与上传时间范围过滤。
    """
    query = base_query

    keyword = q.strip()
    if keyword:
        query = query.filter(SecretFile.name.ilike(f"%{keyword}%"))

    if level in ALLOWED_SECRET_LEVELS:
        query = query.filter(SecretFile.level == level)

    if status in ("已加密", "未加密"):
        query = query.filter(SecretFile.status == status)

    parsed_start = _parse_upload_datetime_filter(upload_start)
    parsed_end = _parse_upload_datetime_filter(upload_end, end_of_day=True)

    if parsed_start is not None or parsed_end is not None:
        _log_query_sql(query, "文件列表上传时间筛选前")

    if parsed_start is not None:
        query = query.filter(SecretFile.uploaded_at >= parsed_start)

    if parsed_end is not None:
        query = query.filter(SecretFile.uploaded_at <= parsed_end)

    if parsed_start is not None or parsed_end is not None:
        _log_query_sql(query, "文件列表上传时间筛选后")

    return query


def _decrypt_file_bytes(file_record: SecretFile) -> bytes:
    """
    功能：解密文件记录中的密文内容。
    参数：
        file_record (SecretFile): 文件记录。
    返回值：
        bytes: 解密后的明文。
    注意事项：
        若未找到独立密钥，会尝试兼容旧版本全局密钥数据。
    """
    key_dir = current_app.config["FILE_KEY_DIR"]
    chunk_size = int(current_app.config["FILE_CRYPTO_CHUNK_SIZE"])
    encrypted_blob = bytes(file_record.content or b"")

    try:
        return FileCryptoService.decrypt_for_record(
            record_id=int(file_record.id),
            encrypted_blob=encrypted_blob,
            key_dir=key_dir,
            chunk_size=chunk_size,
        )
    except FileCryptoServiceError:
        # 兼容模块8旧格式：content 为 UTF-8 Base64 字符串，使用全局 AES_KEY。
        try:
            encrypted_text = encrypted_blob.decode("utf-8")
            return AESUtil.decrypt_bytes(encrypted_text, current_app.config["AES_KEY"])
        except (UnicodeDecodeError, AESCryptoError) as exc:
            raise FileCryptoServiceError("文件解密失败，密钥不存在或密文损坏。") from exc


def _encrypt_and_bind_record(record_id: int, plain_bytes: bytes) -> tuple[bytes, str]:
    """
    功能：为指定记录生成独立密钥并加密内容。
    参数：
        record_id (int): 文件记录ID。
        plain_bytes (bytes): 明文。
    返回值：
        tuple[bytes, str]: (密文字节, 密钥路径)。
    注意事项：
        加密采用分块处理，适配大文件。
    """
    key_dir = current_app.config["FILE_KEY_DIR"]
    chunk_size = int(current_app.config["FILE_CRYPTO_CHUNK_SIZE"])
    return FileCryptoService.encrypt_for_record(
        record_id=record_id,
        plain_bytes=plain_bytes,
        key_dir=key_dir,
        chunk_size=chunk_size,
    )


def _next_version(
    latest_file: SecretFile,
    requested_major: int | None,
    is_admin: bool,
) -> tuple[int, int, str]:
    """
    功能：计算下一版本号。
    参数：
        latest_file (SecretFile): 当前最新版本。
        requested_major (int | None): 请求的主版本号。
        is_admin (bool): 是否管理员。
    返回值：
        tuple[int, int, str]: (major, minor, version_text)
    注意事项：
        1. 默认次版本 +1。
        2. 仅管理员可改主版本且改主版本后次版本重置为 1。
    """
    current_major = int(latest_file.major_version)
    current_minor = int(latest_file.minor_version)

    if requested_major is not None and requested_major != current_major:
        if not is_admin:
            raise ValueError("仅管理员可修改主版本号。")
        if requested_major <= 0:
            raise ValueError("主版本号必须为正整数。")

        major_version = requested_major
        minor_version = 1
    else:
        major_version = current_major
        minor_version = current_minor + 1

    return major_version, minor_version, f"{major_version}.{minor_version}"


def _render_download_response(
    plain_bytes: bytes,
    file_name: str,
    mime_type: str,
):
    """
    功能：构造文件下载响应。
    参数：
        plain_bytes (bytes): 明文字节。
        file_name (str): 下载文件名。
        mime_type (str): MIME 类型。
    返回值：
        Response: 下载响应。
    注意事项：
        通过 send_file 返回附件下载。
    """
    safe_name = (file_name or "download.bin").replace("\r", "").replace("\n", "")
    encoded_name = quote(safe_name)

    response = send_file(
        io.BytesIO(plain_bytes),
        as_attachment=True,
        download_name=safe_name,
        mimetype=mime_type or "application/octet-stream",
        conditional=False,
    )
    response.headers["Content-Disposition"] = (
        f"attachment; filename=\"{safe_name}\"; filename*=UTF-8''{encoded_name}"
    )
    response.headers["Content-Type"] = mime_type or "application/octet-stream"
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@file_bp.route("/files", methods=["GET"])
@login_required
def file_list_page():
    """
    功能：Windows 风格文件资源管理器主页。
    参数：
        无。
    返回值：
        Response: 文件列表页面。
    注意事项：
        支持目录层级、面包屑导航、右键菜单和列表/图标视图切换。
    """
    q = request.args.get("q", "")
    level = request.args.get("level", "")
    status = request.args.get("status", "")
    upload_start = request.args.get("upload_start", "")
    upload_end = request.args.get("upload_end", "")
    parent_id = _safe_parent_id(request.args.get("parent_id"), default=0)
    is_admin = _is_admin()

    current_folder = _get_active_folder_or_none(parent_id)
    if parent_id > 0 and current_folder is None:
        flash("目标目录不存在或已删除。", "warning")
        return redirect(url_for("file.file_list_page", parent_id=0))

    if current_folder is not None and not _can_access_level(current_folder.level):
        flash("权限不足：不可访问该目录。", "danger")
        return redirect(url_for("file.file_list_page", parent_id=0))

    allowed_levels = ABACService.allowed_file_levels(
        account_type=session.get("account_type", "customer"),
        security_level=session.get("security_level", "初级"),
    )

    active_query = SecretFile.query.filter_by(
        is_latest=True,
        is_deleted=False,
        parent_id=parent_id,
    )
    if allowed_levels:
        active_query = active_query.filter(SecretFile.level.in_(allowed_levels))
    else:
        active_query = active_query.filter(SecretFile.id == -1)

    active_query = _apply_search_filters(
        active_query,
        q,
        level,
        upload_start,
        upload_end,
        status,
    )
    visible_items = active_query.order_by(
        SecretFile.is_folder.desc(),
        SecretFile.uploaded_at.desc(),
        SecretFile.id.desc(),
    ).all()

    # 搜索操作审计日志
    has_active_filters = bool((q or "").strip() or level.strip() or status.strip() or upload_start.strip() or upload_end.strip())
    if has_active_filters:
        search_detail_parts = []
        if (q or "").strip():
            search_detail_parts.append(f"关键词: {q.strip()}")
        if level.strip():
            search_detail_parts.append(f"密级: {level.strip()}")
        if status.strip():
            search_detail_parts.append(f"状态: {status.strip()}")
        if upload_start.strip():
            search_detail_parts.append(f"起始时间: {upload_start.strip()}")
        if upload_end.strip():
            search_detail_parts.append(f"结束时间: {upload_end.strip()}")

        search_detail = "; ".join(search_detail_parts) if search_detail_parts else "空搜索"
        is_search_success = len(visible_items) > 0
        search_result_note = f"找到 {len(visible_items)} 条记录" if is_search_success else "未找到匹配记录"

        actor_id, account_type, actor_type_label, _username = _current_actor()
        _record_file_audit(
            operation_type="文件搜索",
            detail=f"{search_detail} | {search_result_note}",
            is_success=is_search_success,
            customer_id=str(actor_id) if account_type == "customer" else None,
            administrator_id=int(actor_id) if account_type == "administrator" else None,
        )
        db.session.commit()

    breadcrumbs = _build_breadcrumbs(parent_id)
    current_parent_id = int(current_folder.parent_id or 0) if current_folder is not None else 0

    directory_payload = _build_directory_items_payload(visible_items)

    return render_template(
        "file_list.html",
        files=visible_items,
        directory_items=directory_payload,
        filters={
            "q": q,
            "level": level,
            "status": status,
            "upload_start": upload_start,
            "upload_end": upload_end,
            "parent_id": parent_id,
        },
        has_active_filters=bool((q or "").strip() or level.strip() or status.strip() or upload_start.strip() or upload_end.strip()),
        allowed_levels=allowed_levels,
        is_admin=is_admin,
        parent_id=parent_id,
        current_parent_id=current_parent_id,
        breadcrumbs=breadcrumbs,
        current_folder=current_folder,
        default_new_folder_level="秘密",
        current_actor_id=session.get("account_id"),
        current_actor_type=session.get("account_type"),
        explorer_files=_build_explorer_items(visible_items),
        current_path=request.path,
    )


@file_bp.route("/files/upload", methods=["POST"])
@login_required
def file_upload_submit():
    """
    功能：上传文件并自动加密后入库。
    参数：
        无。
    返回值：
        Response: 重定向回文件列表页。
    注意事项：
        每条记录使用独立随机密钥，密钥文件保存为 keys/<file_id>.key。
    """
    actor_id, account_type, actor_type_label, username = _current_actor()
    level = request.form.get("level", "秘密").strip()
    parent_id = _safe_parent_id(request.form.get("parent_id"), default=0)
    upload_file: FileStorage | None = request.files.get("secret_file")

    created_file_id: int | None = None
    max_size = _max_upload_file_size()

    try:
        if not _is_csrf_token_valid():
            return _respond_file_action(
                message="请求校验失败，请刷新页面后重试。",
                category="danger",
                is_success=False,
                redirect_endpoint="file.file_list_page",
                status_code=403,
                endpoint_values={"parent_id": parent_id},
            )

        if level not in ALLOWED_SECRET_LEVELS:
            return _respond_file_action(
                message="密级参数非法，请重新选择。",
                category="danger",
                is_success=False,
                redirect_endpoint="file.file_list_page",
                status_code=400,
                endpoint_values={"parent_id": parent_id},
            )

        if not _can_access_level(level):
            return _respond_file_action(
                message="权限不足：当前账号不可上传该密级文件。",
                category="danger",
                is_success=False,
                redirect_endpoint="file.file_list_page",
                status_code=403,
                endpoint_values={"parent_id": parent_id},
            )

        target_parent = _get_active_folder_or_none(parent_id)
        if parent_id > 0 and target_parent is None:
            return _respond_file_action(
                message="目标目录不存在或已删除。",
                category="danger",
                is_success=False,
                redirect_endpoint="file.file_list_page",
                status_code=404,
                endpoint_values={"parent_id": 0},
            )

        if target_parent is not None and not _can_access_level(target_parent.level):
            return _respond_file_action(
                message="权限不足：不可上传到该目录。",
                category="danger",
                is_success=False,
                redirect_endpoint="file.file_list_page",
                status_code=403,
                endpoint_values={"parent_id": 0},
            )

        if target_parent is not None and not _can_contain_level(target_parent.level, level):
            return _respond_file_action(
                message="权限不足：该目录无法容纳此密级文件。",
                category="danger",
                is_success=False,
                redirect_endpoint="file.file_list_page",
                status_code=403,
                endpoint_values={"parent_id": parent_id},
            )

        if upload_file is None or not upload_file.filename:
            return _respond_file_action(
                message="请选择要上传的文件。",
                category="danger",
                is_success=False,
                redirect_endpoint="file.file_list_page",
                status_code=400,
                endpoint_values={"parent_id": parent_id},
            )

        file_name = secure_filename(upload_file.filename).strip()
        if not file_name:
            return _respond_file_action(
                message="文件名无效，请重新选择文件。",
                category="danger",
                is_success=False,
                redirect_endpoint="file.file_list_page",
                status_code=400,
                endpoint_values={"parent_id": parent_id},
            )

        file_bytes = upload_file.read()
        if not file_bytes:
            return _respond_file_action(
                message="上传文件为空，请重新选择。",
                category="danger",
                is_success=False,
                redirect_endpoint="file.file_list_page",
                status_code=400,
                endpoint_values={"parent_id": parent_id},
            )

        if len(file_bytes) > max_size:
            return _respond_file_action(
                message="文件过大，单文件最大 100MB。",
                category="danger",
                is_success=False,
                redirect_endpoint="file.file_list_page",
                status_code=413,
                endpoint_values={"parent_id": parent_id},
            )

        guessed_mime = mimetypes.guess_type(file_name)[0] or "application/octet-stream"
        final_mime = (upload_file.mimetype or guessed_mime or "application/octet-stream")[:120]

        new_record = SecretFile(
            file_group_id=uuid4().hex,
            name=file_name,
            parent_id=parent_id,
            level=level,
            uploader_id=actor_id,
            uploader_type=actor_type_label,
            content=file_bytes,  # 存储明文，不自动加密
            mime_type=final_mime,
            status="未加密",  # 默认状态改为未加密
            is_folder=False,
            major_version=1,
            minor_version=1,
            version="1.1",
            is_latest=True,
            is_deleted=False,
            file_size=len(file_bytes),
        )
        db.session.add(new_record)
        db.session.flush()

        created_file_id = int(new_record.id)

        _record_file_audit(
            operation_type="文件上传",
            detail=(
                f"{actor_type_label} {username} 上传文件成功（未加密），"
                f"文件={file_name}，版本=1.1，密级={level}，目录ID={parent_id}。"
            ),
            is_success=True,
            customer_id=actor_id if account_type == "customer" else None,
            administrator_id=actor_id if account_type == "administrator" else None,
            file_id=created_file_id,
        )
        db.session.commit()

        return _respond_file_action(
            message="文件上传成功，请手动加密以保护文件内容。",
            category="success",
            is_success=True,
            redirect_endpoint="file.file_list_page",
            status_code=200,
            endpoint_values={"parent_id": parent_id},
        )

    except (FileCryptoServiceError, SQLAlchemyError) as exc:
        db.session.rollback()
        if created_file_id is not None:
            try:
                FileCryptoService.delete_key_file(created_file_id, current_app.config["FILE_KEY_DIR"])
            except FileCryptoServiceError:
                current_app.logger.warning("上传失败后清理密钥文件失败: file_id=%s", created_file_id)

        current_app.logger.exception("文件上传加密失败: %s", exc)
        _record_file_audit(
            operation_type="文件加密存储",
            detail=f"{actor_type_label} {username} 上传加密失败：{exc}",
            is_success=False,
            customer_id=actor_id if account_type == "customer" else None,
            administrator_id=actor_id if account_type == "administrator" else None,
            file_id=created_file_id,
        )
        try:
            db.session.commit()
        except SQLAlchemyError:
            db.session.rollback()

        return _respond_file_action(
            message="文件上传失败，请稍后重试。",
            category="danger",
            is_success=False,
            redirect_endpoint="file.file_list_page",
            status_code=500,
            endpoint_values={"parent_id": parent_id},
        )
    except Exception as exc:
        db.session.rollback()
        current_app.logger.exception("文件上传异常: %s", exc)
        return _respond_file_action(
            message="上传失败：系统发生未知异常。",
            category="danger",
            is_success=False,
            redirect_endpoint="file.file_list_page",
            status_code=500,
            endpoint_values={"parent_id": parent_id},
        )


@file_bp.route("/files/folders/create", methods=["POST"])
@login_required
def folder_create_submit():
    """
    功能：在当前目录创建新文件夹。
    参数：
        无。
    返回值：
        Response: JSON 或页面重定向响应。
    注意事项：
        文件夹密级由前端弹窗选择，默认值为"秘密"。
    """
    actor_id, account_type, actor_type_label, username = _current_actor()
    parent_id = _safe_parent_id(request.form.get("parent_id"), default=0)
    folder_name = _normalize_folder_name(request.form.get("folder_name", ""))
    folder_level = request.form.get("level", "秘密").strip()

    try:
        if not _is_csrf_token_valid():
            return _respond_file_action(
                message="请求校验失败，请刷新页面后重试。",
                category="danger",
                is_success=False,
                redirect_endpoint="file.file_list_page",
                status_code=403,
                endpoint_values={"parent_id": parent_id},
            )

        if not folder_name:
            return _respond_file_action(
                message="文件夹名称不能为空。",
                category="danger",
                is_success=False,
                redirect_endpoint="file.file_list_page",
                status_code=400,
                endpoint_values={"parent_id": parent_id},
            )

        parent_folder = _get_active_folder_or_none(parent_id)
        if parent_id > 0 and parent_folder is None:
            return _respond_file_action(
                message="目标目录不存在或已删除。",
                category="danger",
                is_success=False,
                redirect_endpoint="file.file_list_page",
                status_code=404,
                endpoint_values={"parent_id": 0},
            )

        if parent_folder is not None and not _can_access_level(parent_folder.level):
            return _respond_file_action(
                message="权限不足：不可在该目录创建文件夹。",
                category="danger",
                is_success=False,
                redirect_endpoint="file.file_list_page",
                status_code=403,
                endpoint_values={"parent_id": 0},
            )

        if folder_level not in ALLOWED_SECRET_LEVELS:
            return _respond_file_action(
                message="密级参数非法，请重新选择。",
                category="danger",
                is_success=False,
                redirect_endpoint="file.file_list_page",
                status_code=400,
                endpoint_values={"parent_id": parent_id},
            )

        if not _can_access_level(folder_level):
            return _respond_file_action(
                message="权限不足：当前账号不可创建该密级目录。",
                category="danger",
                is_success=False,
                redirect_endpoint="file.file_list_page",
                status_code=403,
                endpoint_values={"parent_id": parent_id},
            )

        if parent_folder is not None and not _can_contain_level(parent_folder.level, folder_level):
            return _respond_file_action(
                message="权限不足：该目录无法容纳此密级文件夹。",
                category="danger",
                is_success=False,
                redirect_endpoint="file.file_list_page",
                status_code=403,
                endpoint_values={"parent_id": parent_id},
            )

        duplicated_folder = (
            SecretFile.query.filter_by(
                parent_id=parent_id,
                is_latest=True,
                is_deleted=False,
                is_folder=True,
            )
            .filter(SecretFile.name == folder_name)
            .first()
        )
        if duplicated_folder is not None:
            return _respond_file_action(
                message="文件夹已存在。",
                category="warning",
                is_success=False,
                redirect_endpoint="file.file_list_page",
                status_code=409,
                endpoint_values={"parent_id": parent_id},
            )

        new_folder = SecretFile(
            file_group_id=uuid4().hex,
            name=folder_name,
            parent_id=parent_id,
            level=folder_level,
            uploader_id=actor_id,
            uploader_type=actor_type_label,
            content=b"",
            mime_type="application/x-directory",
            status="未加密",
            is_folder=True,
            major_version=1,
            minor_version=0,
            version="1.0",
            is_latest=True,
            is_deleted=False,
            file_size=0,
        )
        db.session.add(new_folder)
        db.session.flush()

        _record_file_audit(
            operation_type="新建文件夹",
            detail=(
                f"{actor_type_label} {username} 新建文件夹成功，"
                f"名称={folder_name}，目录ID={parent_id}，密级={folder_level}。"
            ),
            is_success=True,
            customer_id=actor_id if account_type == "customer" else None,
            administrator_id=actor_id if account_type == "administrator" else None,
            file_id=int(new_folder.id),
        )
        db.session.commit()

        return _respond_file_action(
            message="文件夹创建成功。",
            category="success",
            is_success=True,
            redirect_endpoint="file.file_list_page",
            status_code=200,
            endpoint_values={"parent_id": parent_id},
        )

    except SQLAlchemyError as exc:
        db.session.rollback()
        current_app.logger.exception("创建文件夹失败: %s", exc)
        _record_file_audit(
            operation_type="新建文件夹",
            detail=f"{actor_type_label} {username} 新建文件夹失败：{exc}",
            is_success=False,
            customer_id=actor_id if account_type == "customer" else None,
            administrator_id=actor_id if account_type == "administrator" else None,
        )
        db.session.commit()

        return _respond_file_action(
            message="文件夹创建失败，请稍后重试。",
            category="danger",
            is_success=False,
            redirect_endpoint="file.file_list_page",
            status_code=500,
            endpoint_values={"parent_id": parent_id},
        )


@file_bp.route("/files/folders/<int:folder_id>/rename", methods=["POST"])
@login_required
def folder_rename_submit(folder_id: int):
    """
    功能：重命名文件夹。
    参数：
        folder_id (int): 文件夹记录 ID。
    返回值：
        Response: JSON 或页面重定向响应。
    注意事项：
        同目录下禁止重名。
    """
    actor_id, account_type, actor_type_label, username = _current_actor()
    new_folder_name = _normalize_folder_name(request.form.get("new_name", ""))

    folder_item = _get_active_folder_or_none(folder_id)
    parent_id = int(folder_item.parent_id or 0) if folder_item is not None else 0

    try:
        if not _is_csrf_token_valid():
            return _respond_file_action(
                message="请求校验失败，请刷新页面后重试。",
                category="danger",
                is_success=False,
                redirect_endpoint="file.file_list_page",
                status_code=403,
                endpoint_values={"parent_id": parent_id},
            )

        if folder_item is None:
            return _respond_file_action(
                message="目标文件夹不存在或已删除。",
                category="warning",
                is_success=False,
                redirect_endpoint="file.file_list_page",
                status_code=404,
                endpoint_values={"parent_id": 0},
            )

        if not _can_delete_item_by_abac(folder_item):
            return _respond_file_action(
                message="权限不足：不可重命名该文件夹。",
                category="danger",
                is_success=False,
                redirect_endpoint="file.file_list_page",
                status_code=403,
                endpoint_values={"parent_id": parent_id},
            )

        if not new_folder_name:
            return _respond_file_action(
                message="文件夹名称不能为空。",
                category="danger",
                is_success=False,
                redirect_endpoint="file.file_list_page",
                status_code=400,
                endpoint_values={"parent_id": parent_id},
            )

        duplicated_folder = (
            SecretFile.query.filter_by(
                parent_id=parent_id,
                is_latest=True,
                is_deleted=False,
                is_folder=True,
            )
            .filter(SecretFile.id != int(folder_item.id))
            .filter(SecretFile.name == new_folder_name)
            .first()
        )
        if duplicated_folder is not None:
            return _respond_file_action(
                message="文件夹已存在。",
                category="warning",
                is_success=False,
                redirect_endpoint="file.file_list_page",
                status_code=409,
                endpoint_values={"parent_id": parent_id},
            )

        old_name = folder_item.name
        folder_item.name = new_folder_name

        _record_file_audit(
            operation_type="重命名文件夹",
            detail=(
                f"{actor_type_label} {username} 重命名文件夹成功，"
                f"{old_name} -> {new_folder_name}。"
            ),
            is_success=True,
            customer_id=actor_id if account_type == "customer" else None,
            administrator_id=actor_id if account_type == "administrator" else None,
            file_id=int(folder_item.id),
        )
        db.session.commit()

        return _respond_file_action(
            message="文件夹重命名成功。",
            category="success",
            is_success=True,
            redirect_endpoint="file.file_list_page",
            status_code=200,
            endpoint_values={"parent_id": parent_id},
        )

    except SQLAlchemyError as exc:
        db.session.rollback()
        current_app.logger.exception("重命名文件夹失败: %s", exc)
        _record_file_audit(
            operation_type="重命名文件夹",
            detail=f"{actor_type_label} {username} 重命名文件夹失败：{exc}",
            is_success=False,
            customer_id=actor_id if account_type == "customer" else None,
            administrator_id=actor_id if account_type == "administrator" else None,
            file_id=int(folder_item.id) if folder_item is not None else None,
        )
        db.session.commit()

        return _respond_file_action(
            message="文件夹重命名失败，请稍后重试。",
            category="danger",
            is_success=False,
            redirect_endpoint="file.file_list_page",
            status_code=500,
            endpoint_values={"parent_id": parent_id},
        )


@file_bp.route("/files/items/<int:item_id>/delete", methods=["POST"])
@login_required
def file_item_delete_submit(item_id: int):
    """
    功能：按目录项 ID 删除文件或文件夹（软删除到回收站）。
    参数：
        item_id (int): 目录项记录 ID（最新版本记录）。
    返回值：
        Response: JSON 或页面重定向响应。
    注意事项：
        删除文件夹时会级联软删除其全部子树和历史版本。
    """
    actor_id, account_type, actor_type_label, username = _current_actor()

    target_item = SecretFile.query.filter_by(
        id=item_id,
        is_latest=True,
        is_deleted=False,
    ).first()
    parent_id = int(target_item.parent_id or 0) if target_item is not None else 0

    try:
        if not _is_csrf_token_valid():
            return _respond_file_action(
                message="请求校验失败，请刷新页面后重试。",
                category="danger",
                is_success=False,
                redirect_endpoint="file.file_list_page",
                status_code=403,
                endpoint_values={"parent_id": parent_id},
            )

        if target_item is None:
            return _respond_file_action(
                message="目标文件或文件夹不存在。",
                category="warning",
                is_success=False,
                redirect_endpoint="file.file_list_page",
                status_code=404,
                endpoint_values={"parent_id": 0},
            )

        if not _can_delete_item_by_abac(target_item):
            return _respond_file_action(
                message="权限不足：不可删除该文件或文件夹。",
                category="danger",
                is_success=False,
                redirect_endpoint="file.file_list_page",
                status_code=403,
                endpoint_values={"parent_id": parent_id},
            )

        operation_type = "文件删除(回收站)"
        if bool(target_item.is_folder):
            group_ids = _collect_folder_tree_group_ids(int(target_item.id))
            if not group_ids:
                group_ids = {str(target_item.file_group_id)}

            latest_items = (
                SecretFile.query.filter(
                    SecretFile.file_group_id.in_(group_ids),
                    SecretFile.is_latest.is_(True),
                    SecretFile.is_deleted.is_(False),
                )
                .order_by(SecretFile.id.asc())
                .all()
            )
            group_path_map = {
                str(item.file_group_id): _build_parent_path_text(int(item.parent_id or 0))
                for item in latest_items
            }
            if not group_path_map:
                group_path_map = {
                    str(target_item.file_group_id): _build_parent_path_text(int(target_item.parent_id or 0))
                }

            affected_rows = _soft_delete_file_groups(
                group_path_map=group_path_map,
                actor_id=actor_id,
                actor_type_label=actor_type_label,
            )
            operation_type = "文件夹删除(回收站)"
        else:
            affected_rows = _soft_delete_file_groups(
                group_path_map={
                    str(target_item.file_group_id): _build_parent_path_text(int(target_item.parent_id or 0))
                },
                actor_id=actor_id,
                actor_type_label=actor_type_label,
            )

        _record_file_audit(
            operation_type=operation_type,
            detail=(
                f"{actor_type_label} {username} 删除目录项成功，"
                f"名称={target_item.name}，影响记录={affected_rows}。"
            ),
            is_success=True,
            customer_id=actor_id if account_type == "customer" else None,
            administrator_id=actor_id if account_type == "administrator" else None,
            file_id=int(target_item.id),
        )
        db.session.commit()

        return _respond_file_action(
            message="删除成功。",
            category="success",
            is_success=True,
            redirect_endpoint="file.file_list_page",
            status_code=200,
            endpoint_values={"parent_id": parent_id},
        )

    except SQLAlchemyError as exc:
        db.session.rollback()
        current_app.logger.exception("目录项删除失败: %s", exc)
        _record_file_audit(
            operation_type="目录项删除",
            detail=f"{actor_type_label} {username} 删除目录项失败：{exc}",
            is_success=False,
            customer_id=actor_id if account_type == "customer" else None,
            administrator_id=actor_id if account_type == "administrator" else None,
            file_id=int(target_item.id) if target_item is not None else None,
        )
        db.session.commit()

        return _respond_file_action(
            message="删除失败，请稍后重试。",
            category="danger",
            is_success=False,
            redirect_endpoint="file.file_list_page",
            status_code=500,
            endpoint_values={"parent_id": parent_id},
        )


@file_bp.route("/files/<string:file_group_id>", methods=["GET"])
@login_required
def file_detail_page(file_group_id: str):
    """
    功能：查看文件详情页（最新版本）。
    参数：
        file_group_id (str): 文件分组ID。
    返回值：
        Response: 文件详情页面。
    注意事项：
        普通用户无法访问回收站中的文件详情。
    """
    latest_file = _get_latest_file_or_none(file_group_id)
    if latest_file is None:
        flash("文件不存在或已被移除。", "warning")
        return redirect(url_for("file.file_list_page"))

    if bool(latest_file.is_folder):
        flash("文件夹不支持查看文件详情页。", "warning")
        return redirect(url_for("file.file_list_page", parent_id=latest_file.parent_id or 0))

    if latest_file.is_deleted and not _is_admin():
        flash("文件已进入回收站。", "warning")
        return redirect(url_for("file.file_list_page"))

    if not _can_access_level(latest_file.level):
        flash("权限不足：不可访问该密级文件。", "danger")
        return redirect(url_for("file.file_list_page"))

    is_admin = _is_admin()
    allowed_levels = ABACService.allowed_file_levels(
        account_type=session.get("account_type", "customer"),
        security_level=session.get("security_level", "初级"),
    )

    history_count = SecretFile.query.filter_by(file_group_id=file_group_id).count()

    sidebar_query = SecretFile.query.filter_by(is_latest=True, is_deleted=False)
    if allowed_levels:
        sidebar_query = sidebar_query.filter(SecretFile.level.in_(allowed_levels))
    else:
        sidebar_query = sidebar_query.filter(SecretFile.id == -1)
    sidebar_files = sidebar_query.order_by(SecretFile.uploaded_at.desc()).limit(30).all()

    return render_template(
        "file_detail.html",
        file_item=latest_file,
        history_count=history_count,
        can_manage=_can_manage_file(latest_file),
        can_change_level=is_admin,
        is_admin=is_admin,
        explorer_files=_build_explorer_items(sidebar_files),
        current_path=request.path,
    )


@file_bp.route("/files/<string:file_group_id>/update", methods=["POST"])
@login_required
def file_update_submit(file_group_id: str):
    """
    功能：保存文件新版本并自动加密。
    参数：
        file_group_id (str): 文件分组ID。
    返回值：
        Response: 重定向到详情页。
    注意事项：
        每次保存次版本 +1；管理员可手动调整主版本号。
    """
    actor_id, account_type, actor_type_label, username = _current_actor()
    created_version_id: int | None = None
    max_size = _max_upload_file_size()

    try:
        if not _is_csrf_token_valid():
            flash("请求校验失败，请刷新页面后重试。", "danger")
            return redirect(url_for("file.file_detail_page", file_group_id=file_group_id))

        latest_file = _get_latest_file_or_none(file_group_id)
        if latest_file is None or latest_file.is_deleted:
            flash("文件不存在或已被删除。", "warning")
            return redirect(url_for("file.file_list_page"))

        if bool(latest_file.is_folder):
            flash("文件夹不支持版本更新。", "warning")
            return redirect(url_for("file.file_list_page", parent_id=latest_file.parent_id or 0))

        if not _can_manage_file(latest_file):
            flash("权限不足：不可修改该文件。", "danger")
            return redirect(url_for("file.file_detail_page", file_group_id=file_group_id))

        upload_file: FileStorage | None = request.files.get("secret_file")
        if upload_file is None or not upload_file.filename:
            flash("请先上传新的文件内容。", "danger")
            return redirect(url_for("file.file_detail_page", file_group_id=file_group_id))

        file_bytes = upload_file.read()
        if not file_bytes:
            flash("上传文件为空，请重新选择。", "danger")
            return redirect(url_for("file.file_detail_page", file_group_id=file_group_id))

        if len(file_bytes) > max_size:
            flash("文件过大，单文件最大 100MB。", "danger")
            return redirect(url_for("file.file_detail_page", file_group_id=file_group_id))

        level = request.form.get("level", latest_file.level).strip()
        if level not in ALLOWED_SECRET_LEVELS:
            flash("密级参数非法，请重新选择。", "danger")
            return redirect(url_for("file.file_detail_page", file_group_id=file_group_id))

        if not _can_access_level(level):
            flash("权限不足：当前账号不可保存该密级文件。", "danger")
            return redirect(url_for("file.file_detail_page", file_group_id=file_group_id))

        target_parent_id = int(latest_file.parent_id or 0)
        target_parent = _get_active_folder_or_none(target_parent_id)
        if target_parent_id > 0 and target_parent is None:
            flash("目标目录不存在或已删除。", "warning")
            return redirect(url_for("file.file_list_page", parent_id=0))

        if target_parent is not None and not _can_contain_level(target_parent.level, level):
            flash("当前目录密级无法容纳该文件密级。", "danger")
            return redirect(url_for("file.file_detail_page", file_group_id=file_group_id))

        if not _is_admin() and level != latest_file.level:
            flash("权限不足：仅管理员可以修改文件密级。", "danger")
            return redirect(url_for("file.file_detail_page", file_group_id=file_group_id))

        requested_major_raw = request.form.get("major_version", "").strip()
        requested_major: int | None = None
        if requested_major_raw:
            try:
                requested_major = int(requested_major_raw)
            except ValueError as exc:
                raise ValueError("主版本号必须为整数。") from exc

        next_major, next_minor, next_version = _next_version(
            latest_file=latest_file,
            requested_major=requested_major,
            is_admin=_is_admin(),
        )

        next_name = secure_filename(request.form.get("name", latest_file.name).strip())
        if not next_name:
            next_name = latest_file.name

        latest_file.is_latest = False

        new_version_record = SecretFile(
            file_group_id=file_group_id,
            name=next_name,
            parent_id=int(latest_file.parent_id or 0),
            level=level,
            uploader_id=actor_id,
            uploader_type=actor_type_label,
            content=b"",
            mime_type=(upload_file.mimetype or latest_file.mime_type or "application/octet-stream")[:120],
            status="已加密",
            is_folder=False,
            major_version=next_major,
            minor_version=next_minor,
            version=next_version,
            is_latest=True,
            is_deleted=False,
            file_size=len(file_bytes),
        )
        db.session.add(new_version_record)
        db.session.flush()

        created_version_id = int(new_version_record.id)
        encrypted_blob, key_path = _encrypt_and_bind_record(created_version_id, file_bytes)
        new_version_record.content = encrypted_blob

        _record_file_audit(
            operation_type="文件加密更新",
            detail=(
                f"{actor_type_label} {username} 更新文件成功，"
                f"文件={latest_file.name}，版本 {latest_file.version} -> {next_version}，"
                f"密级={level}，key={key_path}。"
            ),
            is_success=True,
            customer_id=actor_id if account_type == "customer" else None,
            administrator_id=actor_id if account_type == "administrator" else None,
            file_id=created_version_id,
        )
        db.session.commit()

        flash(f"文件已保存并加密，当前版本 {next_version}。", "success")
        return redirect(url_for("file.file_detail_page", file_group_id=file_group_id))

    except (ValueError, FileCryptoServiceError, SQLAlchemyError) as exc:
        db.session.rollback()
        if created_version_id is not None:
            try:
                FileCryptoService.delete_key_file(created_version_id, current_app.config["FILE_KEY_DIR"])
            except FileCryptoServiceError:
                current_app.logger.warning("更新失败后清理密钥文件失败: file_id=%s", created_version_id)

        current_app.logger.exception("文件版本更新失败: %s", exc)
        _record_file_audit(
            operation_type="文件加密更新",
            detail=f"{actor_type_label} {username} 更新文件失败：{exc}",
            is_success=False,
            customer_id=actor_id if account_type == "customer" else None,
            administrator_id=actor_id if account_type == "administrator" else None,
            file_id=created_version_id,
        )
        db.session.commit()

        flash(str(exc), "danger")
        return redirect(url_for("file.file_detail_page", file_group_id=file_group_id))


@file_bp.route("/files/<string:file_group_id>/download", methods=["GET"])
@login_required
def file_download_latest(file_group_id: str):
    """
    功能：下载最新版本，未加密直接下载，已加密自动解密。
    参数：
        file_group_id (str): 文件分组ID。
    返回值：
        Response: 附件下载响应。
    注意事项：
        下载前进行密级权限检查。
        未加密文件直接返回明文，已加密文件需要解密后返回。
    """
    actor_id, account_type, actor_type_label, username = _current_actor()

    try:
        latest_file = _get_latest_file_or_none(file_group_id)
        if latest_file is None or latest_file.is_deleted:
            flash("文件不存在或已被删除。", "warning")
            return redirect(url_for("file.file_list_page"))

        if bool(latest_file.is_folder):
            flash("文件夹不支持下载。", "warning")
            return redirect(url_for("file.file_list_page", parent_id=latest_file.parent_id or 0))

        if not _can_access_level(latest_file.level):
            flash("权限不足：不可下载该密级文件。", "danger")
            return redirect(url_for("file.file_list_page"))

        # 根据状态决定是否需要解密
        if latest_file.status == "未加密":
            # 未加密文件直接返回明文
            plain_bytes = latest_file.content
            operation_type = "文件下载（未加密）"
        else:
            # 已加密文件需要解密
            plain_bytes = _decrypt_file_bytes(latest_file)
            operation_type = "文件解密下载"

        _record_file_audit(
            operation_type=operation_type,
            detail=(
                f"{actor_type_label} {username} 下载文件成功，"
                f"文件={latest_file.name}，版本={latest_file.version}，状态={latest_file.status}。"
            ),
            is_success=True,
            customer_id=actor_id if account_type == "customer" else None,
            administrator_id=actor_id if account_type == "administrator" else None,
            file_id=int(latest_file.id),
        )
        db.session.commit()

        return _render_download_response(
            plain_bytes=plain_bytes,
            file_name=latest_file.name,
            mime_type=latest_file.mime_type,
        )

    except (FileCryptoServiceError, SQLAlchemyError) as exc:
        db.session.rollback()
        current_app.logger.exception("下载失败: %s", exc)
        _record_file_audit(
            operation_type="文件下载",
            detail=f"{actor_type_label} {username} 下载失败：{exc}",
            is_success=False,
            customer_id=actor_id if account_type == "customer" else None,
            administrator_id=actor_id if account_type == "administrator" else None,
            file_id=int(latest_file.id) if 'latest_file' in locals() and latest_file is not None else None,
        )
        db.session.commit()

        flash("文件下载失败，请稍后重试。", "danger")
        return redirect(url_for("file.file_list_page"))


@file_bp.route("/files/<string:file_group_id>/manual/encrypt", methods=["POST"])
@login_required
def file_manual_encrypt(file_group_id: str):
    """
    功能：手动加密文件，可选择密级。
    参数：
        file_group_id (str): 文件分组ID。
        level: 密级选择（可选，如果不提供则保持原密级）。
    返回值：
        Response: JSON响应或重定向。
    注意事项：
        1. 仅管理员或原上传者可执行。
        2. 密级选择受用户权限限制：
           - 初级用户：只能选择「秘密」
           - 中级用户：可选择「秘密」「机密」
           - 高级用户和管理员：可选择「秘密」「机密」「绝密」
    """
    actor_id, account_type, actor_type_label, username = _current_actor()
    requested_level = request.form.get("level", "").strip()

    try:
        latest_file = _get_latest_file_or_none(file_group_id)
        if latest_file is None or latest_file.is_deleted:
            return _respond_file_action(
                message="文件不存在或已被删除。",
                category="warning",
                is_success=False,
                redirect_endpoint="file.file_list_page",
                status_code=404,
            )

        if bool(latest_file.is_folder):
            return _respond_file_action(
                message="文件夹不支持手动加密。",
                category="warning",
                is_success=False,
                redirect_endpoint="file.file_list_page",
                status_code=400,
                endpoint_values={"parent_id": latest_file.parent_id or 0},
            )

        if not _can_manage_file(latest_file):
            return _respond_file_action(
                message="权限不足：不可手动加密该文件。",
                category="danger",
                is_success=False,
                redirect_endpoint="file.file_detail_page",
                status_code=403,
                endpoint_values={"file_group_id": file_group_id},
            )

        # 检查文件是否已加密
        if latest_file.status == "已加密":
            return _respond_file_action(
                message="文件已加密，无需重复操作。",
                category="warning",
                is_success=False,
                redirect_endpoint="file.file_detail_page",
                status_code=400,
                endpoint_values={"file_group_id": file_group_id},
            )

        # 处理密级选择
        final_level = latest_file.level
        if requested_level and requested_level in ALLOWED_SECRET_LEVELS:
            # 检查用户是否有权限选择该密级
            if not _can_access_level(requested_level):
                return _respond_file_action(
                    message=f"权限不足：不可加密为{requested_level}密级。",
                    category="danger",
                    is_success=False,
                    redirect_endpoint="file.file_detail_page",
                    status_code=403,
                    endpoint_values={"file_group_id": file_group_id},
                )
            final_level = requested_level

        # 加密文件
        plain_bytes = latest_file.content  # 未加密状态，content是明文
        encrypted_blob, key_path = _encrypt_and_bind_record(int(latest_file.id), plain_bytes)

        latest_file.content = encrypted_blob
        latest_file.status = "已加密"
        latest_file.level = final_level  # 更新密级

        _record_file_audit(
            operation_type="文件手动加密",
            detail=(
                f"{actor_type_label} {username} 手动加密成功，"
                f"文件={latest_file.name}，版本={latest_file.version}，密级={final_level}，key={key_path}。"
            ),
            is_success=True,
            customer_id=actor_id if account_type == "customer" else None,
            administrator_id=actor_id if account_type == "administrator" else None,
            file_id=int(latest_file.id),
        )
        db.session.commit()

        return _respond_file_action(
            message=f"文件加密完成，密级：{final_level}。",
            category="success",
            is_success=True,
            redirect_endpoint="file.file_detail_page",
            status_code=200,
            endpoint_values={"file_group_id": file_group_id},
        )

    except (FileCryptoServiceError, SQLAlchemyError) as exc:
        db.session.rollback()
        current_app.logger.exception("手动加密失败: %s", exc)
        _record_file_audit(
            operation_type="文件手动加密",
            detail=f"{actor_type_label} {username} 手动加密失败：{exc}",
            is_success=False,
            customer_id=actor_id if account_type == "customer" else None,
            administrator_id=actor_id if account_type == "administrator" else None,
            file_id=int(latest_file.id) if 'latest_file' in locals() and latest_file is not None else None,
        )
        db.session.commit()

        return _respond_file_action(
            message="手动加密失败，请稍后重试。",
            category="danger",
            is_success=False,
            redirect_endpoint="file.file_detail_page",
            status_code=500,
            endpoint_values={"file_group_id": file_group_id},
        )


@file_bp.route("/files/<string:file_group_id>/manual/decrypt", methods=["GET"])
@login_required
def file_manual_decrypt(file_group_id: str):
    """
    功能：手动解密并下载最新版本。
    参数：
        file_group_id (str): 文件分组ID。
    返回值：
        Response: 下载响应。
    注意事项：
        用户仅可在密级权限范围内执行。
    """
    actor_id, account_type, actor_type_label, username = _current_actor()

    try:
        latest_file = _get_latest_file_or_none(file_group_id)
        if latest_file is None or latest_file.is_deleted:
            flash("文件不存在或已被删除。", "warning")
            return redirect(url_for("file.file_list_page"))

        if bool(latest_file.is_folder):
            flash("文件夹不支持手动解密下载。", "warning")
            return redirect(url_for("file.file_list_page", parent_id=latest_file.parent_id or 0))

        if not _can_access_level(latest_file.level):
            flash("权限不足：不可手动解密该密级文件。", "danger")
            return redirect(url_for("file.file_list_page"))

        plain_bytes = _decrypt_file_bytes(latest_file)

        _record_file_audit(
            operation_type="文件手动解密",
            detail=(
                f"{actor_type_label} {username} 手动解密成功，"
                f"文件={latest_file.name}，版本={latest_file.version}。"
            ),
            is_success=True,
            customer_id=actor_id if account_type == "customer" else None,
            administrator_id=actor_id if account_type == "administrator" else None,
            file_id=int(latest_file.id),
        )
        db.session.commit()

        return _render_download_response(
            plain_bytes=plain_bytes,
            file_name=f"{latest_file.name}.decrypted",
            mime_type=latest_file.mime_type,
        )

    except (FileCryptoServiceError, SQLAlchemyError) as exc:
        db.session.rollback()
        current_app.logger.exception("手动解密失败: %s", exc)
        _record_file_audit(
            operation_type="文件手动解密",
            detail=f"{actor_type_label} {username} 手动解密失败：{exc}",
            is_success=False,
            customer_id=actor_id if account_type == "customer" else None,
            administrator_id=actor_id if account_type == "administrator" else None,
            file_id=int(latest_file.id) if 'latest_file' in locals() and latest_file is not None else None,
        )
        db.session.commit()

        flash("手动解密失败，请稍后重试。", "danger")
        return redirect(url_for("file.file_detail_page", file_group_id=file_group_id))


@file_bp.route("/files/<string:file_group_id>/history", methods=["GET"])
@login_required
def file_history_page(file_group_id: str):
    """
    功能：查看文件分组历史版本。
    参数：
        file_group_id (str): 文件分组ID。
    返回值：
        Response: 历史版本页面。
    注意事项：
        历史列表按主版本、次版本倒序。
    """
    history_files = (
        SecretFile.query.filter_by(file_group_id=file_group_id)
        .order_by(
            SecretFile.major_version.desc(),
            SecretFile.minor_version.desc(),
            SecretFile.id.desc(),
        )
        .all()
    )

    if not history_files:
        flash("未找到该文件的历史记录。", "warning")
        return redirect(url_for("file.file_list_page"))

    latest_file = next((item for item in history_files if item.is_latest), history_files[0])

    if bool(latest_file.is_folder):
        flash("文件夹不支持历史版本页面。", "warning")
        return redirect(url_for("file.file_list_page", parent_id=latest_file.parent_id or 0))

    if latest_file.is_deleted and not _is_admin():
        flash("该文件已进入回收站。", "warning")
        return redirect(url_for("file.file_list_page"))

    if not _can_access_level(latest_file.level):
        flash("权限不足：不可访问该密级文件历史版本。", "danger")
        return redirect(url_for("file.file_list_page"))

    is_admin = _is_admin()
    allowed_levels = ABACService.allowed_file_levels(
        account_type=session.get("account_type", "customer"),
        security_level=session.get("security_level", "初级"),
    )

    sidebar_query = SecretFile.query.filter_by(is_latest=True, is_deleted=False)
    if allowed_levels:
        sidebar_query = sidebar_query.filter(SecretFile.level.in_(allowed_levels))
    else:
        sidebar_query = sidebar_query.filter(SecretFile.id == -1)
    sidebar_files = sidebar_query.order_by(SecretFile.uploaded_at.desc()).limit(30).all()

    return render_template(
        "file_history.html",
        latest_file=latest_file,
        history_files=history_files,
        is_admin=is_admin,
        current_path=request.path,
        explorer_files=_build_explorer_items(sidebar_files),
    )


@file_bp.route("/files/<string:file_group_id>/download/<int:file_id>", methods=["GET"])
@login_required
def file_download_history(file_group_id: str, file_id: int):
    """
    功能：下载指定历史版本，自动解密。
    参数：
        file_group_id (str): 文件分组ID。
        file_id (int): 历史版本记录ID。
    返回值：
        Response: 下载响应。
    注意事项：
        需要满足密级权限检查。
    """
    actor_id, account_type, actor_type_label, username = _current_actor()

    try:
        target_file = SecretFile.query.filter(
            and_(SecretFile.id == file_id, SecretFile.file_group_id == file_group_id)
        ).first()

        if target_file is None:
            flash("历史版本不存在。", "warning")
            return redirect(url_for("file.file_history_page", file_group_id=file_group_id))

        if bool(target_file.is_folder):
            flash("文件夹不支持历史版本下载。", "warning")
            return redirect(url_for("file.file_list_page", parent_id=target_file.parent_id or 0))

        if target_file.is_deleted and not _is_admin():
            flash("目标版本已在回收站中。", "warning")
            return redirect(url_for("file.file_list_page"))

        if not _can_access_level(target_file.level):
            flash("权限不足：不可下载该密级文件。", "danger")
            return redirect(url_for("file.file_list_page"))

        plain_bytes = _decrypt_file_bytes(target_file)

        _record_file_audit(
            operation_type="历史版本解密下载",
            detail=(
                f"{actor_type_label} {username} 下载历史版本成功，"
                f"文件={target_file.name}，版本={target_file.version}。"
            ),
            is_success=True,
            customer_id=actor_id if account_type == "customer" else None,
            administrator_id=actor_id if account_type == "administrator" else None,
            file_id=int(target_file.id),
        )
        db.session.commit()

        return _render_download_response(
            plain_bytes=plain_bytes,
            file_name=f"{target_file.name}_v{target_file.version}",
            mime_type=target_file.mime_type,
        )

    except (FileCryptoServiceError, SQLAlchemyError) as exc:
        db.session.rollback()
        current_app.logger.exception("历史版本下载失败: %s", exc)
        _record_file_audit(
            operation_type="历史版本解密下载",
            detail=f"{actor_type_label} {username} 下载历史版本失败：{exc}",
            is_success=False,
            customer_id=actor_id if account_type == "customer" else None,
            administrator_id=actor_id if account_type == "administrator" else None,
            file_id=int(target_file.id) if 'target_file' in locals() and target_file is not None else None,
        )
        db.session.commit()

        flash("历史版本下载失败，请稍后重试。", "danger")
        return redirect(url_for("file.file_history_page", file_group_id=file_group_id))


@file_bp.route("/recycle", methods=["GET"])
@admin_required
def recycle_bin_page():
    """
    功能：独立回收站页面（文件回收站 + 用户回收站）。
    参数：
        无。
    返回值：
        Response: 回收站页面。
    注意事项：
        仅管理员可访问。
    """
    current_tab = (request.args.get("tab", "files") or "files").strip().lower()
    if current_tab not in {"files", "users"}:
        current_tab = "files"

    recycle_file_rows: list[dict[str, object]] = []
    recycle_files = (
        SecretFile.query.filter_by(is_latest=True, is_deleted=True)
        .order_by(SecretFile.deleted_at.desc(), SecretFile.id.desc())
        .all()
    )
    for item in recycle_files:
        recycle_file_rows.append(
            {
                "id": int(item.id),
                "name": item.name,
                "is_folder": bool(item.is_folder),
                "size_text": "--" if bool(item.is_folder) else _format_file_size(int(item.file_size or 0)),
                "deleted_at": item.deleted_at,
                "deleted_by": f"{item.deleted_by_type or '--'}#{item.deleted_by_id or '--'}",
                "original_path": item.original_path or _build_parent_path_text(int(item.parent_id or 0)),
            }
        )

    recycle_user_rows = (
        User.query.filter_by(is_deleted=True)
        .order_by(User.deleted_at.desc(), User.id.desc())
        .all()
    )

    return render_template(
        "recycle_bin.html",
        current_tab=current_tab,
        recycle_file_rows=recycle_file_rows,
        recycle_user_rows=recycle_user_rows,
        active_nav="recycle",
        current_path=request.path,
    )


@file_bp.route("/recycle/files/<int:item_id>/restore", methods=["POST"])
@admin_required
def recycle_file_restore_submit(item_id: int):
    """
    功能：从回收站还原文件或文件夹。
    参数：
        item_id (int): 回收站目录项 ID（最新版本记录）。
    返回值：
        Response: 重定向回文件回收站。
    注意事项：
        当原父目录不存在时，会自动回退到根目录。
    """
    admin_id = int(session.get("account_id"))
    admin_username = session.get("username", "unknown")

    target_item = SecretFile.query.filter_by(
        id=item_id,
        is_latest=True,
        is_deleted=True,
    ).first()

    try:
        if not _is_csrf_token_valid():
            flash("请求校验失败，请刷新页面后重试。", "danger")
            return redirect(url_for("file.recycle_bin_page", tab="files"))

        if target_item is None:
            flash("目标文件或文件夹不在回收站中。", "warning")
            return redirect(url_for("file.recycle_bin_page", tab="files"))

        if bool(target_item.is_folder):
            group_ids = _collect_deleted_folder_tree_group_ids(int(target_item.id))
            if not group_ids:
                group_ids = {str(target_item.file_group_id)}
        else:
            group_ids = {str(target_item.file_group_id)}

        affected_rows, fallback_to_root = _restore_file_groups(group_ids)
        if affected_rows <= 0:
            flash("目标文件或文件夹不在回收站中。", "warning")
            return redirect(url_for("file.recycle_bin_page", tab="files"))

        _record_file_audit(
            operation_type="文件还原",
            detail=(
                f"管理员 {admin_username} 从回收站还原目录项，"
                f"名称={target_item.name}，影响记录={affected_rows}。"
            ),
            is_success=True,
            administrator_id=admin_id,
            file_id=int(target_item.id),
        )
        db.session.commit()

        flash("文件已还原。", "success")
        if fallback_to_root:
            flash("部分目录原位置不存在，已自动恢复到根目录。", "warning")
        return redirect(url_for("file.recycle_bin_page", tab="files"))

    except SQLAlchemyError as exc:
        db.session.rollback()
        current_app.logger.exception("回收站还原失败: %s", exc)
        _record_file_audit(
            operation_type="文件还原",
            detail=f"管理员 {admin_username} 还原失败：{exc}",
            is_success=False,
            administrator_id=admin_id,
            file_id=int(target_item.id) if target_item is not None else None,
        )
        db.session.commit()

        flash("还原失败，请稍后重试。", "danger")
        return redirect(url_for("file.recycle_bin_page", tab="files"))


@file_bp.route("/recycle/files/<int:item_id>/purge", methods=["POST"])
@admin_required
def recycle_file_purge_submit(item_id: int):
    """
    功能：从回收站彻底删除文件或文件夹。
    参数：
        item_id (int): 回收站目录项 ID（最新版本记录）。
    返回值：
        Response: 重定向回文件回收站。
    注意事项：
        永久删除后会同步清理关联密钥文件。
    """
    admin_id = int(session.get("account_id"))
    admin_username = session.get("username", "unknown")

    target_item = SecretFile.query.filter_by(
        id=item_id,
        is_latest=True,
        is_deleted=True,
    ).first()

    try:
        if not _is_csrf_token_valid():
            flash("请求校验失败，请刷新页面后重试。", "danger")
            return redirect(url_for("file.recycle_bin_page", tab="files"))

        if target_item is None:
            flash("目标文件或文件夹不在回收站中。", "warning")
            return redirect(url_for("file.recycle_bin_page", tab="files"))

        if bool(target_item.is_folder):
            group_ids = _collect_deleted_folder_tree_group_ids(int(target_item.id))
            if not group_ids:
                group_ids = {str(target_item.file_group_id)}
        else:
            group_ids = {str(target_item.file_group_id)}

        deleted_rows, record_ids = _purge_file_groups(group_ids)
        if deleted_rows <= 0:
            flash("目标文件或文件夹不在回收站中。", "warning")
            return redirect(url_for("file.recycle_bin_page", tab="files"))

        _record_file_audit(
            operation_type="文件彻底删除",
            detail=(
                f"管理员 {admin_username} 彻底删除回收站目录项，"
                f"名称={target_item.name}，清理记录={deleted_rows}。"
            ),
            is_success=True,
            administrator_id=admin_id,
            file_id=int(target_item.id),
        )
        db.session.commit()

        key_cleanup_failed: list[int] = []
        for record_id in record_ids:
            try:
                FileCryptoService.delete_key_file(record_id, current_app.config["FILE_KEY_DIR"])
            except FileCryptoServiceError:
                key_cleanup_failed.append(record_id)

        if key_cleanup_failed:
            current_app.logger.warning("回收站彻底删除后密钥清理失败: %s", key_cleanup_failed)
            flash("目录项记录已删除，但部分密钥文件清理失败，请检查服务器日志。", "warning")
        else:
            flash("文件已从回收站彻底删除。", "success")

        return redirect(url_for("file.recycle_bin_page", tab="files"))

    except SQLAlchemyError as exc:
        db.session.rollback()
        current_app.logger.exception("回收站彻底删除失败: %s", exc)
        _record_file_audit(
            operation_type="文件彻底删除",
            detail=f"管理员 {admin_username} 彻底删除失败：{exc}",
            is_success=False,
            administrator_id=admin_id,
            file_id=int(target_item.id) if target_item is not None else None,
        )
        db.session.commit()

        flash("彻底删除失败，请稍后重试。", "danger")
        return redirect(url_for("file.recycle_bin_page", tab="files"))


@file_bp.route("/files/<string:file_group_id>/delete", methods=["POST"])
@login_required
def file_delete_to_recycle(file_group_id: str):
    """
    功能：将文件分组移入回收站（软删除）。
    参数：
        file_group_id (str): 文件分组ID。
    返回值：
        Response: 重定向回文件列表。
    注意事项：
        软删除保留历史版本与密钥文件，便于审计追踪。
    """
    actor_id, account_type, actor_type_label, username = _current_actor()

    try:
        latest_file = _get_latest_file_or_none(file_group_id)
        if latest_file is None or latest_file.is_deleted:
            flash("文件不存在或已在回收站。", "warning")
            return redirect(url_for("file.file_list_page"))

        if not _can_manage_file(latest_file):
            flash("权限不足：不可删除该文件。", "danger")
            return redirect(url_for("file.file_detail_page", file_group_id=file_group_id))

        affected_rows = _soft_delete_file_groups(
            group_path_map={
                str(file_group_id): _build_parent_path_text(int(latest_file.parent_id or 0))
            },
            actor_id=actor_id,
            actor_type_label=actor_type_label,
        )

        _record_file_audit(
            operation_type="文件删除(回收站)",
            detail=(
                f"{actor_type_label} {username} 将文件移入回收站，"
                f"文件={latest_file.name}，影响版本数={affected_rows}。"
            ),
            is_success=True,
            customer_id=actor_id if account_type == "customer" else None,
            administrator_id=actor_id if account_type == "administrator" else None,
            file_id=int(latest_file.id),
        )
        db.session.commit()

        flash("文件已移入回收站。", "success")
        return redirect(url_for("file.file_list_page"))

    except SQLAlchemyError as exc:
        db.session.rollback()
        current_app.logger.exception("文件软删除失败: %s", exc)
        _record_file_audit(
            operation_type="文件删除(回收站)",
            detail=f"{actor_type_label} {username} 删除文件失败：{exc}",
            is_success=False,
            customer_id=actor_id if account_type == "customer" else None,
            administrator_id=actor_id if account_type == "administrator" else None,
            file_id=int(latest_file.id) if 'latest_file' in locals() and latest_file is not None else None,
        )
        db.session.commit()

        flash("文件删除失败，请稍后重试。", "danger")
        return redirect(url_for("file.file_list_page"))


@file_bp.route("/files/<string:file_group_id>/purge", methods=["POST"])
@admin_required
def file_purge(file_group_id: str):
    """
    功能：管理员彻底删除回收站文件。
    参数：
        file_group_id (str): 文件分组ID。
    返回值：
        Response: 重定向回列表页。
    注意事项：
        永久删除后会同步清理该分组全部密钥文件。
    """
    admin_id = int(session.get("account_id"))
    admin_username = session.get("username", "unknown")

    try:
        recycle_latest = SecretFile.query.filter_by(
            file_group_id=file_group_id,
            is_latest=True,
            is_deleted=True,
        ).first()
        if recycle_latest is None:
            flash("目标文件不在回收站中，无法彻底删除。", "warning")
            return redirect(url_for("file.file_list_page"))

        file_name = recycle_latest.name
        deleted_rows, record_ids = _purge_file_groups({str(file_group_id)})
        if deleted_rows <= 0:
            flash("目标文件不在回收站中，无法彻底删除。", "warning")
            return redirect(url_for("file.file_list_page"))

        _record_file_audit(
            operation_type="文件彻底删除",
            detail=(
                f"管理员 {admin_username} 彻底删除文件，"
                f"文件={file_name}，清理记录数={deleted_rows}。"
            ),
            is_success=True,
            administrator_id=admin_id,
            file_id=record_ids[0] if record_ids else None,
        )
        db.session.commit()

        key_cleanup_failed: list[int] = []
        for record_id in record_ids:
            try:
                FileCryptoService.delete_key_file(record_id, current_app.config["FILE_KEY_DIR"])
            except FileCryptoServiceError:
                key_cleanup_failed.append(record_id)

        if key_cleanup_failed:
            current_app.logger.warning(
                "彻底删除后密钥清理失败: %s",
                key_cleanup_failed,
            )
            flash("文件记录已删除，但部分密钥文件清理失败，请检查服务器日志。", "warning")
        else:
            flash("文件已从回收站彻底删除。", "success")

        return redirect(url_for("file.file_list_page"))

    except SQLAlchemyError as exc:
        db.session.rollback()
        current_app.logger.exception("文件彻底删除失败: %s", exc)
        _record_file_audit(
            operation_type="文件彻底删除",
            detail=f"管理员 {admin_username} 彻底删除失败：{exc}",
            is_success=False,
            administrator_id=admin_id,
            file_id=record_ids[0] if 'record_ids' in locals() and record_ids else None,
        )
        db.session.commit()

        flash("彻底删除失败，请稍后重试。", "danger")
        return redirect(url_for("file.file_list_page"))
