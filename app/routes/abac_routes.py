"""
app/routes/abac_routes.py
功能：实现模块10 ABAC 权限管理与密级管理后台。
注意事项：
1. 所有路由仅管理员可访问。
2. 所有权限变更操作必须写入审计日志。
"""

from __future__ import annotations

from datetime import datetime

from flask import Blueprint, flash, redirect, render_template, request, session, url_for
from sqlalchemy.exc import SQLAlchemyError

from app.models import SecretFile, User
from app.routes.auth_routes import admin_required
from app.services.abac_service import ABACService, ABACServiceError
from app.services.audit_log_service import AuditLogService
from extensions import db

abac_bp = Blueprint("abac", __name__)


def _record_admin_audit(
    operation_type: str,
    detail: str,
    is_success: bool,
    file_id: int | None = None,
) -> None:
    """
    功能：记录管理员权限变更相关审计日志。
    参数：
        operation_type (str): 操作类型。
        detail (str): 详情。
        is_success (bool): 是否成功。
        file_id (int | None): 文件ID。
    返回值：
        None
    注意事项：
        仅添加日志对象，提交事务由调用方负责。
    """
    admin_id = int(session.get("account_id"))
    AuditLogService.append_log(
        administrator_id=admin_id,
        file_id=file_id,
        operation_type=operation_type,
        detail=detail,
        is_success=is_success,
        ip_address=AuditLogService.get_client_ip(),
    )


@abac_bp.route("/admin", methods=["GET"])
@admin_required
def admin_home_page():
    """
    功能：系统管理导航入口页。
    参数：
        无。
    返回值：
        Response: 管理员权限管理页面。
    注意事项：
        复用权限管理页，保持业务逻辑单一来源。
    """
    return permission_management_page()


@abac_bp.route("/abac/permissions", methods=["GET"])
@admin_required
def permission_management_page():
    """
    功能：权限管理页，展示并修改用户安全级别。
    参数：
        无。
    返回值：
        Response: 权限管理页面。
    注意事项：
        仅管理员可访问。
    """
    users = User.query.filter_by(is_deleted=False).order_by(User.id.asc()).all()
    return render_template(
        "permission_management.html",
        users=users,
        security_levels=["初级", "中级", "高级"],
        active_nav="admin",
        current_path=request.path,
    )


@abac_bp.route("/abac/users/<string:user_id>/security-level", methods=["POST"])
@admin_required
def update_user_security_level(user_id: str):
    """
    功能：管理员修改用户安全级别。
    参数：
        user_id (str): 用户ID。
    返回值：
        Response: 重定向回权限管理页。
    注意事项：
        更新成功与失败均记录审计日志。
    """
    target_user = User.query.filter_by(id=user_id, is_deleted=False).first()
    new_level = request.form.get("security_level", "").strip()

    try:
        if target_user is None:
            flash("目标用户不存在。", "warning")
            return redirect(url_for("abac.permission_management_page"))

        ABACService.validate_security_level(new_level)

        old_level = target_user.security_level
        if old_level == new_level:
            flash("安全级别未发生变化。", "info")
            return redirect(url_for("abac.permission_management_page"))

        target_user.security_level = new_level

        _record_admin_audit(
            operation_type="用户安全级别变更",
            detail=(
                f"管理员将用户 {target_user.username} 安全级别由 "
                f"{old_level} 调整为 {new_level}。"
            ),
            is_success=True,
        )
        db.session.commit()

        flash("用户安全级别更新成功。", "success")
        return redirect(url_for("abac.permission_management_page"))

    except (ABACServiceError, SQLAlchemyError) as exc:
        db.session.rollback()
        _record_admin_audit(
            operation_type="用户安全级别变更",
            detail=f"用户ID={user_id} 安全级别变更失败：{exc}",
            is_success=False,
        )
        db.session.commit()

        flash(str(exc), "danger")
        return redirect(url_for("abac.permission_management_page"))


@abac_bp.route("/abac/users/<string:user_id>/delete", methods=["POST"])
@admin_required
def delete_user(user_id: str):
    """
    功能：管理员将用户账号移入回收站。
    参数：
        user_id (str): 用户ID。
    返回值：
        Response: 重定向回权限管理页。
    注意事项：
        删除成功与失败均写入审计日志。
    """
    target_user = User.query.filter_by(id=user_id, is_deleted=False).first()

    try:
        if target_user is None:
            flash("目标用户不存在。", "warning")
            return redirect(url_for("abac.permission_management_page"))

        deleted_username = target_user.username
        target_user.is_deleted = True
        target_user.deleted_at = datetime.now()
        target_user.account_status = 1
        target_user.status = "禁用"
        target_user.login_attempts = 0
        target_user.login_fail_count = 0
        target_user.lock_until = None

        _record_admin_audit(
            operation_type="用户删除(回收站)",
            detail=f"管理员将用户移入回收站：{deleted_username} (ID={user_id})。",
            is_success=True,
        )
        db.session.commit()

        flash("用户已移入回收站。", "success")
        return redirect(url_for("abac.permission_management_page"))

    except SQLAlchemyError as exc:
        db.session.rollback()
        _record_admin_audit(
            operation_type="用户删除(回收站)",
            detail=f"删除用户失败：user_id={user_id}，原因：{exc}",
            is_success=False,
        )
        db.session.commit()

        flash("删除用户失败，请稍后重试。", "danger")
        return redirect(url_for("abac.permission_management_page"))


@abac_bp.route("/abac/recycle/users/<string:user_id>/restore", methods=["POST"])
@admin_required
def restore_user(user_id: str):
    """
    功能：管理员从回收站还原用户。
    参数：
        user_id (str): 用户ID。
    返回值：
        Response: 重定向回回收站页面。
    注意事项：
        还原后账号状态默认重置为"启用"。
    """
    target_user = User.query.filter_by(id=user_id, is_deleted=True).first()

    try:
        if target_user is None:
            flash("目标用户不在回收站中。", "warning")
            return redirect(url_for("file.recycle_bin_page", tab="users"))

        restored_username = target_user.username
        target_user.is_deleted = False
        target_user.deleted_at = None
        target_user.account_status = 0
        target_user.status = "启用"
        target_user.login_attempts = 0
        target_user.login_fail_count = 0
        target_user.lock_until = None

        _record_admin_audit(
            operation_type="用户还原",
            detail=f"管理员从回收站还原用户：{restored_username} (ID={user_id})。",
            is_success=True,
        )
        db.session.commit()

        flash("用户已还原。", "success")
        return redirect(url_for("file.recycle_bin_page", tab="users"))

    except SQLAlchemyError as exc:
        db.session.rollback()
        _record_admin_audit(
            operation_type="用户还原",
            detail=f"还原用户失败：user_id={user_id}，原因：{exc}",
            is_success=False,
        )
        db.session.commit()

        flash("还原用户失败，请稍后重试。", "danger")
        return redirect(url_for("file.recycle_bin_page", tab="users"))


@abac_bp.route("/abac/recycle/users/<string:user_id>/purge", methods=["POST"])
@admin_required
def purge_user(user_id: str):
    """
    功能：管理员彻底删除回收站用户。
    参数：
        user_id (str): 用户ID。
    返回值：
        Response: 重定向回回收站页面。
    注意事项：
        彻底删除会清理该用户关联数据（由数据库级联约束处理）。
    """
    target_user = User.query.filter_by(id=user_id, is_deleted=True).first()

    try:
        if target_user is None:
            flash("目标用户不在回收站中。", "warning")
            return redirect(url_for("file.recycle_bin_page", tab="users"))

        purged_username = target_user.username
        db.session.delete(target_user)

        _record_admin_audit(
            operation_type="用户彻底删除",
            detail=f"管理员彻底删除回收站用户：{purged_username} (ID={user_id})。",
            is_success=True,
        )
        db.session.commit()

        flash("用户已彻底删除。", "success")
        return redirect(url_for("file.recycle_bin_page", tab="users"))

    except SQLAlchemyError as exc:
        db.session.rollback()
        _record_admin_audit(
            operation_type="用户彻底删除",
            detail=f"彻底删除用户失败：user_id={user_id}，原因：{exc}",
            is_success=False,
        )
        db.session.commit()

        flash("彻底删除用户失败，请稍后重试。", "danger")
        return redirect(url_for("file.recycle_bin_page", tab="users"))


@abac_bp.route("/abac/users/<string:user_id>/toggle-status", methods=["POST"])
@admin_required
def toggle_user_status(user_id: str):
    """
    功能：管理员切换用户账户状态。
    参数：
        user_id (str): 用户ID。
    返回值：
        Response: 重定向回权限管理页。
    注意事项：
        状态切换成功与失败均写入审计日志。
    """
    target_user = User.query.filter_by(id=user_id, is_deleted=False).first()

    try:
        if target_user is None:
            flash("目标用户不存在。", "warning")
            return redirect(url_for("abac.permission_management_page"))

        old_status = int(target_user.account_status or 0)
        new_status = 0 if old_status == 1 else 1
        target_user.account_status = new_status
        target_user.status = "禁用" if new_status == 1 else "启用"

        if new_status == 0:
            target_user.login_attempts = 0
            target_user.login_fail_count = 0
            target_user.lock_until = None

        _record_admin_audit(
            operation_type="用户账户状态切换",
            detail=(
                f"管理员将用户 {target_user.username} 账户状态由 "
                f"{'已禁用' if old_status == 1 else '正常'} 切换为 "
                f"{'已禁用' if new_status == 1 else '正常'}。"
            ),
            is_success=True,
        )
        db.session.commit()

        flash(f"用户账户已{'禁用' if new_status == 1 else '启用'}。", "success")
        return redirect(url_for("abac.permission_management_page"))

    except SQLAlchemyError as exc:
        db.session.rollback()
        _record_admin_audit(
            operation_type="用户账户状态切换",
            detail=f"用户ID={user_id} 账户状态切换失败：{exc}",
            is_success=False,
        )
        db.session.commit()

        flash("用户账户状态切换失败，请稍后重试。", "danger")
        return redirect(url_for("abac.permission_management_page"))


@abac_bp.route("/abac/users/<string:user_id>/enable-account", methods=["POST"])
@admin_required
def enable_user_account(user_id: str):
    """
    功能：管理员启用用户账户并重置登录失败次数。
    参数：
        user_id (str): 用户ID。
    返回值：
        Response: 重定向回权限管理页。
    注意事项：
        启用操作会同步清理新旧登录风控字段。
    """
    target_user = User.query.filter_by(id=user_id, is_deleted=False).first()

    try:
        if target_user is None:
            flash("目标用户不存在。", "warning")
            return redirect(url_for("abac.permission_management_page"))

        target_user.account_status = 0
        target_user.status = "启用"
        target_user.login_attempts = 0
        target_user.login_fail_count = 0
        target_user.lock_until = None

        _record_admin_audit(
            operation_type="用户账户启用",
            detail=f"管理员启用用户账户：{target_user.username} (ID={user_id})。",
            is_success=True,
        )
        db.session.commit()

        flash("用户账户已启用。", "success")
        return redirect(url_for("abac.permission_management_page"))

    except SQLAlchemyError as exc:
        db.session.rollback()
        _record_admin_audit(
            operation_type="用户账户启用",
            detail=f"启用用户账户失败：user_id={user_id}，原因：{exc}",
            is_success=False,
        )
        db.session.commit()

        flash("启用用户账户失败，请稍后重试。", "danger")
        return redirect(url_for("abac.permission_management_page"))


@abac_bp.route("/abac/files/levels", methods=["GET"])
@admin_required
def file_level_management_page():
    """
    功能：文件密级设置页，展示并修改文件密级。
    参数：
        无。
    返回值：
        Response: 文件密级管理页面。
    注意事项：
        仅显示最新版本记录，修改时同步作用于同分组全部历史版本。
    """
    files = (
        SecretFile.query.filter_by(is_latest=True, is_deleted=False)
        .order_by(SecretFile.uploaded_at.desc())
        .all()
    )
    return render_template(
        "file_level_management.html",
        files=files,
        file_levels=["秘密", "机密", "绝密"],
        active_nav="admin",
        current_path=request.path,
    )


@abac_bp.route("/abac/files/<string:file_group_id>/level", methods=["POST"])
@admin_required
def update_file_level(file_group_id: str):
    """
    功能：管理员修改文件密级。
    参数：
        file_group_id (str): 文件分组ID。
    返回值：
        Response: 重定向回文件密级设置页。
    注意事项：
        会同步更新该分组所有版本的 level 字段。
    """
    new_level = request.form.get("level", "").strip()
    latest_file = SecretFile.query.filter_by(file_group_id=file_group_id, is_latest=True).first()

    try:
        if latest_file is None:
            flash("目标文件不存在。", "warning")
            return redirect(url_for("abac.file_level_management_page"))

        ABACService.validate_file_level(new_level)

        old_level = latest_file.level
        if old_level == new_level:
            flash("文件密级未发生变化。", "info")
            return redirect(url_for("abac.file_level_management_page"))

        updated_count = (
            SecretFile.query.filter_by(file_group_id=file_group_id)
            .update({SecretFile.level: new_level}, synchronize_session=False)
        )

        _record_admin_audit(
            operation_type="文件密级变更",
            detail=(
                f"管理员将文件 {latest_file.name} 密级由 {old_level} "
                f"调整为 {new_level}，影响版本数={updated_count}。"
            ),
            is_success=True,
            file_id=int(latest_file.id),
        )
        db.session.commit()

        flash("文件密级更新成功。", "success")
        return redirect(url_for("abac.file_level_management_page"))

    except (ABACServiceError, SQLAlchemyError) as exc:
        db.session.rollback()
        _record_admin_audit(
            operation_type="文件密级变更",
            detail=f"文件分组 {file_group_id} 密级变更失败：{exc}",
            is_success=False,
            file_id=int(latest_file.id) if latest_file is not None else None,
        )
        db.session.commit()

        flash(str(exc), "danger")
        return redirect(url_for("abac.file_level_management_page"))
