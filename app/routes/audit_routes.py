"""
app/routes/audit_routes.py
功能：实现模块11防篡改审计日志的查看、详情、查询与导出。
注意事项：
1. 仅管理员可访问。
2. 列表分页固定每页 20 条。
"""

from __future__ import annotations

import csv
import io
import re
from urllib.parse import urlencode

from flask import Blueprint, Response, flash, redirect, render_template, request, url_for

from app.models import AuditLog
from app.routes.auth_routes import admin_required
from app.services.audit_log_service import AuditLogService


audit_bp = Blueprint("audit", __name__)

PAGE_SIZE = 20

DATETIME_FILTER_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}(?: \d{2}:\d{2}:\d{2})?$")
OPERATOR_FILTER_PATTERN = re.compile(r"^[0-9\u4e00-\u9fa5#]*$")
OPERATION_TYPE_FILTER_PATTERN = re.compile(r"^[\u4e00-\u9fa5]*$")
FILE_ID_FILTER_PATTERN = re.compile(r"^[0-9]*$")


def _normalize_and_validate_filters(raw_filters: dict[str, str]) -> dict[str, str]:
    """
    功能：规范化并校验审计筛选输入。
    参数：
        raw_filters (dict[str, str]): 原始筛选参数。
    返回值：
        dict[str, str]: 校验后的筛选参数。
    注意事项：
        非法输入将清空并给出提示，避免无效参数影响查询。
    """
    start_time = (raw_filters.get("start_time") or "").strip()
    end_time = (raw_filters.get("end_time") or "").strip()
    operator_id = (raw_filters.get("operator_id") or "").strip()
    operation_type = (raw_filters.get("operation_type") or "").strip()
    file_id = (raw_filters.get("file_id") or "").strip()

    if start_time and not DATETIME_FILTER_PATTERN.fullmatch(start_time):
        flash("开始时间格式非法，请使用 YYYY-MM-DD 或 YYYY-MM-DD HH:MM:SS。", "danger")
        start_time = ""
    elif start_time and AuditLogService.parse_time_start(start_time) is None:
        flash("开始时间无效，请输入合法日期时间。", "danger")
        start_time = ""

    if end_time and not DATETIME_FILTER_PATTERN.fullmatch(end_time):
        flash("结束时间格式非法，请使用 YYYY-MM-DD 或 YYYY-MM-DD HH:MM:SS。", "danger")
        end_time = ""
    elif end_time and AuditLogService.parse_time_end_exclusive(end_time) is None:
        flash("结束时间无效，请输入合法日期时间。", "danger")
        end_time = ""

    if operator_id and not OPERATOR_FILTER_PATTERN.fullmatch(operator_id):
        flash("操作者仅支持数字、中文和#。", "danger")
        operator_id = ""

    if operation_type and not OPERATION_TYPE_FILTER_PATTERN.fullmatch(operation_type):
        flash("操作类型仅支持中文。", "danger")
        operation_type = ""

    if file_id and not FILE_ID_FILTER_PATTERN.fullmatch(file_id):
        flash("文件ID仅支持数字。", "danger")
        file_id = ""

    return {
        "start_time": start_time,
        "end_time": end_time,
        "operator_id": operator_id,
        "operation_type": operation_type,
        "file_id": file_id,
    }


def _render_audit_log_list_page():
    """
    功能：审计日志列表页。
    参数：
        无。
    返回值：
        Response: 审计日志列表页面。
    注意事项：
        支持按时间、操作者、操作类型、文件ID过滤。
    """
    filters = _normalize_and_validate_filters(
        {
            "start_time": request.args.get("start_time", ""),
            "end_time": request.args.get("end_time", ""),
            "operator_id": request.args.get("operator_id", ""),
            "operation_type": request.args.get("operation_type", ""),
            "file_id": request.args.get("file_id", ""),
        }
    )
    page_text = request.args.get("page", "1")

    try:
        page = max(1, int(page_text))
    except ValueError:
        page = 1

    base_query = AuditLog.query
    filtered_query = AuditLogService.apply_filters(
        base_query=base_query,
        start_time_text=filters["start_time"],
        end_time_text=filters["end_time"],
        operator_id_text=filters["operator_id"],
        operation_type_text=filters["operation_type"],
        file_id_text=filters["file_id"],
    )

    ordered_query = filtered_query.order_by(
        AuditLog.operation_time.desc(),
        AuditLog.id.desc(),
    )
    pagination = ordered_query.paginate(page=page, per_page=PAGE_SIZE, error_out=False)
    if page > 1 and pagination.total > 0 and not pagination.items:
        page = 1
        pagination = ordered_query.paginate(page=1, per_page=PAGE_SIZE, error_out=False)

    log_rows: list[dict[str, object]] = []
    for item in pagination.items:
        log_rows.append(
            {
                "log": item,
                "actor": AuditLogService.actor_label(item),
            }
        )

    operation_types = [
        row[0]
        for row in AuditLog.query.with_entities(AuditLog.operation_type)
        .filter(AuditLog.operation_type.isnot(None))
        .distinct()
        .order_by(AuditLog.operation_type.asc())
        .limit(200)
        .all()
        if row[0]
    ]

    export_query = urlencode(
        {
            "start_time": filters["start_time"],
            "end_time": filters["end_time"],
            "operator_id": filters["operator_id"],
            "operation_type": filters["operation_type"],
            "file_id": filters["file_id"],
        }
    )

    return render_template(
        "audit_log_list.html",
        log_rows=log_rows,
        pagination=pagination,
        page_size=PAGE_SIZE,
        filters=filters,
        operation_types=operation_types,
        export_query=export_query,
        active_nav="audit",
        current_path=request.path,
    )


@audit_bp.route("/audit", methods=["GET"])
@admin_required
def audit_home_page():
    """
    功能：审计日志导航入口页。
    参数：
        无。
    返回值：
        Response: 审计日志列表页面。
    注意事项：
        左侧导航"审计日志"统一跳转到该路由。
    """
    return _render_audit_log_list_page()


@audit_bp.route("/audit/logs", methods=["GET"])
@admin_required
def audit_log_list_page():
    """
    功能：审计日志列表页（兼容旧路由）。
    参数：
        无。
    返回值：
        Response: 审计日志列表页面。
    注意事项：
        保留旧路由避免外部链接失效。
    """
    return _render_audit_log_list_page()


@audit_bp.route("/audit/logs/<int:log_id>", methods=["GET"])
@admin_required
def audit_log_detail_page(log_id: int):
    """
    功能：审计日志详情页。
    参数：
        log_id (int): 日志ID。
    返回值：
        Response: 审计日志详情页面。
    注意事项：
        页面展示哈希链并执行单条完整性校验。
    """
    log_item = AuditLog.query.filter_by(id=log_id).first()
    if log_item is None:
        flash("日志不存在。", "warning")
        return redirect(url_for("audit.audit_log_list_page"))

    previous_log = (
        AuditLog.query.filter(AuditLog.id < log_id)
        .order_by(AuditLog.id.desc())
        .first()
    )
    integrity_ok = AuditLogService.verify_log_integrity(log_item, previous_log=previous_log)

    back_url = request.args.get("next", "").strip() or url_for("audit.audit_log_list_page")
    if not back_url.startswith("/"):
        back_url = url_for("audit.audit_log_list_page")

    return render_template(
        "audit_log_detail.html",
        log_item=log_item,
        actor_label=AuditLogService.actor_label(log_item),
        integrity_ok=integrity_ok,
        back_url=back_url,
        active_nav="audit",
        current_path=request.path,
    )


@audit_bp.route("/audit/logs/export", methods=["GET"])
@admin_required
def audit_log_export_csv():
    """
    功能：导出审计日志 CSV。
    参数：
        无。
    返回值：
        Response: CSV 下载响应。
    注意事项：
        导出条件与列表页过滤条件保持一致。
    """
    filters = _normalize_and_validate_filters(
        {
            "start_time": request.args.get("start_time", ""),
            "end_time": request.args.get("end_time", ""),
            "operator_id": request.args.get("operator_id", ""),
            "operation_type": request.args.get("operation_type", ""),
            "file_id": request.args.get("file_id", ""),
        }
    )

    filtered_query = AuditLogService.apply_filters(
        base_query=AuditLog.query,
        start_time_text=filters["start_time"],
        end_time_text=filters["end_time"],
        operator_id_text=filters["operator_id"],
        operation_type_text=filters["operation_type"],
        file_id_text=filters["file_id"],
    )

    log_items = filtered_query.order_by(
        AuditLog.operation_time.desc(),
        AuditLog.id.desc(),
    ).all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        [
            "日志ID",
            "操作者ID",
            "IP地址",
            "操作时间",
            "操作类型",
            "文件ID",
            "操作结果",
            "详细信息",
            "前序哈希",
            "当前哈希",
        ]
    )

    for item in log_items:
        writer.writerow(
            [
                item.id,
                AuditLogService.actor_label(item),
                item.ip_address,
                item.operation_time.strftime("%Y-%m-%d %H:%M:%S") if item.operation_time else "",
                item.operation_type,
                item.file_id if item.file_id is not None else "",
                "成功" if item.is_success else "失败",
                item.detail,
                item.prev_hash,
                item.entry_hash,
            ]
        )

    csv_text = output.getvalue()
    output.close()

    return Response(
        csv_text,
        mimetype="text/csv; charset=utf-8",
        headers={"Content-Disposition": "attachment; filename=audit_logs.csv"},
    )
