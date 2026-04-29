"""
app/services/audit_log_service.py
功能：封装模块11审计日志防篡改、查询过滤与导出辅助能力。
注意事项：
1. 审计日志一旦写入仅允许新增，禁止更新/删除。
2. 通过 MySQL 触发器在数据库层拦截更新与删除行为。
"""

from __future__ import annotations

import hashlib
import socket
from datetime import datetime, timedelta

from flask import has_request_context, request
from sqlalchemy import or_, text
from sqlalchemy.exc import SQLAlchemyError

from app.models import AuditLog
from extensions import db


def _get_local_ip() -> str:
    """
    功能：获取本机非回环 IPv4 地址。
    参数：
        无。
    返回值：
        str: 本机局域网 IP 地址，失败时返回 "unknown"。
    注意事项：
        用于本地开发环境，避免显示 127.0.0.1。
    """
    try:
        # 创建 UDP socket 连接公共地址（不发送数据）
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            if local_ip and not local_ip.startswith("127."):
                return local_ip
    except Exception:
        pass
    return "unknown"


class AuditLogServiceError(Exception):
    """
    功能：审计日志服务异常。
    参数：
        message (str): 异常描述。
    返回值：
        无。
    注意事项：
        供路由层捕获并输出友好提示。
    """


class AuditLogService:
    """
    功能：审计日志服务类。
    参数：
        无。
    返回值：
        无。
    注意事项：
        统一提供追加日志、查询过滤、防篡改触发器维护能力。
    """

    UPDATE_TRIGGER_NAME = "trg_audit_log_no_update"
    DELETE_TRIGGER_NAME = "trg_audit_log_no_delete"

    @staticmethod
    def get_client_ip() -> str:
        """
        功能：读取当前请求客户端 IP。
        参数：
            无。
        返回值：
            str: 客户端 IP。
        注意事项：
            优先使用 X-Forwarded-For 首地址。
            本地开发环境返回本机真实 IP（非回环地址）。
        """
        if not has_request_context():
            return _get_local_ip()

        forwarded_for = request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        if forwarded_for and not forwarded_for.startswith("127."):
            return forwarded_for[:50]

        remote_addr = request.remote_addr or ""
        # 如果是本地回环地址，返回本机真实 IP
        if remote_addr.startswith("127.") or remote_addr == "localhost":
            return _get_local_ip()

        return (remote_addr or "unknown")[:50]

    @staticmethod
    def append_log(
        operation_type: str,
        detail: str,
        is_success: bool,
        customer_id: str | None = None,
        administrator_id: int | None = None,
        file_id: int | None = None,
        ip_address: str | None = None,
    ) -> AuditLog:
        """
        功能：追加一条审计日志。
        参数：
            operation_type (str): 操作类型。
            detail (str): 操作详情。
            is_success (bool): 操作是否成功。
            customer_id (str | None): 用户ID。
            administrator_id (int | None): 管理员ID。
            file_id (int | None): 文件记录ID。
            ip_address (str | None): 指定 IP，留空自动读取请求 IP。
        返回值：
            AuditLog: 新增的日志对象（尚未提交）。
        注意事项：
            事务提交由调用方控制。
        """
        log_item = AuditLog(
            customer_id=customer_id,
            administrator_id=administrator_id,
            file_id=file_id,
            ip_address=(ip_address or AuditLogService.get_client_ip())[:50],
            operation_type=(operation_type or "未知操作")[:50],
            detail=detail or "",
            is_success=bool(is_success),
        )
        db.session.add(log_item)
        return log_item

    @staticmethod
    def _trigger_exists(trigger_name: str) -> bool:
        """
        功能：判断触发器是否存在。
        参数：
            trigger_name (str): 触发器名称。
        返回值：
            bool: 存在返回 True。
        注意事项：
            依赖当前数据库连接上下文。
        """
        count_value = db.session.execute(
            text(
                "SELECT COUNT(1) "
                "FROM information_schema.TRIGGERS "
                "WHERE TRIGGER_SCHEMA = DATABASE() AND TRIGGER_NAME = :trigger_name"
            ),
            {"trigger_name": trigger_name},
        ).scalar()
        return int(count_value or 0) > 0

    @staticmethod
    def ensure_immutable_triggers() -> None:
        """
        功能：确保 audit_log 表更新/删除拦截触发器存在。
        参数：
            无。
        返回值：
            None
        注意事项：
            若数据库权限不足会抛出 AuditLogServiceError。
        """
        try:
            if not AuditLogService._trigger_exists(AuditLogService.UPDATE_TRIGGER_NAME):
                db.session.execute(
                    text(
                        "CREATE TRIGGER trg_audit_log_no_update "
                        "BEFORE UPDATE ON audit_log "
                        "FOR EACH ROW "
                        "SIGNAL SQLSTATE '45000' "
                        "SET MESSAGE_TEXT = 'audit_log 表禁止更新'"
                    )
                )

            if not AuditLogService._trigger_exists(AuditLogService.DELETE_TRIGGER_NAME):
                db.session.execute(
                    text(
                        "CREATE TRIGGER trg_audit_log_no_delete "
                        "BEFORE DELETE ON audit_log "
                        "FOR EACH ROW "
                        "SIGNAL SQLSTATE '45000' "
                        "SET MESSAGE_TEXT = 'audit_log 表禁止删除'"
                    )
                )

            db.session.commit()
        except SQLAlchemyError as exc:
            db.session.rollback()
            raise AuditLogServiceError(f"审计日志防篡改触发器初始化失败：{exc}") from exc

    @staticmethod
    def drop_immutable_triggers_if_exists() -> None:
        """
        功能：按需删除 audit_log 防篡改触发器。
        参数：
            无。
        返回值：
            None
        注意事项：
            主要用于升级脚本中临时回填历史哈希。
        """
        try:
            db.session.execute(text("DROP TRIGGER IF EXISTS trg_audit_log_no_update"))
            db.session.execute(text("DROP TRIGGER IF EXISTS trg_audit_log_no_delete"))
            db.session.commit()
        except SQLAlchemyError as exc:
            db.session.rollback()
            raise AuditLogServiceError(f"删除审计日志触发器失败：{exc}") from exc

    @staticmethod
    def parse_time_start(raw_text: str) -> datetime | None:
        """
        功能：解析起始时间文本。
        参数：
            raw_text (str): 时间文本。
        返回值：
            datetime | None: 解析后的起始时间。
        注意事项：
            支持 YYYY-MM-DD 与 YYYY-MM-DD HH:MM:SS。
        """
        normalized = (raw_text or "").strip()
        if not normalized:
            return None

        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
            try:
                return datetime.strptime(normalized, fmt)
            except ValueError:
                continue
        return None

    @staticmethod
    def parse_time_end_exclusive(raw_text: str) -> datetime | None:
        """
        功能：解析结束时间并转换为右开区间终点。
        参数：
            raw_text (str): 时间文本。
        返回值：
            datetime | None: 右开区间终点。
        注意事项：
            日期输入会自动 +1 天，秒级输入自动 +1 秒。
        """
        normalized = (raw_text or "").strip()
        if not normalized:
            return None

        try:
            parsed = datetime.strptime(normalized, "%Y-%m-%d %H:%M:%S")
            return parsed + timedelta(seconds=1)
        except ValueError:
            pass

        try:
            parsed = datetime.strptime(normalized, "%Y-%m-%d")
            return parsed + timedelta(days=1)
        except ValueError:
            return None

    @staticmethod
    def apply_filters(
        base_query,
        start_time_text: str,
        end_time_text: str,
        operator_id_text: str,
        operation_type_text: str,
        file_id_text: str,
    ):
        """
        功能：对审计日志查询追加过滤条件。
        参数：
            base_query: 原始查询对象。
            start_time_text (str): 起始时间文本。
            end_time_text (str): 结束时间文本。
            operator_id_text (str): 操作者ID文本。
            operation_type_text (str): 操作类型文本。
            file_id_text (str): 文件ID文本。
        返回值：
            Query: 过滤后的查询对象。
        注意事项：
            非法输入将被忽略，不抛异常。
        """
        query = base_query

        start_at = AuditLogService.parse_time_start(start_time_text)
        if start_at is not None:
            query = query.filter(AuditLog.operation_time >= start_at)

        end_exclusive = AuditLogService.parse_time_end_exclusive(end_time_text)
        if end_exclusive is not None:
            query = query.filter(AuditLog.operation_time < end_exclusive)

        operator_text = (operator_id_text or "").strip()
        if operator_text:
            normalized_operator = operator_text.replace("管理员#", "管理员").replace("用户#", "用户")

            if normalized_operator.isdigit():
                admin_candidate = int(normalized_operator)
                query = query.filter(
                    or_(
                        AuditLog.customer_id == normalized_operator,
                        AuditLog.administrator_id == admin_candidate,
                    )
                )
            elif normalized_operator.startswith("管理员"):
                suffix_text = normalized_operator.replace("管理员", "", 1).strip()
                if suffix_text == "1" or not suffix_text:
                    query = query.filter(AuditLog.administrator_id.isnot(None))
                elif suffix_text.isdigit():
                    query = query.filter(AuditLog.administrator_id == int(suffix_text))
            elif normalized_operator.startswith("用户"):
                suffix_text = normalized_operator.replace("用户", "", 1).strip()
                if suffix_text.isdigit():
                    query = query.filter(AuditLog.customer_id == suffix_text)
                elif not suffix_text:
                    query = query.filter(AuditLog.customer_id.isnot(None))

        operation_type = (operation_type_text or "").strip()
        if operation_type:
            query = query.filter(AuditLog.operation_type.ilike(f"%{operation_type}%"))

        file_text = (file_id_text or "").strip()
        if file_text.isdigit():
            query = query.filter(AuditLog.file_id == int(file_text))

        return query

    @staticmethod
    def actor_label(log_item: AuditLog) -> str:
        """
        功能：构造审计日志操作者展示文本。
        参数：
            log_item (AuditLog): 日志对象。
        返回值：
            str: 操作者展示文本。
        注意事项：
            优先展示管理员ID，其次用户ID。
        """
        if log_item.administrator_id is not None:
            return "管理员#1"
        if log_item.customer_id is not None:
            return str(log_item.customer_id)
        return "系统"

    @staticmethod
    def _build_hash_payload(log_item: AuditLog, prev_hash: str) -> str:
        """
        功能：生成审计日志哈希原文。
        参数：
            log_item (AuditLog): 日志对象。
            prev_hash (str): 前序日志哈希。
        返回值：
            str: 哈希原文。
        注意事项：
            字段拼接顺序必须固定，保证哈希稳定。
        """
        operation_time_text = ""
        if log_item.operation_time is not None:
            operation_time_text = log_item.operation_time.strftime("%Y-%m-%d %H:%M:%S")

        return "|".join(
            [
                str(log_item.customer_id or ""),
                str(log_item.administrator_id or ""),
                str(log_item.file_id or ""),
                log_item.ip_address or "",
                operation_time_text,
                log_item.operation_type or "",
                log_item.detail or "",
                "1" if bool(log_item.is_success) else "0",
                prev_hash or "",
            ]
        )

    @staticmethod
    def calculate_entry_hash(log_item: AuditLog, prev_hash: str) -> str:
        """
        功能：计算日志当前哈希。
        参数：
            log_item (AuditLog): 日志对象。
            prev_hash (str): 前序哈希。
        返回值：
            str: SHA-256 十六进制哈希。
        注意事项：
            与模型层 before_insert 逻辑保持一致。
        """
        payload = AuditLogService._build_hash_payload(log_item, prev_hash)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    @staticmethod
    def verify_log_integrity(log_item: AuditLog, previous_log: AuditLog | None = None) -> bool:
        """
        功能：校验单条日志哈希完整性与链路一致性。
        参数：
            log_item (AuditLog): 待校验日志。
            previous_log (AuditLog | None): 前一条日志。
        返回值：
            bool: 校验通过返回 True。
        注意事项：
            若存在上一条日志，将额外校验 prev_hash 链接关系。
        """
        prev_hash = log_item.prev_hash or ""
        expected_hash = AuditLogService.calculate_entry_hash(log_item, prev_hash)
        if expected_hash != (log_item.entry_hash or ""):
            return False

        if previous_log is None:
            return True

        return (previous_log.entry_hash or "") == prev_hash
