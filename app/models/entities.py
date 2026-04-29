"""
app/models/entities.py
功能：定义系统五张核心数据库表对应的 SQLAlchemy ORM 模型。
注意事项：
1. 表名、字段名、数据类型和约束严格对齐论文设计。
2. 审计日志模型在代码层强制只允许插入，禁止更新和删除。
"""

import hashlib
from datetime import datetime

from sqlalchemy import Boolean, CheckConstraint, Index, SmallInteger, UniqueConstraint, event, text
from sqlalchemy.dialects.mysql import BIGINT, DATETIME, ENUM, INTEGER, LONGBLOB, TEXT, VARCHAR
from sqlalchemy.orm import Session, relationship

from extensions import db


class AuditLogImmutableError(Exception):
    """
    功能：审计日志不可变异常。
    参数：
        message (str): 异常描述信息。
    返回值：
        无。
    注意事项：
        当代码尝试更新或删除审计日志时抛出该异常。
    """


class User(db.Model):
    """
    功能：用户模型，对应 customer 表。
    参数：
        无。
    返回值：
        无。
    注意事项：
        存储普通用户账号、权限级别和登录风控状态。
    """

    __tablename__ = "customer"
    __table_args__ = (
        Index("idx_customer_recycle", "is_deleted", "deleted_at"),
    )

    id = db.Column(VARCHAR(10), primary_key=True)
    name = db.Column(VARCHAR(50), nullable=False)
    username = db.Column(VARCHAR(50), nullable=False, unique=True, index=True)
    password = db.Column(VARCHAR(255), nullable=False)
    face_feature_encrypted = db.Column(TEXT, nullable=True)
    security_level = db.Column(
        ENUM("初级", "中级", "高级", name="customer_security_level_enum"),
        nullable=False,
        server_default=text("'初级'"),
    )
    login_attempts = db.Column(
        INTEGER(unsigned=False),
        nullable=False,
        server_default=text("0"),
    )
    account_status = db.Column(
        SmallInteger,
        nullable=False,
        server_default=text("0"),
    )
    status = db.Column(
        ENUM("启用", "禁用", name="customer_status_enum"),
        nullable=False,
        server_default=text("'启用'"),
    )
    login_fail_count = db.Column(
        INTEGER(unsigned=False),
        nullable=False,
        server_default=text("0"),
    )
    lock_until = db.Column(DATETIME(fsp=0), nullable=True)
    is_deleted = db.Column(Boolean, nullable=False, server_default=text("0"))
    deleted_at = db.Column(DATETIME(fsp=0), nullable=True)
    created_at = db.Column(
        DATETIME(fsp=0),
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP"),
    )
    updated_at = db.Column(
        DATETIME(fsp=0),
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP"),
    )

    biometric_records = relationship(
        "BiometricData",
        back_populates="customer",
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="select",
    )
    audit_logs = relationship(
        "AuditLog",
        back_populates="customer",
        passive_deletes=True,
        lazy="select",
    )


class Administrator(db.Model):
    """
    功能：管理员模型，对应 administrator 表。
    参数：
        无。
    返回值：
        无。
    注意事项：
        存储管理员账号信息与登录风控状态。
    """

    __tablename__ = "administrator"

    id = db.Column(INTEGER(unsigned=False), primary_key=True, autoincrement=True)
    name = db.Column(VARCHAR(50), nullable=False)
    username = db.Column(VARCHAR(50), nullable=False, unique=True, index=True)
    password = db.Column(VARCHAR(255), nullable=False)
    login_attempts = db.Column(
        INTEGER(unsigned=False),
        nullable=False,
        server_default=text("0"),
    )
    account_status = db.Column(
        SmallInteger,
        nullable=False,
        server_default=text("0"),
    )
    login_fail_count = db.Column(
        INTEGER(unsigned=False),
        nullable=False,
        server_default=text("0"),
    )
    lock_until = db.Column(DATETIME(fsp=0), nullable=True)
    created_at = db.Column(
        DATETIME(fsp=0),
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP"),
    )
    updated_at = db.Column(
        DATETIME(fsp=0),
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP"),
    )

    biometric_records = relationship(
        "BiometricData",
        back_populates="administrator",
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="select",
    )
    audit_logs = relationship(
        "AuditLog",
        back_populates="administrator",
        passive_deletes=True,
        lazy="select",
    )


class BiometricData(db.Model):
    """
    功能：生物特征模型，对应 biometric_data 表。
    参数：
        无。
    返回值：
        无。
    注意事项：
        1. customer_id 与 administrator_id 必须且只能有一个非空。
        2. 特征模板保存 AES-256 加密后的字符串。
    """

    __tablename__ = "biometric_data"
    __table_args__ = (
        CheckConstraint(
            "((customer_id IS NOT NULL AND administrator_id IS NULL) OR "
            "(customer_id IS NULL AND administrator_id IS NOT NULL))",
            name="ck_biometric_data_actor_only_one",
        ),
        UniqueConstraint(
            "customer_id",
            "feature_type",
            name="uq_biometric_data_customer_feature_type",
        ),
        UniqueConstraint(
            "administrator_id",
            "feature_type",
            name="uq_biometric_data_administrator_feature_type",
        ),
    )

    id = db.Column(INTEGER(unsigned=False), primary_key=True, autoincrement=True)
    customer_id = db.Column(
        VARCHAR(10),
        db.ForeignKey("customer.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    administrator_id = db.Column(
        INTEGER(unsigned=False),
        db.ForeignKey("administrator.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    feature_type = db.Column(
        ENUM("人脸", "指纹", name="biometric_feature_type_enum"),
        nullable=False,
    )
    feature_template = db.Column(TEXT, nullable=False)
    created_at = db.Column(
        DATETIME(fsp=0),
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP"),
    )
    updated_at = db.Column(
        DATETIME(fsp=0),
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP"),
    )

    customer = relationship("User", back_populates="biometric_records", lazy="joined")
    administrator = relationship(
        "Administrator",
        back_populates="biometric_records",
        lazy="joined",
    )


class SecretFile(db.Model):
    """
    功能：涉密文件模型，对应 secret_file 表。
    参数：
        无。
    返回值：
        无。
    注意事项：
        1. content 字段直接存储 AES-256 加密后的二进制文件内容。
        2. uploader_id 与 uploader_type 组合标识上传者身份。
    """

    __tablename__ = "secret_file"
    __table_args__ = (
        Index("idx_secret_file_uploader", "uploader_id", "uploader_type"),
        Index("idx_secret_file_group_latest", "file_group_id", "is_latest"),
        Index("idx_secret_file_parent_latest", "parent_id", "is_latest", "is_deleted"),
        Index("idx_secret_file_search", "name", "level", "uploaded_at"),
        Index("idx_secret_file_recycle", "is_deleted", "deleted_at"),
    )

    id = db.Column(INTEGER(unsigned=False), primary_key=True, autoincrement=True)
    file_group_id = db.Column(VARCHAR(64), nullable=False, index=True)
    name = db.Column(VARCHAR(255), nullable=False)
    parent_id = db.Column(
        INTEGER(unsigned=False),
        nullable=False,
        server_default=text("0"),
    )
    level = db.Column(
        ENUM("秘密", "机密", "绝密", name="secret_file_level_enum"),
        nullable=False,
        server_default=text("'秘密'"),
    )
    uploader_id = db.Column(VARCHAR(32), nullable=False)
    uploader_type = db.Column(
        ENUM("用户", "管理员", name="secret_file_uploader_type_enum"),
        nullable=False,
    )
    content = db.Column(LONGBLOB, nullable=False)
    mime_type = db.Column(
        VARCHAR(120),
        nullable=False,
        server_default=text("'application/octet-stream'"),
    )
    status = db.Column(
        ENUM("已加密", "未加密", name="secret_file_encrypt_status_enum"),
        nullable=False,
        server_default=text("'已加密'"),
    )
    is_folder = db.Column(Boolean, nullable=False, server_default=text("0"))
    major_version = db.Column(
        INTEGER(unsigned=False),
        nullable=False,
        server_default=text("1"),
    )
    minor_version = db.Column(
        INTEGER(unsigned=False),
        nullable=False,
        server_default=text("1"),
    )
    version = db.Column(VARCHAR(20), nullable=False, server_default=text("'1.1'"))
    is_latest = db.Column(Boolean, nullable=False, server_default=text("1"))
    is_deleted = db.Column(Boolean, nullable=False, server_default=text("0"))
    deleted_at = db.Column(DATETIME(fsp=0), nullable=True)
    deleted_by_id = db.Column(VARCHAR(32), nullable=True)
    deleted_by_type = db.Column(
        ENUM("用户", "管理员", name="secret_file_deleted_by_type_enum"),
        nullable=True,
    )
    original_path = db.Column(VARCHAR(255), nullable=True)
    file_size = db.Column(BIGINT(unsigned=False), nullable=False)
    uploaded_at = db.Column(
        DATETIME(fsp=0),
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP"),
    )


class AuditLog(db.Model):
    """
    功能：审计日志模型，对应 audit_log 表。
    参数：
        无。
    返回值：
        无。
    注意事项：
        1. 仅允许插入，不允许更新和删除。
        2. customer_id 和 administrator_id 均允许为空，
           以支持删除主体账号后保留历史日志。
    """

    __tablename__ = "audit_log"
    __table_args__ = (
        Index("idx_audit_log_operation_time", "operation_time"),
        Index("idx_audit_log_file_id", "file_id"),
        Index("idx_audit_log_entry_hash", "entry_hash"),
    )

    id = db.Column(INTEGER(unsigned=False), primary_key=True, autoincrement=True)
    customer_id = db.Column(
        VARCHAR(10),
        db.ForeignKey("customer.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    administrator_id = db.Column(
        INTEGER(unsigned=False),
        db.ForeignKey("administrator.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    file_id = db.Column(
        INTEGER(unsigned=False),
        nullable=True,
    )
    ip_address = db.Column(VARCHAR(50), nullable=False)
    operation_time = db.Column(
        DATETIME(fsp=0),
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP"),
    )
    operation_type = db.Column(VARCHAR(50), nullable=False)
    detail = db.Column(TEXT, nullable=False)
    is_success = db.Column(Boolean, nullable=False, server_default=text("1"))
    prev_hash = db.Column(
        VARCHAR(64),
        nullable=False,
        server_default=text("''"),
    )
    entry_hash = db.Column(
        VARCHAR(64),
        nullable=False,
        server_default=text("''"),
    )

    customer = relationship("User", back_populates="audit_logs", lazy="joined")
    administrator = relationship("Administrator", back_populates="audit_logs", lazy="joined")


def _build_audit_hash_payload(log_item: AuditLog, prev_hash: str) -> str:
    """
    功能：构造审计日志哈希原文。
    参数：
        log_item (AuditLog): 审计日志对象。
        prev_hash (str): 前序日志哈希。
    返回值：
        str: 待哈希文本。
    注意事项：
        字段顺序固定，保证哈希稳定可复算。
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


@event.listens_for(AuditLog, "before_insert")
def _populate_audit_hash_before_insert(mapper, connection, target: AuditLog) -> None:
    """
    功能：写入前为审计日志自动填充前序哈希与当前哈希。
    参数：
        mapper: SQLAlchemy mapper 对象。
        connection: 数据库连接。
        target (AuditLog): 待插入日志。
    返回值：
        None
    注意事项：
        采用哈希链方式增强篡改可检测性。
    """
    del mapper  # 未使用参数

    if target.operation_time is None:
        target.operation_time = datetime.now()

    prev_hash = connection.execute(
        text("SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1")
    ).scalar()
    prev_hash = str(prev_hash or "")

    target.prev_hash = prev_hash
    payload = _build_audit_hash_payload(target, prev_hash)
    target.entry_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()


@event.listens_for(Session, "before_flush")
def _prevent_audit_log_update_delete(session, flush_context, instances) -> None:
    """
    功能：在会话提交前阻断审计日志的更新与删除操作。
    参数：
        session (Session): 当前 SQLAlchemy 会话。
        flush_context: SQLAlchemy 刷新上下文。
        instances: 待刷新的实例集合。
    返回值：
        None
    注意事项：
        仅允许新增 AuditLog 记录；若检测到修改或删除则抛出异常。
    """
    for obj in session.dirty:
        if isinstance(obj, AuditLog):
            raise AuditLogImmutableError("audit_log 表仅允许插入，禁止更新。")

    for obj in session.deleted:
        if isinstance(obj, AuditLog):
            raise AuditLogImmutableError("audit_log 表仅允许插入，禁止删除。")
