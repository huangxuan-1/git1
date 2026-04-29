"""
app/services/abac_service.py
功能：提供模块10 ABAC（基于属性访问控制）策略能力。
注意事项：
1. 核心属性为用户安全级别与文件密级。
2. 管理员默认拥有全部访问与操作权限。
"""

from __future__ import annotations


class ABACServiceError(Exception):
    """
    功能：ABAC 服务异常类型。
    参数：
        message (str): 异常说明。
    返回值：
        无。
    注意事项：
        路由层可捕获后提示用户。
    """


class ABACService:
    """
    功能：封装 ABAC 权限判定规则。
    参数：
        无。
    返回值：
        无。
    注意事项：
        所有方法均为静态方法，无需实例化。
    """

    SECURITY_LEVEL_RANK = {
        "初级": 1,
        "中级": 2,
        "高级": 3,
        "管理员": 99,
    }
    FILE_LEVEL_RANK = {
        "秘密": 1,
        "机密": 2,
        "绝密": 3,
    }
    ALLOWED_SECURITY_LEVELS = {"初级", "中级", "高级"}
    ALLOWED_FILE_LEVELS = {"秘密", "机密", "绝密"}

    @staticmethod
    def normalize_security_level(account_type: str, security_level: str | None) -> str:
        """
        功能：标准化主体安全级别。
        参数：
            account_type (str): 主体类型（customer/administrator）。
            security_level (str | None): 原始安全级别。
        返回值：
            str: 标准化安全级别。
        注意事项：
            管理员统一映射为"管理员"。
        """
        if account_type == "administrator":
            return "管理员"
        return security_level if security_level in ABACService.ALLOWED_SECURITY_LEVELS else "初级"

    @staticmethod
    def can_access_file_level(account_type: str, security_level: str | None, file_level: str) -> bool:
        """
        功能：判断主体是否可访问指定文件密级。
        参数：
            account_type (str): 主体类型。
            security_level (str | None): 主体安全级别。
            file_level (str): 文件密级。
        返回值：
            bool: 允许访问返回 True。
        注意事项：
            若文件密级非法，默认拒绝访问。
        """
        if file_level not in ABACService.FILE_LEVEL_RANK:
            return False

        normalized_level = ABACService.normalize_security_level(account_type, security_level)
        user_rank = ABACService.SECURITY_LEVEL_RANK.get(normalized_level, 1)
        file_rank = ABACService.FILE_LEVEL_RANK[file_level]
        return user_rank >= file_rank

    @staticmethod
    def can_contain_level(parent_level: str, child_level: str) -> bool:
        """
        功能：判断父级密级是否可容纳子级密级。
        参数：
            parent_level (str): 父级密级。
            child_level (str): 子级密级。
        返回值：
            bool: 可容纳返回 True。
        注意事项：
            父级密级必须高于或等于子级密级。
        """
        if parent_level not in ABACService.FILE_LEVEL_RANK:
            return False
        if child_level not in ABACService.FILE_LEVEL_RANK:
            return False
        return ABACService.FILE_LEVEL_RANK[parent_level] >= ABACService.FILE_LEVEL_RANK[child_level]

    @staticmethod
    def allowed_file_levels(account_type: str, security_level: str | None) -> list[str]:
        """
        功能：返回主体可访问的文件密级集合。
        参数：
            account_type (str): 主体类型。
            security_level (str | None): 主体安全级别。
        返回值：
            list[str]: 可访问密级列表。
        注意事项：
            返回顺序固定为 秘密 -> 机密 -> 绝密。
        """
        levels = ["秘密", "机密", "绝密"]
        return [
            level
            for level in levels
            if ABACService.can_access_file_level(account_type, security_level, level)
        ]

    @staticmethod
    def validate_security_level(level: str) -> None:
        """
        功能：校验用户安全级别是否合法。
        参数：
            level (str): 安全级别。
        返回值：
            None
        注意事项：
            非法值会抛出 ABACServiceError。
        """
        if level not in ABACService.ALLOWED_SECURITY_LEVELS:
            raise ABACServiceError("安全级别参数非法。")

    @staticmethod
    def validate_file_level(level: str) -> None:
        """
        功能：校验文件密级是否合法。
        参数：
            level (str): 文件密级。
        返回值：
            None
        注意事项：
            非法值会抛出 ABACServiceError。
        """
        if level not in ABACService.ALLOWED_FILE_LEVELS:
            raise ABACServiceError("文件密级参数非法。")
