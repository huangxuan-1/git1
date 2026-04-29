"""
extensions.py
功能：集中管理 Flask 扩展实例，避免跨模块循环导入问题。
注意事项：
1. 所有模型和脚本应统一从本文件导入 db。
2. 本文件仅负责扩展对象声明，不承担业务逻辑。
"""

from flask_sqlalchemy import SQLAlchemy

# 全局数据库对象，供应用工厂、模型层和脚本层统一使用。
db = SQLAlchemy()
