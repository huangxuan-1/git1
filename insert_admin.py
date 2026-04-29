"""
insert_admin.py
功能：插入默认管理员账号。
默认账号：
1. 用户名：admin
2. 密码：admin123
注意事项：
1. 密码不会明文入库，使用 bcrypt 哈希后保存。
2. 若用户名已存在，脚本不会重复插入。
"""

from sqlalchemy.exc import SQLAlchemyError

from app import create_app
from app.models import Administrator
from extensions import db
from utils.security_utils import PasswordSecurityError, hash_password


def insert_default_admin() -> None:
    """
    功能：插入系统默认管理员账号。
    参数：
        无。
    返回值：
        None
    注意事项：
        若账号已存在，函数直接返回并提示，无重复写入。
    """
    app = create_app()

    try:
        with app.app_context():
            existing_admin = Administrator.query.filter_by(username="admin").first()
            if existing_admin is not None:
                print("默认管理员已存在，跳过插入。")
                return

            hashed_password = hash_password("admin123")
            admin_user = Administrator(
                id=1,
                name="系统管理员",
                username="admin",
                password=hashed_password,
                login_attempts=0,
                account_status=0,
                login_fail_count=0,
            )

            db.session.add(admin_user)
            db.session.commit()
            print("默认管理员创建成功，用户名：admin。")
    except (PasswordSecurityError, SQLAlchemyError) as exc:
        db.session.rollback()
        print(f"默认管理员创建失败：{exc}")
        raise
    except Exception as exc:
        db.session.rollback()
        print(f"发生未知错误：{exc}")
        raise


def main() -> None:
    """
    功能：默认管理员插入脚本入口。
    参数：
        无。
    返回值：
        None
    注意事项：
        运行前请先执行 init_db.py 确保数据表已创建。
    """
    try:
        insert_default_admin()
    except Exception:
        raise


if __name__ == "__main__":
    main()
