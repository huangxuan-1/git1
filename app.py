"""
app.py
功能：项目启动入口文件。
注意事项：
1. 应用工厂位于 app 包中。
2. 该文件仅负责读取运行参数并启动 Flask 服务。
"""

import os

from app import create_app


def _safe_int(value: str | None, default: int) -> int:
    """
    功能：将字符串安全转换为整数。
    参数：
        value (str | None): 待转换的字符串。
        default (int): 转换失败时返回的默认值。
    返回值：
        int: 转换后的整数。
    注意事项：
        用于避免端口号等环境变量格式错误导致程序崩溃。
    """
    try:
        return int(value) if value is not None else default
    except (TypeError, ValueError):
        return default


app = create_app()

if __name__ == "__main__":
    flask_host = os.getenv("FLASK_HOST", "127.0.0.1")
    flask_port = _safe_int(os.getenv("FLASK_PORT"), 5000)
    flask_debug = os.getenv("FLASK_DEBUG", "True").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    app.run(host=flask_host, port=flask_port, debug=flask_debug)
