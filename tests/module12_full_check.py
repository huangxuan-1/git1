"""
tests/module12_full_check.py
功能：模块12一键全局回归入口（数据库预升级 + 模块5/8/9/10/11 + 模块12整合/安全/性能）。
执行方式：
    python -X faulthandler tests/module12_full_check.py
注意事项：
1. 脚本会先执行数据库初始化与升级脚本，确保当前库结构兼容模块11。
2. 任一子脚本失败会立即停止并输出失败详情。
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

PRECHECK_SCRIPTS = [
    "init_db.py",
    "upgrade_module8.py",
    "upgrade_module9.py",
    "upgrade_module11.py",
    "upgrade_module13.py",
]

SCRIPT_ORDER = [
    "tests/module5_runtime_check.py",
    "tests/module8_runtime_check.py",
    "tests/module9_runtime_check.py",
    "tests/module10_runtime_check.py",
    "tests/module11_runtime_check.py",
    "tests/module12_integration_check.py",
    "tests/module12_security_check.py",
    "tests/module12_performance_check.py",
]


def _run_single(script_relative_path: str) -> None:
    """
    功能：执行单个子脚本并检查结果。
    参数：
        script_relative_path (str): 相对项目根目录的脚本路径。
    返回值：
        None
    注意事项：
        若子脚本失败会抛出 RuntimeError。
    """
    script_path = PROJECT_ROOT / script_relative_path
    if not script_path.exists():
        raise RuntimeError(f"测试脚本不存在：{script_relative_path}")

    command = [
        sys.executable,
        "-X",
        "faulthandler",
        str(script_path),
    ]
    result = subprocess.run(
        command,
        cwd=str(PROJECT_ROOT),
        text=True,
        capture_output=True,
        check=False,
    )

    print(f"[RUN] {script_relative_path}")
    if result.stdout.strip():
        print(result.stdout.strip())

    if result.returncode != 0:
        if result.stderr.strip():
            print(result.stderr.strip())
        raise RuntimeError(
            f"子脚本执行失败：{script_relative_path}（exit={result.returncode}）"
        )


def main() -> None:
    """
    功能：执行模块12全量回归。
    参数：
        无。
    返回值：
        None
    注意事项：
        全部通过后输出总成功标记。
    """
    for script in PRECHECK_SCRIPTS:
        _run_single(script)

    for script in SCRIPT_ORDER:
        _run_single(script)

    print("[MODULE12] full regression suite passed")


if __name__ == "__main__":
    main()
