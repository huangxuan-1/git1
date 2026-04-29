"""
tests/module12_performance_check.py
功能：模块12性能基准脚本（页面响应 + 文件上传下载吞吐）。
执行方式：
    python -X faulthandler tests/module12_performance_check.py
可选环境变量：
    MODULE12_PERF_FILE_MB=2
    MODULE12_PERF_PAGE_MAX_MS=1500
    MODULE12_PERF_MIN_MBPS=0.5
    MODULE12_PERF_PAGE_ROUNDS=5
注意事项：
1. 依赖本地 MySQL 与已配置环境变量。
2. 脚本会创建并清理 module12_performance_* 测试数据。
"""

from __future__ import annotations

import io
import os
import statistics
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app import create_app
from app.models import SecretFile
from extensions import db

TEST_FILE_NAME = "module12_performance_payload.bin"
FILE_SIZE_MB = max(1, int(os.getenv("MODULE12_PERF_FILE_MB", "2")))
PAGE_MAX_MS = float(os.getenv("MODULE12_PERF_PAGE_MAX_MS", "1500"))
THROUGHPUT_MIN_MBPS = float(os.getenv("MODULE12_PERF_MIN_MBPS", "0.5"))
PAGE_ROUNDS = max(3, int(os.getenv("MODULE12_PERF_PAGE_ROUNDS", "5")))
TEST_CSRF_TOKEN = "test-csrf-token"


def _set_admin_session(client) -> None:
    """
    功能：向测试客户端注入管理员会话。
    参数：
        client: Flask 测试客户端。
    返回值：
        None
    注意事项：
        使用默认管理员 ID=1 场景。
    """
    with client.session_transaction() as sess:
        sess["account_id"] = 1
        sess["account_type"] = "administrator"
        sess["account_name"] = "admin"
        sess["username"] = "admin"
        sess["security_level"] = "管理员"
        sess["permissions"] = ["system:admin"]
        sess["csrf_token"] = TEST_CSRF_TOKEN


def _cleanup_test_data() -> None:
    """
    功能：清理性能测试文件与密钥。
    参数：
        无。
    返回值：
        None
    注意事项：
        仅清理 module12_performance_* 前缀文件。
    """
    stale_files = SecretFile.query.filter(SecretFile.name == TEST_FILE_NAME).all()
    stale_ids = [int(item.id) for item in stale_files]

    if stale_files:
        group_ids = list({item.file_group_id for item in stale_files})
        SecretFile.query.filter(SecretFile.file_group_id.in_(group_ids)).delete(
            synchronize_session=False
        )
        db.session.commit()

    for stale_id in stale_ids:
        key_path = PROJECT_ROOT / "keys" / f"{stale_id}.key"
        if key_path.exists():
            key_path.unlink()


def _measure_page_avg_ms(client, path: str, rounds: int) -> float:
    """
    功能：测量页面平均响应时间。
    参数：
        client: Flask 测试客户端。
        path (str): 路径。
        rounds (int): 采样次数。
    返回值：
        float: 平均耗时（毫秒）。
    注意事项：
        若任一请求非 200，会抛出 AssertionError。
    """
    samples: list[float] = []
    for _ in range(rounds):
        start_time = time.perf_counter()
        response = client.get(path, follow_redirects=True)
        elapsed_ms = (time.perf_counter() - start_time) * 1000
        assert response.status_code == 200
        samples.append(elapsed_ms)
    return statistics.mean(samples)


def main() -> None:
    """
    功能：执行模块12性能测试。
    参数：
        无。
    返回值：
        None
    注意事项：
        任一步失败会抛出 AssertionError。
    """
    app = create_app()

    with app.app_context():
        _cleanup_test_data()

    client = app.test_client()
    _set_admin_session(client)

    page_metrics = {
        "/dashboard": _measure_page_avg_ms(client, "/dashboard", PAGE_ROUNDS),
        "/files": _measure_page_avg_ms(client, "/files", PAGE_ROUNDS),
        "/audit/logs": _measure_page_avg_ms(client, "/audit/logs", PAGE_ROUNDS),
    }

    for path, avg_ms in page_metrics.items():
        assert avg_ms <= PAGE_MAX_MS, (
            f"页面性能不达标：{path} 平均 {avg_ms:.2f}ms，阈值 {PAGE_MAX_MS:.2f}ms"
        )

    payload_size_bytes = FILE_SIZE_MB * 1024 * 1024
    payload = os.urandom(payload_size_bytes)

    upload_start = time.perf_counter()
    upload_response = client.post(
        "/files/upload",
        data={
            "csrf_token": TEST_CSRF_TOKEN,
            "level": "秘密",
            "secret_file": (io.BytesIO(payload), TEST_FILE_NAME),
        },
        content_type="multipart/form-data",
        follow_redirects=False,
    )
    upload_elapsed = max(1e-9, time.perf_counter() - upload_start)
    assert upload_response.status_code == 302
    upload_mbps = payload_size_bytes / upload_elapsed / (1024 * 1024)

    with app.app_context():
        latest_file = SecretFile.query.filter_by(name=TEST_FILE_NAME, is_latest=True).first()
        assert latest_file is not None
        file_group_id = latest_file.file_group_id

    download_start = time.perf_counter()
    download_response = client.get(
        f"/files/{file_group_id}/download",
        follow_redirects=False,
    )
    download_elapsed = max(1e-9, time.perf_counter() - download_start)
    assert download_response.status_code == 200
    assert download_response.data == payload
    download_mbps = payload_size_bytes / download_elapsed / (1024 * 1024)

    assert upload_mbps >= THROUGHPUT_MIN_MBPS, (
        f"上传吞吐不达标：{upload_mbps:.2f} MB/s，阈值 {THROUGHPUT_MIN_MBPS:.2f} MB/s"
    )
    assert download_mbps >= THROUGHPUT_MIN_MBPS, (
        f"下载吞吐不达标：{download_mbps:.2f} MB/s，阈值 {THROUGHPUT_MIN_MBPS:.2f} MB/s"
    )

    with app.app_context():
        _cleanup_test_data()

    print(
        "[MODULE12] performance check passed | "
        f"pages(ms): dashboard={page_metrics['/dashboard']:.2f}, "
        f"files={page_metrics['/files']:.2f}, audit={page_metrics['/audit/logs']:.2f} | "
        f"throughput(MB/s): upload={upload_mbps:.2f}, download={download_mbps:.2f}"
    )


if __name__ == "__main__":
    main()
