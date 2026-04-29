"""
tests/module5_runtime_check.py
功能：模块5运行级冒烟测试脚本（非正式单元测试）。
注意事项：
1. 用于快速验证指纹服务与路由链路是否可用。
2. 脚本可重复执行，不会破坏正式业务数据。
"""

import io
import sys
from pathlib import Path

import cv2
import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app import create_app
from app.models import AuditLog, BiometricData, User
from app.services.fingerprint_service import FingerprintVerificationService
from extensions import db
from utils.security_utils import hash_password


def build_fingerprint_image(style: str) -> bytes:
    """
    功能：生成测试用指纹图片字节流。
    参数：
        style (str): 图像风格标识（A/B）。
    返回值：
        bytes: PNG 编码后的图片字节流。
    注意事项：
        仅用于本地测试，不代表真实指纹分布。
    """
    canvas = np.full((360, 280), 255, dtype=np.uint8)

    if style == "A":
        for idx in range(16):
            y_pos = 40 + idx * 16
            cv2.ellipse(canvas, (140, y_pos), (110, 30 + idx), 0, 10, 170, 0, 2)
        cv2.line(canvas, (120, 160), (120, 250), 0, 2)
        cv2.line(canvas, (120, 205), (160, 240), 0, 2)
    else:
        for idx in range(14):
            x_pos = 30 + idx * 16
            cv2.ellipse(canvas, (x_pos, 170), (28 + idx, 118), 90, 15, 165, 0, 2)
        cv2.line(canvas, (170, 100), (230, 160), 0, 2)
        cv2.line(canvas, (200, 160), (245, 220), 0, 2)

    image_bgr = cv2.cvtColor(canvas, cv2.COLOR_GRAY2BGR)
    ok, encoded = cv2.imencode(".png", image_bgr)
    if not ok:
        raise RuntimeError("测试图像编码失败")
    return encoded.tobytes()


def smoke_test_service() -> None:
    """
    功能：验证指纹服务层提取、加解密和自匹配。
    参数：
        无。
    返回值：
        None
    注意事项：
        若失败会直接抛出异常并终止脚本。
    """
    image_a_bytes = build_fingerprint_image("A")
    image_bgr = FingerprintVerificationService.decode_file_image(image_a_bytes)

    template = FingerprintVerificationService.build_template(image_bgr)
    key = "0123456789abcdef0123456789abcdef".encode("utf-8")
    encrypted = FingerprintVerificationService.encrypt_template(template, key)
    decrypted = FingerprintVerificationService.decrypt_template(encrypted, key)

    result = FingerprintVerificationService.match_templates(
        template,
        decrypted,
        threshold=0.7,
    )

    print("[SERVICE] minutiae:", len(template.minutiae))
    print("[SERVICE] self_match_score:", f"{result.score:.6f}")
    print("[SERVICE] self_match_pass:", result.is_match)


def smoke_test_route() -> None:
    """
    功能：验证指纹路由注册、上传注册和比对流程。
    参数：
        无。
    返回值：
        None
    注意事项：
        使用 Flask test_client 执行，不需要启动 Web 服务。
    """
    app = create_app()

    with app.app_context():
        client = app.test_client()

        response_unauth = client.get("/fingerprint", follow_redirects=False)
        print("[ROUTE] unauth_status:", response_unauth.status_code)
        print("[ROUTE] unauth_location:", response_unauth.headers.get("Location", ""))

        test_username = "module5_fp_user"
        test_user = User.query.filter_by(username=test_username).first()
        if test_user is None:
            test_user = User(
                name="模块五测试用户",
                username=test_username,
                password=hash_password("Fp@123456"),
                security_level="初级",
                status="启用",
                login_fail_count=0,
            )
            db.session.add(test_user)
            db.session.commit()

        client.post(
            "/login",
            data={
                "account_type": "customer",
                "username": test_username,
                "password": "Fp@123456",
            },
            follow_redirects=False,
        )

        image_a = build_fingerprint_image("A")
        image_b = build_fingerprint_image("B")

        register_response = client.post(
            "/fingerprint/register",
            data={
                "fingerprint_image_file": (io.BytesIO(image_a), "finger_a.png"),
            },
            content_type="multipart/form-data",
            follow_redirects=True,
        )
        print("[ROUTE] register_status:", register_response.status_code)

        record = BiometricData.query.filter_by(
            customer_id=test_user.id,
            feature_type="指纹",
        ).first()
        print("[ROUTE] record_exists:", record is not None)

        verify_same_response = client.post(
            "/fingerprint/verify",
            data={
                "verify_fingerprint_image_file": (
                    io.BytesIO(image_a),
                    "finger_same.png",
                ),
            },
            content_type="multipart/form-data",
            follow_redirects=True,
        )
        verify_diff_response = client.post(
            "/fingerprint/verify",
            data={
                "verify_fingerprint_image_file": (
                    io.BytesIO(image_b),
                    "finger_diff.png",
                ),
            },
            content_type="multipart/form-data",
            follow_redirects=True,
        )

        print("[ROUTE] verify_same_status:", verify_same_response.status_code)
        print("[ROUTE] verify_diff_status:", verify_diff_response.status_code)

        print(
            "[ROUTE] verify_same_pass_text:",
            "指纹比对通过" in verify_same_response.get_data(as_text=True),
        )
        print(
            "[ROUTE] verify_diff_fail_text:",
            "指纹比对未通过" in verify_diff_response.get_data(as_text=True),
        )

        audit_count = AuditLog.query.filter(
            AuditLog.customer_id == test_user.id,
            AuditLog.operation_type.in_(["指纹注册", "指纹更新", "指纹比对"]),
        ).count()
        print("[ROUTE] fingerprint_audit_count:", int(audit_count))


if __name__ == "__main__":
    smoke_test_service()
    smoke_test_route()
