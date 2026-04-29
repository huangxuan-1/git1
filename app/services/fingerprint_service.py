"""
app/services/fingerprint_service.py
功能：封装指纹图像预处理、minutiae 特征提取、模板加解密与匹配逻辑。
注意事项：
1. 本模块使用上传图片进行指纹识别，不依赖硬件采集器。
2. 模板中保存端点和分叉点，且入库前必须使用 AES-256-CBC 加密。
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass

import cv2
import numpy as np

from utils.aes_utils import AESCryptoError, AESUtil

# 指纹匹配阈值，分值越高越相似。
FINGERPRINT_MATCH_THRESHOLD = 0.7
# 最低 minutiae 数量，小于该值视为指纹质量不足。
MIN_MINUTIAE_COUNT = 10
# 同类型 minutiae 的最近距离阈值（像素），用于去除重复点。
MINUTIAE_MIN_DISTANCE = 8
# 匹配时单点最大容差（归一化空间）。
MINUTIAE_MATCH_DISTANCE = 0.22


class FingerprintServiceError(Exception):
    """
    功能：指纹服务统一异常类型。
    参数：
        message (str): 异常描述信息。
    返回值：
        无。
    注意事项：
        路由层捕获后可直接向用户返回友好提示。
    """


@dataclass
class FingerprintTemplate:
    """
    功能：表示指纹模板结构。
    参数：
        minutiae (list[dict[str, float | str]]): minutiae 点集合。
        width (int): 原始图像宽度。
        height (int): 原始图像高度。
    返回值：
        无。
    注意事项：
        minutiae 每项包含 x/y/type/angle 字段。
    """

    minutiae: list[dict[str, float | str]]
    width: int
    height: int


@dataclass
class FingerprintMatchResult:
    """
    功能：表示指纹匹配结果。
    参数：
        score (float): 匹配分值，范围 [0, 1]。
        is_match (bool): 是否匹配。
        matched_points (int): 匹配成功的 minutiae 数量。
        probe_points (int): 待验证模板点数量。
        enrolled_points (int): 已注册模板点数量。
    返回值：
        无。
    注意事项：
        is_match 依据 score 与阈值比较得出。
    """

    score: float
    is_match: bool
    matched_points: int
    probe_points: int
    enrolled_points: int


class FingerprintVerificationService:
    """
    功能：提供指纹模板生成、加密、解密与匹配能力。
    参数：
        无。
    返回值：
        无。
    注意事项：
        所有接口均可在路由层直接调用。
    """

    @staticmethod
    def decode_file_image(file_bytes: bytes) -> np.ndarray:
        """
        功能：将上传图片字节流解码为 BGR 图像。
        参数：
            file_bytes (bytes): 上传图片字节流。
        返回值：
            np.ndarray: BGR 图像。
        注意事项：
            仅支持 OpenCV 可解码的常见图片格式。
        """
        try:
            if not isinstance(file_bytes, bytes) or len(file_bytes) == 0:
                raise FingerprintServiceError("指纹图片为空，请重新上传。")

            np_bytes = np.frombuffer(file_bytes, dtype=np.uint8)
            image = cv2.imdecode(np_bytes, cv2.IMREAD_COLOR)
            if image is None:
                raise FingerprintServiceError("图片解码失败，请上传清晰的指纹图片。")
            return image
        except FingerprintServiceError:
            raise
        except Exception as exc:
            raise FingerprintServiceError("指纹图片读取失败，请稍后重试。") from exc

    @staticmethod
    def _skeletonize(binary_image: np.ndarray) -> np.ndarray:
        """
        功能：对二值图执行细化操作，输出骨架图。
        参数：
            binary_image (np.ndarray): 二值化后的指纹图。
        返回值：
            np.ndarray: 细化后的骨架图（0/255）。
        注意事项：
            使用形态学迭代法实现，不依赖额外 OpenCV 扩展模块。
        """
        skeleton = np.zeros(binary_image.shape, np.uint8)
        element = cv2.getStructuringElement(cv2.MORPH_CROSS, (3, 3))
        image = binary_image.copy()

        while True:
            eroded = cv2.erode(image, element)
            opened = cv2.dilate(eroded, element)
            residue = cv2.subtract(image, opened)
            skeleton = cv2.bitwise_or(skeleton, residue)
            image = eroded.copy()
            if cv2.countNonZero(image) == 0:
                break

        return skeleton

    @staticmethod
    def preprocess_fingerprint(image_bgr: np.ndarray) -> np.ndarray:
        """
        功能：执行指纹预处理（灰度化、二值化、细化、去噪）。
        参数：
            image_bgr (np.ndarray): 原始 BGR 指纹图像。
        返回值：
            np.ndarray: 预处理后的骨架图。
        注意事项：
            图像质量较低时可能导致提取到的 minutiae 数量不足。
        """
        try:
            if image_bgr is None or image_bgr.size == 0:
                raise FingerprintServiceError("指纹图像数据无效，无法预处理。")

            gray = cv2.cvtColor(image_bgr, cv2.COLOR_BGR2GRAY)

            # 先平滑去噪，再进行自适应增强。
            blur = cv2.GaussianBlur(gray, (5, 5), 0)
            clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
            enhanced = clahe.apply(blur)

            # OTSU 二值化，指纹脊线作为前景（255）。
            _, binary = cv2.threshold(
                enhanced,
                0,
                255,
                cv2.THRESH_BINARY_INV + cv2.THRESH_OTSU,
            )

            kernel = np.ones((3, 3), np.uint8)
            denoise = cv2.morphologyEx(binary, cv2.MORPH_OPEN, kernel, iterations=1)
            denoise = cv2.morphologyEx(denoise, cv2.MORPH_CLOSE, kernel, iterations=1)

            skeleton = FingerprintVerificationService._skeletonize(denoise)
            return skeleton
        except FingerprintServiceError:
            raise
        except Exception as exc:
            raise FingerprintServiceError("指纹预处理失败，请更换图片后重试。") from exc

    @staticmethod
    def _crossing_number(neighbors: list[int]) -> int:
        """
        功能：计算 crossing number，用于区分端点和分叉点。
        参数：
            neighbors (list[int]): 按顺时针顺序的 8 邻域像素值（0/1）。
        返回值：
            int: crossing number 值。
        注意事项：
            端点 CN=1，分叉点 CN=3。
        """
        transitions = 0
        chain = neighbors + [neighbors[0]]
        for idx in range(8):
            transitions += abs(chain[idx] - chain[idx + 1])
        return transitions // 2

    @staticmethod
    def _estimate_minutiae_angle(
        binary01: np.ndarray,
        x_pos: int,
        y_pos: int,
        feature_type: str,
    ) -> float:
        """
        功能：估算 minutiae 主方向角。
        参数：
            binary01 (np.ndarray): 骨架图 0/1 矩阵。
            x_pos (int): 点横坐标。
            y_pos (int): 点纵坐标。
            feature_type (str): 特征类型（ending/bifurcation）。
        返回值：
            float: 方向角（弧度）。
        注意事项：
            对分叉点返回分支平均方向，用于匹配时辅助约束。
        """
        points = []
        for y_off in (-1, 0, 1):
            for x_off in (-1, 0, 1):
                if x_off == 0 and y_off == 0:
                    continue
                nx = x_pos + x_off
                ny = y_pos + y_off
                if binary01[ny, nx] == 1:
                    points.append((nx, ny))

        if not points:
            return 0.0

        if feature_type == "ending":
            nx, ny = points[0]
            return float(math.atan2(y_pos - ny, x_pos - nx))

        vec_x = 0.0
        vec_y = 0.0
        for nx, ny in points:
            vec_x += nx - x_pos
            vec_y += ny - y_pos
        return float(math.atan2(vec_y, vec_x))

    @staticmethod
    def extract_minutiae(skeleton_image: np.ndarray) -> list[dict[str, float | str]]:
        """
        功能：从骨架图中提取端点和分叉点。
        参数：
            skeleton_image (np.ndarray): 细化骨架图（0/255）。
        返回值：
            list[dict[str, float | str]]: minutiae 列表。
        注意事项：
            返回坐标为归一化坐标，便于跨分辨率匹配。
        """
        try:
            if skeleton_image is None or skeleton_image.size == 0:
                raise FingerprintServiceError("骨架图为空，无法提取指纹特征。")

            height, width = skeleton_image.shape[:2]
            binary01 = (skeleton_image > 0).astype(np.uint8)

            border_margin = 10
            raw_points: list[dict[str, float | str]] = []

            for y_pos in range(1, height - 1):
                for x_pos in range(1, width - 1):
                    if binary01[y_pos, x_pos] == 0:
                        continue

                    if (
                        x_pos < border_margin
                        or y_pos < border_margin
                        or x_pos >= width - border_margin
                        or y_pos >= height - border_margin
                    ):
                        continue

                    neighbors = [
                        int(binary01[y_pos - 1, x_pos]),
                        int(binary01[y_pos - 1, x_pos + 1]),
                        int(binary01[y_pos, x_pos + 1]),
                        int(binary01[y_pos + 1, x_pos + 1]),
                        int(binary01[y_pos + 1, x_pos]),
                        int(binary01[y_pos + 1, x_pos - 1]),
                        int(binary01[y_pos, x_pos - 1]),
                        int(binary01[y_pos - 1, x_pos - 1]),
                    ]

                    cn_value = FingerprintVerificationService._crossing_number(neighbors)
                    if cn_value not in (1, 3):
                        continue

                    feature_type = "ending" if cn_value == 1 else "bifurcation"
                    angle = FingerprintVerificationService._estimate_minutiae_angle(
                        binary01=binary01,
                        x_pos=x_pos,
                        y_pos=y_pos,
                        feature_type=feature_type,
                    )

                    raw_points.append(
                        {
                            "x_px": float(x_pos),
                            "y_px": float(y_pos),
                            "type": feature_type,
                            "angle": float(angle),
                        }
                    )

            # 去除彼此过近的同类点，降低噪声影响。
            filtered_points: list[dict[str, float | str]] = []
            for point in raw_points:
                duplicated = False
                for chosen in filtered_points:
                    if point["type"] != chosen["type"]:
                        continue
                    dist = math.hypot(
                        float(point["x_px"]) - float(chosen["x_px"]),
                        float(point["y_px"]) - float(chosen["y_px"]),
                    )
                    if dist < MINUTIAE_MIN_DISTANCE:
                        duplicated = True
                        break
                if not duplicated:
                    filtered_points.append(point)

            minutiae = []
            for point in filtered_points:
                minutiae.append(
                    {
                        "x": float(point["x_px"]) / float(width),
                        "y": float(point["y_px"]) / float(height),
                        "type": str(point["type"]),
                        "angle": float(point["angle"]),
                    }
                )

            if len(minutiae) < MIN_MINUTIAE_COUNT:
                raise FingerprintServiceError(
                    "指纹特征点数量不足，请上传更清晰且完整的指纹图片。"
                )

            return minutiae
        except FingerprintServiceError:
            raise
        except Exception as exc:
            raise FingerprintServiceError("指纹特征提取失败，请稍后重试。") from exc

    @staticmethod
    def build_template(image_bgr: np.ndarray) -> FingerprintTemplate:
        """
        功能：从原始指纹图像生成模板。
        参数：
            image_bgr (np.ndarray): 原始 BGR 图像。
        返回值：
            FingerprintTemplate: 指纹模板对象。
        注意事项：
            模板中包含 minutiae 以及图像宽高元信息。
        """
        skeleton = FingerprintVerificationService.preprocess_fingerprint(image_bgr)
        minutiae = FingerprintVerificationService.extract_minutiae(skeleton)
        height, width = skeleton.shape[:2]
        return FingerprintTemplate(minutiae=minutiae, width=width, height=height)

    @staticmethod
    def encrypt_template(template: FingerprintTemplate, aes_key: bytes) -> str:
        """
        功能：加密指纹模板为字符串。
        参数：
            template (FingerprintTemplate): 指纹模板对象。
            aes_key (bytes): AES-256 密钥。
        返回值：
            str: 加密后的模板字符串。
        注意事项：
            模板采用 JSON 序列化后进行 AES 加密。
        """
        try:
            payload = {
                "minutiae": template.minutiae,
                "width": template.width,
                "height": template.height,
            }
            plain_text = json.dumps(payload, ensure_ascii=False)
            return AESUtil.encrypt_string(plain_text, aes_key)
        except (AESCryptoError, TypeError, ValueError) as exc:
            raise FingerprintServiceError("指纹模板加密失败，请检查加密配置。") from exc

    @staticmethod
    def decrypt_template(encrypted_template: str, aes_key: bytes) -> FingerprintTemplate:
        """
        功能：解密数据库中的指纹模板。
        参数：
            encrypted_template (str): 加密模板字符串。
            aes_key (bytes): AES-256 密钥。
        返回值：
            FingerprintTemplate: 解密后的模板对象。
        注意事项：
            解密内容格式不正确会抛出 FingerprintServiceError。
        """
        try:
            plain_text = AESUtil.decrypt_string(encrypted_template, aes_key)
            data = json.loads(plain_text)
            minutiae = data.get("minutiae", [])
            width = int(data.get("width", 0))
            height = int(data.get("height", 0))

            if not isinstance(minutiae, list) or width <= 0 or height <= 0:
                raise FingerprintServiceError("模板数据结构不完整，无法完成解密。")

            return FingerprintTemplate(
                minutiae=minutiae,
                width=width,
                height=height,
            )
        except FingerprintServiceError:
            raise
        except (AESCryptoError, ValueError, TypeError, json.JSONDecodeError) as exc:
            raise FingerprintServiceError("指纹模板解密失败，数据可能已损坏。") from exc

    @staticmethod
    def _normalize_for_matching(
        minutiae: list[dict[str, float | str]],
        feature_type: str,
    ) -> list[tuple[float, float]]:
        """
        功能：按特征类型筛选并规范化 minutiae 坐标。
        参数：
            minutiae (list[dict[str, float | str]]): 原始 minutiae 列表。
            feature_type (str): 类型（ending/bifurcation）。
        返回值：
            list[tuple[float, float]]: 规范化坐标列表。
        注意事项：
            内部执行平移、主轴对齐和尺度归一化。
        """
        points = [
            (float(item["x"]), float(item["y"]))
            for item in minutiae
            if str(item.get("type", "")) == feature_type
        ]

        if not points:
            return []

        point_count = len(points)
        centroid_x = sum(item[0] for item in points) / float(point_count)
        centroid_y = sum(item[1] for item in points) / float(point_count)
        centered = [(x_val - centroid_x, y_val - centroid_y) for x_val, y_val in points]

        rotated = centered
        if point_count > 1:
            # 使用二阶中心矩估计主轴方向，避免触发平台相关数值库异常。
            u20 = sum(x_val * x_val for x_val, _ in centered)
            u02 = sum(y_val * y_val for _, y_val in centered)
            u11 = sum(x_val * y_val for x_val, y_val in centered)
            angle = 0.5 * math.atan2(2.0 * u11, (u20 - u02))

            cos_v = math.cos(-angle)
            sin_v = math.sin(-angle)
            rotated = [
                (
                    x_val * cos_v - y_val * sin_v,
                    x_val * sin_v + y_val * cos_v,
                )
                for x_val, y_val in centered
            ]

        radius = max((math.hypot(x_val, y_val) for x_val, y_val in rotated), default=0.0)
        if radius <= 0:
            return rotated

        return [(x_val / radius, y_val / radius) for x_val, y_val in rotated]

    @staticmethod
    def _greedy_point_match(
        points_a: list[tuple[float, float]],
        points_b: list[tuple[float, float]],
    ) -> int:
        """
        功能：在同类型 minutiae 集合中执行贪心匹配。
        参数：
            points_a (np.ndarray): 待匹配点集 A。
            points_b (np.ndarray): 待匹配点集 B。
        返回值：
            int: 匹配成功点数量。
        注意事项：
            匹配时每个点最多被匹配一次。
        """
        if not points_a or not points_b:
            return 0

        used_indices: set[int] = set()
        matched = 0

        for idx_a in range(len(points_a)):
            current = points_a[idx_a]
            best_idx = -1
            best_dist = float("inf")

            for idx_b in range(len(points_b)):
                if idx_b in used_indices:
                    continue
                dist = math.hypot(
                    current[0] - points_b[idx_b][0],
                    current[1] - points_b[idx_b][1],
                )
                if dist < best_dist:
                    best_dist = dist
                    best_idx = idx_b

            if best_idx >= 0 and best_dist <= MINUTIAE_MATCH_DISTANCE:
                used_indices.add(best_idx)
                matched += 1

        return matched

    @staticmethod
    def match_templates(
        probe_template: FingerprintTemplate,
        enrolled_template: FingerprintTemplate,
        threshold: float = FINGERPRINT_MATCH_THRESHOLD,
    ) -> FingerprintMatchResult:
        """
        功能：比较两个指纹模板并输出匹配结果。
        参数：
            probe_template (FingerprintTemplate): 当前待验证模板。
            enrolled_template (FingerprintTemplate): 已注册模板。
            threshold (float): 匹配阈值，默认 0.7。
        返回值：
            FingerprintMatchResult: 匹配结果对象。
        注意事项：
            分值综合端点匹配与分叉点匹配，并引入数量一致性约束。
        """
        try:
            probe_count = len(probe_template.minutiae)
            enrolled_count = len(enrolled_template.minutiae)
            if probe_count < MIN_MINUTIAE_COUNT or enrolled_count < MIN_MINUTIAE_COUNT:
                raise FingerprintServiceError("模板特征点不足，无法执行可靠匹配。")

            probe_end = FingerprintVerificationService._normalize_for_matching(
                probe_template.minutiae,
                "ending",
            )
            probe_bif = FingerprintVerificationService._normalize_for_matching(
                probe_template.minutiae,
                "bifurcation",
            )
            enrolled_end = FingerprintVerificationService._normalize_for_matching(
                enrolled_template.minutiae,
                "ending",
            )
            enrolled_bif = FingerprintVerificationService._normalize_for_matching(
                enrolled_template.minutiae,
                "bifurcation",
            )

            matched_end = FingerprintVerificationService._greedy_point_match(
                probe_end,
                enrolled_end,
            )
            matched_bif = FingerprintVerificationService._greedy_point_match(
                probe_bif,
                enrolled_bif,
            )

            total_matched = matched_end + matched_bif
            base_score = total_matched / float(max(probe_count, enrolled_count))

            # 数量差距过大时降低分值，减少"谁都能匹配"的误识别风险。
            count_gap_ratio = abs(probe_count - enrolled_count) / float(
                max(probe_count, enrolled_count)
            )
            consistency_factor = max(0.0, 1.0 - count_gap_ratio)
            final_score = base_score * (0.85 + 0.15 * consistency_factor)

            return FingerprintMatchResult(
                score=float(final_score),
                is_match=bool(final_score >= threshold),
                matched_points=int(total_matched),
                probe_points=int(probe_count),
                enrolled_points=int(enrolled_count),
            )
        except FingerprintServiceError:
            raise
        except Exception as exc:
            raise FingerprintServiceError("指纹模板匹配失败，请稍后重试。") from exc
