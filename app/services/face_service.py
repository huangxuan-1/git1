"""
app/services/face_service.py
功能：封装人脸活体检测、特征提取、AES 加密存储和人脸比对能力，基于百度智能云人脸识别API。
注意事项：
1. 所有本地人脸识别逻辑已替换为百度云API调用。
2. 人脸特征存储为百度云返回的face_token字符串。
3. 活体检测使用百度云faceverify接口，专门用于判断是否为活体。
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import requests
import time
from dataclasses import dataclass
from typing import Any

import cv2
import numpy as np
# 尝试导入百度云SDK，如果未安装则提示
try:
    from aip import AipFace
    BAIDU_SDK_AVAILABLE = True
except ImportError as e:
    AipFace = None
    BAIDU_SDK_AVAILABLE = False
    print("警告：百度云SDK未安装，请运行: pip install baidu-aip")
    print("导入错误详情:", str(e))
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from utils.aes_utils import AESCryptoError, AESUtil

# 百度智能云人脸识别配置
BAIDU_APP_ID = "123015905"
BAIDU_API_KEY = "1pg474MAa76ByqN9THPoUPv9"
BAIDU_SECRET_KEY = "aqRdU4qrHvWJ4kd0n0BFryAlD0Cke9NF"

# 人脸匹配阈值，余弦相似度越高越相似。
FACE_MATCH_THRESHOLD = 0.6
# 活体检测阈值（百度云返回的活体分数）
FACE_LIVENESS_THRESHOLD = 0.6


@dataclass
class FaceLivenessMetrics:
    """
    功能：封装单帧人脸活体分析结果。
    参数：
        face_present (bool): 是否检测到单人脸。
        blink_ear (float): 眨眼 EAR 值（模拟值，用于前端状态机）。
        mouth_mar (float): 张嘴 MAR 值（模拟值，用于前端状态机）。
        center_x (float): 面部中心点 X 坐标（模拟值）。
        center_y (float): 面部中心点 Y 坐标（模拟值）。
    返回值：
        无。
    注意事项：
        由前端按时间窗完成多帧状态机判断，实际活体检测由百度云API完成。
    """

    face_present: bool
    blink_ear: float
    mouth_mar: float
    center_x: float
    center_y: float


class FaceServiceError(Exception):
    """
    功能：人脸服务统一异常类型。
    参数：
        message (str): 异常描述信息。
    返回值：
        无。
    注意事项：
        路由层可捕获该异常并返回友好错误提示。
    """


@dataclass
class FaceVerificationResult:
    """
    功能：封装人脸比对结果。
    参数：
        distance (float): 欧氏距离。
        is_match (bool): 是否匹配。
    返回值：
        无。
    注意事项：
        similarity >= threshold 时判定为匹配。
    """

    similarity: float
    is_match: bool

    @property
    def distance(self) -> float:
        """
        功能：兼容旧字段名。
        参数：
            无。
        返回值：
            float: 相似度值。
        注意事项：
            仅用于兼容历史代码路径。
        """
        return self.similarity


class FaceVerificationService:
    """
    功能：人脸识别业务服务，基于百度智能云API。
    参数：
        landmark_model_path (str): 保留参数，用于兼容现有接口，实际不使用。
    返回值：
        无。
    注意事项：
        初始化百度云客户端，所有识别逻辑委托给百度云API。
    """

    def __init__(self, landmark_model_path: str = ""):
        """
        功能：初始化人脸服务，创建百度云客户端。
        参数：
            landmark_model_path (str): 保留参数，实际不使用。
        返回值：
            None
        注意事项：
            百度云客户端配置从常量读取，实际部署时应改为环境变量。
        """
        if not BAIDU_SDK_AVAILABLE:
            raise FaceServiceError("百度云SDK未安装，请运行: pip install baidu-aip")

        try:
            self.client = AipFace(BAIDU_APP_ID, BAIDU_API_KEY, BAIDU_SECRET_KEY)
            # 设置请求超时时间
            self.client.setConnectionTimeoutInMillis(5000)
            self.client.setSocketTimeoutInMillis(10000)
            print(f"FaceVerificationService初始化成功，APP_ID={BAIDU_APP_ID}")
        except Exception as exc:
            print(f"FaceVerificationService初始化失败: {exc}")
            raise FaceServiceError("百度云人脸识别服务初始化失败，请检查网络连接和API配置。") from exc

    def _get_access_token(self) -> str:
        """
        功能：获取百度云API的access_token。
        参数：
            无。
        返回值：
            str: access_token字符串。
        注意事项：
            使用API Key和Secret Key获取token，有效期30天。
        """
        url = "https://aip.baidubce.com/oauth/2.0/token"
        params = {
            "grant_type": "client_credentials",
            "client_id": BAIDU_API_KEY,
            "client_secret": BAIDU_SECRET_KEY,
        }
        response = requests.post(url, params=params, timeout=10)
        result = response.json()
        if "access_token" not in result:
            raise FaceServiceError(f"获取access_token失败: {result.get('error_description', '未知错误')}")
        return result["access_token"]

    def verify_face_liveness(self, image_bgr: np.ndarray) -> dict:
        """
        功能：调用百度云faceverify接口进行活体检测。
        参数：
            image_bgr (np.ndarray): 待检测的人脸图像。
        返回值：
            dict: 活体检测结果。
                - is_live: 是否为活体（True/False）
                - liveness_score: 活体分数（0-1）
                - face_present: 是否检测到人脸
                - face_token: 人脸特征token
                - message: 结果描述
        注意事项：
            使用百度云faceverify API专门进行活体检测，
            接口地址: https://aip.baidubce.com/rest/2.0/face/v3/faceverify
            注意：请求参数必须是数组格式！
        """
        try:
            # 获取access_token
            access_token = self._get_access_token()
            print(f"[活体检测] 获取到access_token: {access_token[:20]}...")

            # 将BGR图像转换为RGB JPEG
            rgb_image = cv2.cvtColor(image_bgr, cv2.COLOR_BGR2RGB)
            success, encoded_image = cv2.imencode('.jpg', rgb_image, [cv2.IMWRITE_JPEG_QUALITY, 95])
            if not success:
                return {
                    "is_live": False,
                    "liveness_score": 0.0,
                    "face_present": False,
                    "face_token": "",
                    "message": "图像编码失败，请更换图片后重试。",
                }

            image_bytes = encoded_image.tobytes()
            image_base64 = base64.b64encode(image_bytes).decode('utf-8')
            print(f"[活体检测] 图像base64长度: {len(image_base64)}")

            # 调用faceverify接口 - 注意：参数必须是数组格式！
            url = f"https://aip.baidubce.com/rest/2.0/face/v3/faceverify"
            # 百度云faceverify接口要求参数是数组格式，每个元素包含image和image_type
            payload = [
                {
                    "image": image_base64,
                    "image_type": "BASE64",
                    "face_field": "quality,liveness",
                }
            ]
            params = {"access_token": access_token}
            headers = {"Content-Type": "application/json"}

            print(f"[活体检测] 请求URL: {url}")
            print(f"[活体检测] payload格式: 数组，包含1个元素")
            print(f"[活体检测] payload内容: image_type=BASE64, face_field=quality,liveness")

            response = requests.post(url, json=payload, params=params, headers=headers, timeout=20)
            result = response.json()

            print(f"[活体检测] API响应: {result}")

            # 处理API响应
            if 'error_code' in result and result['error_code'] != 0:
                error_code = result['error_code']
                error_msg = result.get('error_msg', '未知错误')
                print(f"[活体检测] 错误: error_code={error_code}, error_msg={error_msg}")

                if error_code == 222202:  # 图片中没有人脸
                    return {
                        "is_live": False,
                        "liveness_score": 0.0,
                        "face_present": False,
                        "face_token": "",
                        "message": "未检测到人脸，请确保画面中有人脸。",
                    }
                elif error_code == 222203:
                    return {
                        "is_live": False,
                        "liveness_score": 0.0,
                        "face_present": True,
                        "face_token": "",
                        "message": "人脸解析失败，请确保人脸清晰、正面。",
                    }
                elif error_code == 222210:
                    return {
                        "is_live": False,
                        "liveness_score": 0.0,
                        "face_present": False,
                        "face_token": "",
                        "message": "活体检测未返回结果，请稍后重试。",
                    }
                else:
                    return {
                        "is_live": False,
                        "liveness_score": 0.0,
                        "face_present": False,
                        "face_token": "",
                        "message": f"活体检测失败: {error_msg} (错误码: {error_code})",
                    }

            # 解析成功响应
            if 'result' not in result:
                return {
                    "is_live": False,
                    "liveness_score": 0.0,
                    "face_present": False,
                    "face_token": "",
                    "message": "活体检测未返回有效结果。",
                }

            face_list = result['result'].get('face_list', [])
            if len(face_list) == 0:
                return {
                    "is_live": False,
                    "liveness_score": 0.0,
                    "face_present": False,
                    "face_token": "",
                    "message": "未检测到人脸。",
                }

            face_info = face_list[0]
            face_token = face_info.get('face_token', '')
            liveness = face_info.get('liveness', {})

            print(f"[活体检测] face_token: {face_token}, liveness字段: {liveness}")

            # 活体分数（百度云返回的liv_2d字段）
            liv_2d_score = liveness.get('liv_2d', 0)
            print(f"[活体检测] liv_2d原始值: {liv_2d_score}")

            # 如果分数大于1，说明是0-100范围，需要转换为0-1
            if liv_2d_score > 1:
                liveness_score = float(liv_2d_score) / 100.0
            else:
                liveness_score = float(liv_2d_score)

            # 活体阈值判断
            is_live = liveness_score >= FACE_LIVENESS_THRESHOLD
            print(f"[活体检测] 最终分数: {liveness_score:.2f}, 阈值: {FACE_LIVENESS_THRESHOLD}, 是否活体: {is_live}")

            return {
                "is_live": is_live,
                "liveness_score": liveness_score,
                "face_present": True,
                "face_token": face_token,
                "message": f"活体检测完成，分数: {liveness_score:.2f}，结果: {'活体' if is_live else '非活体'}",
            }
        except requests.exceptions.Timeout:
            print("[活体检测] 请求超时")
            return {
                "is_live": False,
                "liveness_score": 0.0,
                "face_present": False,
                "face_token": "",
                "message": "活体检测请求超时，请稍后重试。",
            }
        except requests.exceptions.RequestException as exc:
            print(f"[活体检测] 网络错误: {exc}")
            return {
                "is_live": False,
                "liveness_score": 0.0,
                "face_present": False,
                "face_token": "",
                "message": f"活体检测网络错误: {str(exc)}",
            }
        except Exception as exc:
            print(f"[活体检测] 异常: {exc}")
            import traceback
            traceback.print_exc()
            return {
                "is_live": False,
                "liveness_score": 0.0,
                "face_present": False,
                "face_token": "",
                "message": f"活体检测失败: {str(exc)}",
            }

    @staticmethod
    def decode_data_url_image(data_url: str) -> np.ndarray:
        """
        功能：将 Base64 DataURL 字符串解码为 BGR 图像。
        参数：
            data_url (str): 前端上传的 data:image/*;base64 字符串。
        返回值：
            np.ndarray: OpenCV BGR 图像。
        注意事项：
            解码失败会抛出 FaceServiceError。
        """
        try:
            if not isinstance(data_url, str) or not data_url.strip():
                raise FaceServiceError("图像数据为空，请重新采集图像。")

            raw_text = data_url.strip()
            encoded_part = raw_text.split(",", 1)[1] if "," in raw_text else raw_text
            image_bytes = base64.b64decode(encoded_part, validate=True)
            np_bytes = np.frombuffer(image_bytes, dtype=np.uint8)
            image = cv2.imdecode(np_bytes, cv2.IMREAD_COLOR)
            if image is None:
                raise FaceServiceError("图像解码失败，请更换图片后重试。")
            return image
        except FaceServiceError:
            raise
        except Exception as exc:
            raise FaceServiceError("图像解析失败，请检查图片格式。") from exc

    @staticmethod
    def decode_file_image(file_bytes: bytes) -> np.ndarray:
        """
        功能：将上传文件字节流解码为 BGR 图像。
        参数：
            file_bytes (bytes): 图片文件字节流。
        返回值：
            np.ndarray: OpenCV BGR 图像。
        注意事项：
            仅支持可被 OpenCV 解码的常见图片格式。
        """
        try:
            if not isinstance(file_bytes, bytes) or len(file_bytes) == 0:
                raise FaceServiceError("上传图片为空，请重新选择文件。")

            np_bytes = np.frombuffer(file_bytes, dtype=np.uint8)
            image = cv2.imdecode(np_bytes, cv2.IMREAD_COLOR)
            if image is None:
                raise FaceServiceError("图片解码失败，请上传有效图片文件。")
            return image
        except FaceServiceError:
            raise
        except Exception as exc:
            raise FaceServiceError("上传图片处理失败，请稍后重试。") from exc

    def _call_baidu_api(self, api_method, image_bgr: np.ndarray, options: dict = None):
        """
        功能：统一调用百度云API，处理图像编码和错误响应。
        参数：
            api_method: 百度云API方法（如face_detect、face_liveness等）。
            image_bgr (np.ndarray): BGR图像。
            options (dict): API调用选项。
        返回值：
            dict: 百度云API响应结果。
        注意事项：
            自动将BGR图像转换为RGB JPEG格式，处理网络超时和API错误。
        """
        try:
            # 将BGR图像转换为RGB JPEG字节流
            rgb_image = cv2.cvtColor(image_bgr, cv2.COLOR_BGR2RGB)
            success, encoded_image = cv2.imencode('.jpg', rgb_image)
            if not success:
                raise FaceServiceError("图像编码失败，请更换图片后重试。")

            image_bytes = encoded_image.tobytes()
            image_base64 = base64.b64encode(image_bytes).decode('utf-8')

            # 调用百度云API
            if options:
                result = api_method(image_base64, "BASE64", options)
            else:
                result = api_method(image_base64, "BASE64")

            if 'error_code' in result and result['error_code'] != 0:
                error_msg = result.get('error_msg', '未知错误')
                if result['error_code'] == 222202:  # 图片中没有人脸
                    raise FaceServiceError("未检测到人脸，请确保画面中有人脸。")
                elif result['error_code'] == 222203:  # 无法解析人脸
                    raise FaceServiceError("人脸解析失败，请确保人脸清晰、正面。")
                elif result['error_code'] == 222204:  # 人脸模糊
                    raise FaceServiceError("人脸模糊，请确保人脸清晰。")
                elif result['error_code'] == 222205:  # 人脸光照不好
                    raise FaceServiceError("光照不足，请调整光线后重试。")
                elif result['error_code'] == 222206:  # 人脸不完整
                    raise FaceServiceError("人脸不完整，请确保完整面部在画面中。")
                elif result['error_code'] == 222207:  # 人脸角度过大
                    raise FaceServiceError("人脸角度过大，请正对摄像头。")
                else:
                    raise FaceServiceError(f"人脸识别服务错误: {error_msg}")

            return result
        except FaceServiceError:
            raise
        except Exception as exc:
            raise FaceServiceError("人脸识别服务暂时不可用，请稍后重试。") from exc

    def extract_face_encoding(self, image_bgr: np.ndarray) -> np.ndarray:
        """
        功能：提取人脸特征，返回百度云face_token的字节表示。
        参数：
            image_bgr (np.ndarray): 人脸图像。
        返回值：
            np.ndarray: 包含face_token字符串的字节数组。
        注意事项：
            图像中必须且只能包含一张清晰人脸，否则抛出FaceServiceError。
        """
        try:
            # 调用百度云人脸检测接口
            result = self._call_baidu_api(
                self.client.detect,
                image_bgr,
                {"face_field": "quality", "max_face_num": 1}
            )

            if 'result' not in result or 'face_list' not in result['result']:
                raise FaceServiceError("人脸检测失败，未返回有效结果。")

            face_list = result['result']['face_list']
            if len(face_list) != 1:
                raise FaceServiceError("特征提取失败：图像中必须且只能有一张人脸。")

            face_info = face_list[0]
            face_token = face_info.get('face_token')
            if not face_token:
                raise FaceServiceError("人脸特征提取失败，未获取到face_token。")

            # 检查人脸质量
            quality = face_info.get('quality', {})
            if quality.get('blur', 1) > 0.7:
                raise FaceServiceError("人脸模糊，请上传清晰的人脸照片。")
            if quality.get('illumination', 0) < 40:
                raise FaceServiceError("光照不足，请调整光线后重试。")
            if quality.get('completeness', 0) < 0.8:
                raise FaceServiceError("人脸不完整，请确保完整面部在画面中。")

            # 将face_token转换为numpy数组（保持接口兼容性）
            # 实际存储时会加密这个字符串
            token_bytes = face_token.encode('utf-8')
            return np.frombuffer(token_bytes, dtype=np.uint8)
        except FaceServiceError:
            raise
        except Exception as exc:
            raise FaceServiceError("人脸特征提取失败，请稍后重试。") from exc

    def check_face_quality(self, image_bgr: np.ndarray) -> dict:
        """
        功能：检测人脸质量，返回详细质量指标（用于第一步基础人脸质量检测）。
        参数：
            image_bgr (np.ndarray): 人脸图像。
        返回值：
            dict: 包含人脸质量指标的字典。
                - face_present: 是否检测到人脸
                - face_token: 人脸特征token（用于后续比对）
                - blur: 模糊度（0-1，越小越清晰）
                - illumination: 光照强度（0-255）
                - completeness: 完整度（0-1）
                - occlusion: 遮挡信息
        注意事项：
            该方法用于第一步基础人脸照片的质量检测，
            不抛出异常，返回质量指标供上层判断。
        """
        try:
            result = self._call_baidu_api(
                self.client.detect,
                image_bgr,
                {"face_field": "quality,occlusion", "max_face_num": 1}
            )

            if 'result' not in result or 'face_list' not in result['result']:
                return {
                    "face_present": False,
                    "blur": 1.0,
                    "illumination": 0,
                    "completeness": 0,
                    "occlusion": {},
                    "face_token": "",
                }

            face_list = result['result']['face_list']
            if len(face_list) == 0:
                return {
                    "face_present": False,
                    "blur": 1.0,
                    "illumination": 0,
                    "completeness": 0,
                    "occlusion": {},
                    "face_token": "",
                }

            face_info = face_list[0]
            quality = face_info.get('quality', {})
            occlusion = face_info.get('occlusion', {})
            face_token = face_info.get('face_token', '')

            return {
                "face_present": True,
                "face_token": face_token,
                "blur": quality.get('blur', 1),
                "illumination": quality.get('illumination', 0),
                "completeness": quality.get('completeness', 0),
                "occlusion": {
                    "left_eye": occlusion.get('left_eye', 0),
                    "right_eye": occlusion.get('right_eye', 0),
                    "mouth": occlusion.get('mouth', 0),
                    "nose": occlusion.get('nose', 0),
                    "left_cheek": occlusion.get('left_cheek', 0),
                    "right_cheek": occlusion.get('right_cheek', 0),
                    "chin": occlusion.get('chin', 0),
                },
            }
        except Exception as exc:
            # 调用失败时返回默认值
            return {
                "face_present": False,
                "blur": 1.0,
                "illumination": 0,
                "completeness": 0,
                "occlusion": {},
                "face_token": "",
            }

    def build_average_face_encoding(self, images_bgr: list[np.ndarray]) -> np.ndarray:
        """
        功能：对三张活体图像提取人脸特征，返回第一张图像的face_token。
        参数：
            images_bgr (list[np.ndarray]): 三张人脸图像。
        返回值：
            np.ndarray: 包含face_token字符串的字节数组。
        注意事项：
            图像数量必须为3，实际使用第一张图像（正常表情）的face_token。
        """
        if len(images_bgr) != 3:
            raise FaceServiceError("人脸特征提取需要三张图像。")

        # 使用第一张图像（正常表情）提取face_token
        return self.extract_face_encoding(images_bgr[0])

    
    def analyze_liveness_frame(self, image_bgr: np.ndarray) -> FaceLivenessMetrics:
        """
        功能：分析单帧图像的人脸位置信息（用于前端状态机）。
        参数：
            image_bgr (np.ndarray): 待分析图像。
        返回值：
            FaceLivenessMetrics: 人脸分析结果。
        注意事项：
            该接口返回人脸位置信息，用于前端人脸对准判断。
            实际安全验证由1:1人脸比对完成（阈值>=0.6）。
        """
        try:
            # 调用百度云人脸检测，检查是否有人脸
            result = self._call_baidu_api(
                self.client.detect,
                image_bgr,
                {"face_field": "quality", "max_face_num": 1}
            )

            if 'result' not in result or 'face_list' not in result['result']:
                return FaceLivenessMetrics(False, 0.0, 0.0, 0.0, 0.0)

            face_list = result['result']['face_list']
            if len(face_list) != 1:
                return FaceLivenessMetrics(False, 0.0, 0.0, 0.0, 0.0)

            face_info = face_list[0]
            location = face_info.get('location', {})

            # 计算人脸中心点（模拟值）
            center_x = location.get('left', 0) + location.get('width', 0) / 2
            center_y = location.get('top', 0) + location.get('height', 0) / 2

            # 返回模拟的EAR和MAR值（正常睁眼闭嘴状态）
            # 这些值仅用于前端状态机显示，实际检测由专用方法完成
            return FaceLivenessMetrics(
                face_present=True,
                blink_ear=0.3,      # 正常睁眼EAR值
                mouth_mar=0.25,     # 正常闭嘴MAR值
                center_x=float(center_x),
                center_y=float(center_y),
            )
        except Exception:
            # 如果API调用失败，返回无人脸状态
            return FaceLivenessMetrics(False, 0.0, 0.0, 0.0, 0.0)

    @staticmethod
    def encrypt_feature_vector(feature_vector: np.ndarray, aes_key: bytes) -> str:
        """
        功能：加密人脸特征（face_token字符串）。
        参数：
            feature_vector (np.ndarray): 包含face_token的字节数组。
            aes_key (bytes): 32 字节 AES 密钥。
        返回值：
            str: AES-256-GCM 加密后的字符串。
        注意事项：
            实际加密的是face_token字符串，而非128维特征向量。
        """
        try:
            if not isinstance(aes_key, bytes) or len(aes_key) != 32:
                raise AESCryptoError("AES 密钥长度必须为 32 字节。")

            # 将numpy数组转换回face_token字符串
            token_bytes = feature_vector.tobytes()
            face_token = token_bytes.decode('utf-8')

            # 加密face_token字符串
            feature_bytes = face_token.encode('utf-8')
            nonce = os.urandom(12)
            cipher_text = AESGCM(aes_key).encrypt(nonce, feature_bytes, None)
            return base64.b64encode(nonce + cipher_text).decode("utf-8")
        except (AESCryptoError, ValueError, TypeError) as exc:
            raise FaceServiceError("人脸特征加密失败，请检查加密配置。") from exc

    @staticmethod
    def decrypt_feature_vector(encrypted_text: str, aes_key: bytes) -> np.ndarray:
        """
        功能：解密人脸特征并恢复为face_token的字节表示。
        参数：
            encrypted_text (str): AES 加密后的特征字符串。
            aes_key (bytes): 32 字节 AES 密钥。
        返回值：
            np.ndarray: 包含face_token字符串的字节数组。
        注意事项：
            同时兼容 GCM 新格式与旧版 CBC JSON 格式。
        """
        try:
            if not isinstance(encrypted_text, str) or not encrypted_text.strip():
                raise FaceServiceError("人脸特征密文为空，无法解密。")

            if not isinstance(aes_key, bytes) or len(aes_key) != 32:
                raise AESCryptoError("AES 密钥长度必须为 32 字节。")

            payload = base64.b64decode(encrypted_text, validate=True)
            if len(payload) > 12 + 16:
                nonce = payload[:12]
                cipher_text = payload[12:]
                try:
                    plain_bytes = AESGCM(aes_key).decrypt(nonce, cipher_text, None)
                    # 将解密后的face_token转换为numpy数组
                    return np.frombuffer(plain_bytes, dtype=np.uint8)
                except Exception:
                    pass

            # 兼容旧版CBC格式
            plain_text = AESUtil.decrypt_string(encrypted_text, aes_key)
            # 旧版存储的是128维特征列表，新版是face_token字符串
            # 尝试解析为JSON，如果失败则认为是face_token字符串
            try:
                feature_list = json.loads(plain_text)
                # 旧版格式，转换为face_token的模拟表示
                # 创建一个模拟的face_token
                simulated_token = f"legacy_feature_{hash(str(feature_list))}"
                return np.frombuffer(simulated_token.encode('utf-8'), dtype=np.uint8)
            except json.JSONDecodeError:
                # 已经是face_token字符串
                return np.frombuffer(plain_text.encode('utf-8'), dtype=np.uint8)
        except FaceServiceError:
            raise
        except (AESCryptoError, json.JSONDecodeError, ValueError, TypeError, binascii.Error) as exc:
            raise FaceServiceError("人脸特征解密失败，数据可能已损坏。") from exc

    def compare_feature_vectors(
        self,
        vector_a: np.ndarray,
        vector_b: np.ndarray,
        threshold: float = FACE_MATCH_THRESHOLD,
    ) -> FaceVerificationResult:
        """
        功能：比对两组人脸特征，调用百度云人脸比对接口。
        参数：
            vector_a (np.ndarray): 人脸图像A（BGR格式）。
            vector_b (np.ndarray): 人脸图像B（BGR格式）。
            threshold (float): 匹配阈值，默认 0.6。
        返回值：
            FaceVerificationResult: 比对结果对象。
        注意事项：
            仅支持图像与图像的比对。face_token有时间限制，不适合直接比对。
        """
        try:
            # 获取access_token
            access_token = self._get_access_token()

            def prepare_image_param(vector, label):
                # 检查是否是图像（numpy数组，3通道BGR）
                if isinstance(vector, np.ndarray) and vector.dtype == np.uint8 and len(vector.shape) == 3 and vector.shape[2] == 3:
                    # 这是BGR图像
                    print(f"[人脸比对] {label}: 检测到图像，shape={vector.shape}")
                    rgb_image = cv2.cvtColor(vector, cv2.COLOR_BGR2RGB)
                    success, encoded_image = cv2.imencode('.jpg', rgb_image, [cv2.IMWRITE_JPEG_QUALITY, 95])
                    if not success:
                        raise FaceServiceError(f"{label}图像编码失败，无法进行人脸比对。")
                    image_bytes = encoded_image.tobytes()
                    image_base64 = base64.b64encode(image_bytes).decode('utf-8')
                    return {'image': image_base64, 'image_type': 'BASE64'}
                else:
                    # 可能是face_token字节数组，尝试解码
                    try:
                        token_bytes = vector.tobytes()
                        face_token = token_bytes.decode('utf-8')
                        print(f"[人脸比对] {label}: 检测到face_token: {face_token[:20]}...")
                        # face_token不能直接用于match接口，需要重新从图像提取
                        raise FaceServiceError(f"{label}是face_token而非图像，face_token无法直接用于比对。请传入原始图像。")
                    except Exception as e:
                        raise FaceServiceError(f"{label}格式错误，无法识别为有效的人脸数据: {e}")

            param_a = prepare_image_param(vector_a, "vector_a")
            param_b = prepare_image_param(vector_b, "vector_b")

            # 调用百度云人脸比对接口
            url = f"https://aip.baidubce.com/rest/2.0/face/v3/match"
            match_params = [param_a, param_b]
            params = {"access_token": access_token}
            headers = {"Content-Type": "application/json"}

            print(f"[人脸比对] 请求URL: {url}")
            print(f"[人脸比对] 参数数量: {len(match_params)}")

            response = requests.post(url, json=match_params, params=params, headers=headers, timeout=20)
            result = response.json()

            print(f"[人脸比对] API响应: {result}")

            if 'error_code' in result and result['error_code'] != 0:
                error_code = result['error_code']
                error_msg = result.get('error_msg', '未知错误')
                print(f"[人脸比对] 错误: error_code={error_code}, error_msg={error_msg}")

                if error_code == 222202:  # 图片中没有人脸
                    raise FaceServiceError("未检测到人脸，请确保画面中有人脸。")
                elif error_code == 222203:
                    raise FaceServiceError("人脸解析失败，请确保人脸清晰。")
                else:
                    raise FaceServiceError(f"人脸比对失败: {error_msg} (错误码: {error_code})")

            if 'result' not in result or 'score' not in result['result']:
                raise FaceServiceError("人脸比对失败，未返回有效结果。")

            # 百度云返回的score是0-100的范围
            raw_score = float(result['result']['score'])
            similarity = raw_score / 100.0  # 转换为0-1范围
            is_match = bool(similarity >= threshold)

            print(f"[人脸比对] 原始分数: {raw_score}, 相似度: {similarity:.4f}, 阈值: {threshold}, 是否匹配: {is_match}")

            return FaceVerificationResult(similarity=similarity, is_match=is_match)
        except FaceServiceError:
            raise
        except requests.exceptions.Timeout:
            raise FaceServiceError("人脸比对请求超时，请稍后重试。")
        except requests.exceptions.RequestException as exc:
            raise FaceServiceError(f"人脸比对网络错误: {str(exc)}")
        except Exception as exc:
            print(f"[人脸比对] 异常: {exc}")
            import traceback
            traceback.print_exc()
            raise FaceServiceError("人脸特征比对失败，请稍后重试。") from exc

    def register_face_to_group(self, image_bgr: np.ndarray, user_id: str, group_id: str = "registered_users") -> str:
        """
        功能：将人脸注册到百度云用户组，用于后续人脸搜索。
        参数：
            image_bgr (np.ndarray): 人脸图像。
            user_id (str): 用户标识（建议使用用户ID）。
            group_id (str): 用户组ID，默认为 "registered_users"。
        返回值：
            str: face_token。
        注意事项：
            此方法将人脸特征注册到百度云端，用于登录时的人脸搜索。
            如果用户组不存在会自动创建。
        """
        try:
            # 获取access_token
            access_token = self._get_access_token()

            # 将BGR图像转换为RGB JPEG
            rgb_image = cv2.cvtColor(image_bgr, cv2.COLOR_BGR2RGB)
            success, encoded_image = cv2.imencode('.jpg', rgb_image, [cv2.IMWRITE_JPEG_QUALITY, 95])
            if not success:
                raise FaceServiceError("图像编码失败。")

            image_bytes = encoded_image.tobytes()
            image_base64 = base64.b64encode(image_bytes).decode('utf-8')

            # 调用人脸注册接口
            url = f"https://aip.baidubce.com/rest/2.0/face/v3/faceset/user/add"
            payload = {
                "image": image_base64,
                "image_type": "BASE64",
                "group_id": group_id,
                "user_id": user_id,
                "user_info": "",  # 可选的用户信息
                "quality_control": "NORMAL",  # 质量控制
                "liveness_control": "NORMAL",  # 活体控制
            }
            params = {"access_token": access_token}
            headers = {"Content-Type": "application/json"}

            print(f"[人脸注册] 请求URL: {url}")
            print(f"[人脸注册] 用户ID: {user_id}, 用户组: {group_id}")

            response = requests.post(url, json=payload, params=params, headers=headers, timeout=20)
            result = response.json()

            print(f"[人脸注册] API响应: {result}")

            if 'error_code' in result and result['error_code'] != 0:
                error_code = result['error_code']
                error_msg = result.get('error_msg', '未知错误')
                print(f"[人脸注册] 错误: error_code={error_code}, error_msg={error_msg}")

                if error_code == 216616:  # 组不存在，需要先创建
                    print("[人脸注册] 用户组不存在，先创建用户组...")
                    self._create_face_group(group_id, access_token)
                    # 重新注册
                    response = requests.post(url, json=payload, params=params, headers=headers, timeout=20)
                    result = response.json()
                    print(f"[人脸注册] 重试注册响应: {result}")

                    if 'error_code' in result and result['error_code'] != 0:
                        # 如果是用户已存在错误，先删除再重新注册
                        if result['error_code'] == 216617:
                            print(f"[人脸注册] 用户已存在，先删除后重新注册...")
                            self._delete_face_user(user_id, group_id, access_token)
                            response = requests.post(url, json=payload, params=params, headers=headers, timeout=20)
                            result = response.json()
                            print(f"[人脸注册] 删除后重新注册响应: {result}")
                            if 'error_code' in result and result['error_code'] != 0:
                                raise FaceServiceError(f"人脸注册失败: {result.get('error_msg', '未知错误')}")
                        else:
                            raise FaceServiceError(f"人脸注册失败: {result.get('error_msg', '未知错误')}")

                elif error_code == 216617:  # 用户已存在
                    print(f"[人脸注册] 用户已存在，先删除后重新注册...")
                    self._delete_face_user(user_id, group_id, access_token)
                    response = requests.post(url, json=payload, params=params, headers=headers, timeout=20)
                    result = response.json()
                    print(f"[人脸注册] 删除后重新注册响应: {result}")
                    if 'error_code' in result and result['error_code'] != 0:
                        raise FaceServiceError(f"人脸注册失败: {result.get('error_msg', '未知错误')}")

                elif error_code == 222202:
                    raise FaceServiceError("未检测到人脸，请确保画面中有人脸。")
                elif error_code == 222203:
                    raise FaceServiceError("人脸解析失败，请确保人脸清晰。")
                else:
                    raise FaceServiceError(f"人脸注册失败: {error_msg} (错误码: {error_code})")

            face_token = result.get('result', {}).get('face_token', '')
            if not face_token:
                raise FaceServiceError("人脸注册成功但未获取到face_token。")

            print(f"[人脸注册] 成功，face_token: {face_token}")
            return face_token

        except FaceServiceError:
            raise
        except requests.exceptions.Timeout:
            raise FaceServiceError("人脸注册请求超时，请稍后重试。")
        except requests.exceptions.RequestException as exc:
            raise FaceServiceError(f"人脸注册网络错误: {str(exc)}")
        except Exception as exc:
            print(f"[人脸注册] 异常: {exc}")
            import traceback
            traceback.print_exc()
            raise FaceServiceError("人脸注册失败，请稍后重试。") from exc

    def _create_face_group(self, group_id: str, access_token: str) -> None:
        """
        功能：创建百度云人脸用户组。
        参数：
            group_id (str): 用户组ID。
            access_token (str): API访问令牌。
        返回值：
            None
        注意事项：
            内部方法，用于在用户组不存在时自动创建。
        """
        url = f"https://aip.baidubce.com/rest/2.0/face/v3/faceset/group/add"
        payload = {"group_id": group_id}
        params = {"access_token": access_token}
        headers = {"Content-Type": "application/json"}

        print(f"[创建用户组] 请求URL: {url}, group_id: {group_id}")

        response = requests.post(url, json=payload, params=params, headers=headers, timeout=20)
        result = response.json()

        print(f"[创建用户组] API响应: {result}")

        if 'error_code' in result and result['error_code'] != 0:
            error_msg = result.get('error_msg', '未知错误')
            raise FaceServiceError(f"创建用户组失败: {error_msg}")

        print(f"[创建用户组] 成功创建用户组: {group_id}")

    def _delete_face_user(self, user_id: str, group_id: str, access_token: str) -> None:
        """
        功能：删除百度云人脸用户组中的用户。
        参数：
            user_id (str): 用户ID。
            group_id (str): 用户组ID。
            access_token (str): API访问令牌。
        返回值：
            None
        注意事项：
            内部方法，用于在用户重新注册时先删除旧记录。
        """
        url = f"https://aip.baidubce.com/rest/2.0/face/v3/faceset/user/delete"
        payload = {
            "group_id": group_id,
            "user_id": user_id,
        }
        params = {"access_token": access_token}
        headers = {"Content-Type": "application/json"}

        print(f"[删除用户] 请求URL: {url}, user_id: {user_id}, group_id: {group_id}")

        response = requests.post(url, json=payload, params=params, headers=headers, timeout=20)
        result = response.json()

        print(f"[删除用户] API响应: {result}")

        # 用户不存在也算成功
        if 'error_code' in result and result['error_code'] not in [0, 216618]:
            error_msg = result.get('error_msg', '未知错误')
            print(f"[删除用户] 错误: {error_msg}")
            # 不抛出异常，继续尝试注册

        print(f"[删除用户] 完成")

    def search_face_in_group(self, image_bgr: np.ndarray, group_id: str = "registered_users", threshold: float = 0.6) -> dict:
        """
        功能：在用户组中搜索人脸。
        参数：
            image_bgr (np.ndarray): 待搜索的人脸图像。
            group_id (str): 用户组ID。
            threshold (float): 匹配阈值。
        返回值：
            dict: 搜索结果。
                - matched: 是否找到匹配
                - user_id: 匹配的用户ID
                - similarity: 相似度
                - face_token: 匹配的face_token
        注意事项：
            用于登录时的人脸验证。
        """
        try:
            access_token = self._get_access_token()

            # 将BGR图像转换为RGB JPEG
            rgb_image = cv2.cvtColor(image_bgr, cv2.COLOR_BGR2RGB)
            success, encoded_image = cv2.imencode('.jpg', rgb_image, [cv2.IMWRITE_JPEG_QUALITY, 95])
            if not success:
                raise FaceServiceError("图像编码失败。")

            image_bytes = encoded_image.tobytes()
            image_base64 = base64.b64encode(image_bytes).decode('utf-8')

            # 调用人脸搜索接口
            url = f"https://aip.baidubce.com/rest/2.0/face/v3/search"
            payload = {
                "image": image_base64,
                "image_type": "BASE64",
                "group_id_list": group_id,
                "max_face_num": 1,
                "match_threshold": int(threshold * 100),
            }
            params = {"access_token": access_token}
            headers = {"Content-Type": "application/json"}

            print(f"[人脸搜索] 请求URL: {url}")
            print(f"[人脸搜索] 搜索用户组: {group_id}, 阈值: {threshold}")

            response = requests.post(url, json=payload, params=params, headers=headers, timeout=20)
            result = response.json()

            print(f"[人脸搜索] API响应: {result}")

            if 'error_code' in result and result['error_code'] != 0:
                error_code = result['error_code']
                error_msg = result.get('error_msg', '未知错误')

                if error_code == 216616:  # 组不存在
                    return {"matched": False, "user_id": "", "similarity": 0.0, "face_token": "", "message": "人脸库不存在"}
                elif error_code == 222202:
                    raise FaceServiceError("未检测到人脸，请确保画面中有人脸。")
                else:
                    raise FaceServiceError(f"人脸搜索失败: {error_msg}")

            if 'result' not in result or 'user_list' not in result['result']:
                return {"matched": False, "user_id": "", "similarity": 0.0, "face_token": ""}

            user_list = result['result']['user_list']
            if len(user_list) == 0:
                return {"matched": False, "user_id": "", "similarity": 0.0, "face_token": ""}

            best_match = user_list[0]
            raw_score = best_match.get('score', 0)
            similarity = raw_score / 100.0
            matched = bool(similarity >= threshold)

            return {
                "matched": matched,
                "user_id": best_match.get('user_id', ''),
                "similarity": similarity,
                "face_token": best_match.get('face_token', ''),
            }

        except FaceServiceError:
            raise
        except Exception as exc:
            print(f"[人脸搜索] 异常: {exc}")
            import traceback
            traceback.print_exc()
            raise FaceServiceError("人脸搜索失败，请稍后重试。") from exc

    def compare_with_encrypted_template(
        self,
        current_vector: np.ndarray,
        encrypted_template: str,
        aes_key: bytes,
        threshold: float = FACE_MATCH_THRESHOLD,
    ) -> FaceVerificationResult:
        """
        功能：将当前人脸图像与数据库加密模板进行比对。
        参数：
            current_vector (np.ndarray): 当前采集的人脸图像。
            encrypted_template (str): 数据库存储的加密模板（face_token）。
            aes_key (bytes): 32 字节 AES 密钥。
            threshold (float): 匹配阈值。
        返回值：
            FaceVerificationResult: 比对结果对象。
        注意事项：
            使用人脸搜索接口在用户组中查找匹配的人脸。
        """
        try:
            # 解密模板，得到face_token的字节表示
            stored_vector = self.decrypt_feature_vector(encrypted_template, aes_key)

            # 尝试解码为face_token
            token_bytes = stored_vector.tobytes()
            stored_face_token = token_bytes.decode('utf-8')

            # 检查是否是legacy特征
            if stored_face_token.startswith('legacy_feature_'):
                raise FaceServiceError("人脸特征已过期，请重新注册人脸。")

            # 确保current_vector是图像
            if current_vector.dtype != np.uint8 or len(current_vector.shape) != 3:
                raise FaceServiceError("当前人脸数据格式错误，请重新采集。")

            # 使用人脸搜索接口
            search_result = self.search_face_in_group(current_vector, "registered_users", threshold)

            if not search_result.get("matched", False):
                return FaceVerificationResult(similarity=search_result.get("similarity", 0.0), is_match=False)

            # 验证搜索到的face_token是否与存储的一致
            matched_face_token = search_result.get("face_token", "")
            matched_user_id = search_result.get("user_id", "")

            # 如果user_id与存储的face_token一致，则匹配成功
            # 注意：我们在注册时用face_token作为user_id存储
            is_match = matched_user_id == stored_face_token or matched_face_token == stored_face_token

            return FaceVerificationResult(
                similarity=search_result.get("similarity", 0.0),
                is_match=is_match
            )

        except FaceServiceError:
            raise
        except Exception as exc:
            print(f"[人脸比对] 异常: {exc}")
            import traceback
            traceback.print_exc()
            raise FaceServiceError("人脸特征比对失败，请稍后重试。") from exc


def resolve_landmark_model_path(config_mapping: dict[str, Any]) -> str:
    """
    功能：解析并规范化 Dlib 模型文件路径（保留函数用于兼容性）。
    参数：
        config_mapping (dict[str, Any]): Flask 配置映射。
    返回值：
        str: 规范化后的绝对路径或原始相对路径。
    注意事项：
        该函数不校验文件是否存在，仅负责路径展开。实际已不再使用Dlib模型。
    """
    model_path = str(config_mapping.get("DLIB_LANDMARK_MODEL_PATH", "")).strip()
    return os.path.normpath(model_path) if model_path else model_path