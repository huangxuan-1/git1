"use strict";

/**
 * 人脸录入模块 - 简化活体检测版
 * 第一步：采集基础人脸照片（上传或摄像头）
 * 第二步：人脸一致性验证（采集一帧，调用百度云1:1比对）
 *
 * 流程：用户点击「开始」 -> 打开摄像头 -> 检测人脸对准 -> 自动采集一帧 -> 调用百度云比对（阈值>=0.7） -> 通过/失败
 */

// ========== 全局变量 ==========

let baseFaceMesh = null;
let baseCamera = null;
let livenessStream = null;  // 活体检测摄像头流（原生API）
let livenessCanvas = null;  // 采集帧用的canvas

// 状态机（简化版：只保留人脸对准和完成）
const STATUS = {
    INIT: 0,
    FACE_ALIGN: 1,
    FINISH: 2
};
let currentStatus = STATUS.INIT;
let stepTimer = null;  // 检测定时器

// API请求冷却时间（防止QPS限制）
const API_COOLDOWN_MS = 2000;  // 2秒冷却时间
let lastApiCallTime = 0;
let apiCallPending = false;

// ========== 工具函数 ==========

function showError(message) {
    const errorBox = document.getElementById('error-box');
    const errorText = document.getElementById('error-text');
    if (errorBox && errorText) {
        errorText.textContent = message;
        errorBox.classList.remove('hidden');
        console.error('[错误]', message);
    }
}

function clearError() {
    const errorBox = document.getElementById('error-box');
    if (errorBox) {
        errorBox.classList.add('hidden');
    }
}

function compressImage(dataUrl, maxWidth = 400, maxHeight = 300, quality = 0.8) {
    return new Promise((resolve) => {
        const img = new Image();
        img.onload = function() {
            let w = img.width, h = img.height;
            if (w > maxWidth || h > maxHeight) {
                const ratio = Math.min(maxWidth / w, maxHeight / h);
                w = Math.round(w * ratio);
                h = Math.round(h * ratio);
            }
            const canvas = document.createElement('canvas');
            canvas.width = w;
            canvas.height = h;
            const ctx = canvas.getContext('2d');
            ctx.drawImage(img, 0, 0, w, h);
            resolve(canvas.toDataURL('image/jpeg', quality));
        };
        img.src = dataUrl;
    });
}

function captureFrame(video) {
    if (!video || !video.videoWidth) return null;
    const canvas = document.createElement('canvas');
    canvas.width = video.videoWidth;
    canvas.height = video.videoHeight;
    const ctx = canvas.getContext('2d');
    ctx.drawImage(video, 0, 0);
    return canvas.toDataURL('image/jpeg', 0.85);
}

// 检查是否可以进行API调用（防止QPS限制）
function canMakeApiCall() {
    const now = Date.now();
    const elapsed = now - lastApiCallTime;
    return elapsed >= API_COOLDOWN_MS && !apiCallPending;
}

// 等待API冷却时间
async function waitForApiCooldown() {
    const now = Date.now();
    const elapsed = now - lastApiCallTime;
    if (elapsed < API_COOLDOWN_MS) {
        const waitTime = API_COOLDOWN_MS - elapsed;
        console.log(`[API冷却] 等待 ${waitTime}ms 后再请求...`);
        await new Promise(resolve => setTimeout(resolve, waitTime));
    }
}

// ========== 界面更新函数 ==========

function updatePrompt(text) {
    const actionText = document.getElementById('liveness-action-text');
    const guideText = document.getElementById('liveness-guide');
    if (actionText) actionText.textContent = text;
    if (guideText) guideText.textContent = text;
    console.log('[提示]', text);
}

// ========== 第一步：基础人脸采集 ==========

function initBaseFaceCapture() {
    const tabUpload = document.getElementById('tab-upload');
    const tabCamera = document.getElementById('tab-camera');
    const contentUpload = document.getElementById('content-upload');
    const contentCamera = document.getElementById('content-camera');

    const fileInput = document.getElementById('base_photo_file_input');
    const uploadImg = document.getElementById('base_photo_upload_img');
    const uploadPreview = document.getElementById('upload-preview');

    const cameraVideo = document.getElementById('base-camera-video');
    const cameraPlaceholder = document.getElementById('base-video-placeholder');
    const startCameraBtn = document.getElementById('base-camera-start');
    const captureBtn = document.getElementById('base-camera-capture');
    const stopCameraBtn = document.getElementById('base-camera-stop');

    const basePhotoDataInput = document.getElementById('base_photo_data');
    const baseFaceTokenInput = document.getElementById('base_face_token');
    const confirmBtn = document.getElementById('confirm-base-photo');

    const stepBaseFace = document.getElementById('step-base-face');
    const stepLiveness = document.getElementById('step-liveness');

    let basePhotoReady = false;

    // 标签页切换
    tabUpload.addEventListener('click', () => {
        tabUpload.classList.add('active');
        tabCamera.classList.remove('active');
        contentUpload.classList.add('active');
        contentCamera.classList.remove('active');
        stopBaseCamera();
    });

    tabCamera.addEventListener('click', () => {
        tabCamera.classList.add('active');
        tabUpload.classList.remove('active');
        contentCamera.classList.add('active');
        contentUpload.classList.remove('active');
    });

    // 文件上传
    fileInput.addEventListener('change', async () => {
        clearError();
        const file = fileInput.files[0];
        if (!file) return;

        const reader = new FileReader();
        reader.onload = async (e) => {
            const compressed = await compressImage(e.target.result);
            uploadImg.src = compressed;
            uploadImg.style.display = 'block';
            const placeholder = uploadPreview.querySelector('.preview-placeholder');
            if (placeholder) placeholder.style.display = 'none';
            basePhotoDataInput.value = compressed;
            updateConfirmBtn();
            console.log('[第一步] 图片上传完成，已压缩');
        };
        reader.readAsDataURL(file);
    });

    // 摄像头控制
    function stopBaseCamera() {
        if (baseCamera) {
            baseCamera.stop();
            baseCamera = null;
        }
        if (baseFaceMesh) {
            baseFaceMesh.close();
            baseFaceMesh = null;
        }
        cameraVideo.srcObject = null;
        cameraPlaceholder.classList.remove('hidden');
        startCameraBtn.classList.remove('hidden');
        captureBtn.disabled = true;
        stopCameraBtn.classList.add('hidden');
    }

    startCameraBtn.addEventListener('click', async () => {
        clearError();
        try {
            // 初始化 MediaPipe FaceMesh
            baseFaceMesh = new FaceMesh({
                locateFile: (file) => {
                    return `https://cdn.jsdelivr.net/npm/@mediapipe/face_mesh@0.4.1633559619/${file}`;
                }
            });

            baseFaceMesh.setOptions({
                maxNumFaces: 1,
                refineLandmarks: true,
                minDetectionConfidence: 0.5,
                minTrackingConfidence: 0.5
            });

            baseFaceMesh.onResults((results) => {
                if (results.multiFaceLandmarks && results.multiFaceLandmarks.length > 0) {
                    console.log('[第一步-摄像头] 人脸已检测到');
                }
            });

            // 初始化摄像头
            baseCamera = new Camera(cameraVideo, {
                onFrame: async () => {
                    if (baseFaceMesh) {
                        await baseFaceMesh.send({ image: cameraVideo });
                    }
                },
                width: 480,
                height: 360
            });

            await baseCamera.start();
            cameraPlaceholder.classList.add('hidden');
            startCameraBtn.classList.add('hidden');
            captureBtn.disabled = false;
            stopCameraBtn.classList.remove('hidden');
            console.log('[第一步] 摄像头已开启（MediaPipe）');

        } catch (e) {
            console.error('[第一步] MediaPipe 初始化失败:', e);
            // 降级到普通摄像头（原生API，100%兼容）
            try {
                const stream = await navigator.mediaDevices.getUserMedia({
                    video: { facingMode: 'user', width: { ideal: 480 }, height: { ideal: 360 } }
                });
                cameraVideo.srcObject = stream;
                cameraPlaceholder.classList.add('hidden');
                startCameraBtn.classList.add('hidden');
                captureBtn.disabled = false;
                stopCameraBtn.classList.remove('hidden');
                baseCamera = { stop: () => stream.getTracks().forEach(t => t.stop()) };
                console.log('[第一步] 摄像头已开启（原生API降级模式）');
            } catch (err) {
                showError('无法开启摄像头: ' + err.message);
            }
        }
    });

    stopCameraBtn.addEventListener('click', stopBaseCamera);

    captureBtn.addEventListener('click', async () => {
        const frame = captureFrame(cameraVideo);
        if (!frame) {
            showError('图像采集失败');
            return;
        }
        const compressed = await compressImage(frame);
        uploadImg.src = compressed;
        uploadImg.style.display = 'block';
        const placeholder = uploadPreview.querySelector('.preview-placeholder');
        if (placeholder) placeholder.style.display = 'none';

        basePhotoDataInput.value = compressed;
        stopBaseCamera();
        updateConfirmBtn();

        // 切换到上传预览显示
        tabUpload.click();
        console.log('[第一步] 摄像头采集完成');
    });

    function updateConfirmBtn() {
        confirmBtn.disabled = !basePhotoDataInput.value;
    }

    // 确认基础人脸
    confirmBtn.addEventListener('click', async () => {
        if (basePhotoReady) return;
        clearError();

        if (!basePhotoDataInput.value) {
            showError('请先采集基础人脸照片');
            return;
        }

        // 等待API冷却时间
        await waitForApiCooldown();

        confirmBtn.disabled = true;
        confirmBtn.textContent = '正在检测...';

        const form = document.getElementById('register-form');
        const qualityUrl = form.dataset.qualityUrl;

        try {
            lastApiCallTime = Date.now();
            apiCallPending = true;

            const formData = new FormData();
            formData.append('base_photo_data', basePhotoDataInput.value);

            console.log('[第一步] 发送质量检测请求');

            const resp = await fetch(qualityUrl, {
                method: 'POST',
                credentials: 'include',
                body: formData
            });

            const text = await resp.text();
            console.log('[第一步] 响应:', resp.status, text.substring(0, 200));

            apiCallPending = false;

            if (text.trim().startsWith('<')) {
                showError('登录状态失效，请刷新页面重新登录');
                confirmBtn.disabled = false;
                confirmBtn.textContent = '确认基础人脸';
                return;
            }

            const result = JSON.parse(text);

            if (result.status !== 'success') {
                let failMsg = result.message || '质量检测未通过';
                // 检查是否是QPS限制错误
                if (failMsg.includes('qps') || failMsg.includes('QPS') || failMsg.includes('request limit')) {
                    failMsg = '百度云API请求频率超限，请等待2秒后重试';
                }
                showError(failMsg);
                confirmBtn.disabled = false;
                confirmBtn.textContent = '确认基础人脸';
                return;
            }

            // 成功
            console.log('[第一步] 质量检测通过, face_token:', result.face_token);
            baseFaceTokenInput.value = result.face_token || '';
            basePhotoReady = true;
            confirmBtn.textContent = '已确认';

            // 隐藏第一步，显示第二步
            stepBaseFace.classList.add('hidden');
            stepLiveness.classList.remove('hidden');

        } catch (e) {
            apiCallPending = false;
            showError('请求失败: ' + e.message);
            confirmBtn.disabled = false;
            confirmBtn.textContent = '确认基础人脸';
        }
    });

    // 导出状态
    window.getBasePhotoData = () => basePhotoDataInput.value;
    window.getBaseFaceToken = () => baseFaceTokenInput.value;
    window.isBasePhotoReady = () => basePhotoReady;
}

// ========== 第二步：人脸一致性验证（简化流程） ==========

function initLivenessDetection() {
    const stepLiveness = document.getElementById('step-liveness');
    const stepComplete = document.getElementById('step-complete');

    const video = document.getElementById('liveness-video');

    const livenessFrameInput = document.getElementById('liveness_frame_data');
    const livenessPassedInput = document.getElementById('liveness_passed');

    const form = document.getElementById('register-form');
    const matchUrl = form.dataset.matchUrl;  // 使用页面已有的后端接口URL

    const startBtn = document.getElementById('start-liveness');
    const restartBtn = document.getElementById('restart-liveness');

    // 初始化 canvas 用于采集帧
    livenessCanvas = document.createElement('canvas');

    // 停止活体检测摄像头
    function stopLivenessCamera() {
        if (stepTimer) {
            clearTimeout(stepTimer);
            stepTimer = null;
        }
        if (livenessStream) {
            livenessStream.getTracks().forEach(track => track.stop());
            livenessStream = null;
        }
        if (video) {
            video.srcObject = null;
        }
    }

    // 核心函数：用原生浏览器API打开摄像头
    async function startLivenessCamera() {
        try {
            console.log('[第二步] 正在打开摄像头（原生API）...');

            livenessStream = await navigator.mediaDevices.getUserMedia({
                video: {
                    width: { ideal: 480 },
                    height: { ideal: 360 },
                    facingMode: "user" // 前置摄像头
                }
            });

            video.srcObject = livenessStream;
            video.play();

            console.log('[第二步] 摄像头已打开，等待人脸对准');

            video.onloadedmetadata = () => {
                startFaceDetection();
            };

        } catch (error) {
            console.error('[第二步] 摄像头打开失败:', error);
            showError('摄像头打开失败，请检查权限后重试');
            startBtn.classList.remove('hidden');
        }
    }

    // 人脸对准检测流程（简化版：只需对准即可采集）
    function startFaceDetection() {
        currentStatus = STATUS.FACE_ALIGN;
        updatePrompt("请将面部对准画面中心");

        // 等待3秒后自动采集人脸帧（增加等待时间以避免QPS限制）
        stepTimer = setTimeout(() => {
            updatePrompt("正在采集人脸...");
            captureAndVerifyFace();
        }, 3000);
    }

    // 采集人脸并调用后端百度云比对
    async function captureAndVerifyFace() {
        try {
            // 检查是否有API调用正在进行
            if (apiCallPending) {
                console.log('[第二步] API调用正在进行，跳过此次请求');
                return;
            }

            // 等待API冷却时间
            await waitForApiCooldown();

            apiCallPending = true;
            lastApiCallTime = Date.now();

            livenessCanvas.width = video.videoWidth || 480;
            livenessCanvas.height = video.videoHeight || 360;
            const ctx = livenessCanvas.getContext("2d");
            ctx.drawImage(video, 0, 0);
            const faceBase64 = livenessCanvas.toDataURL("image/jpeg", 0.85);

            livenessFrameInput.value = faceBase64;

            stopLivenessCamera();

            console.log('[第二步] 正在调用后端百度云接口...');

            const formData = new FormData();
            formData.append('base_photo_data', window.getBasePhotoData());
            formData.append('base_face_token', window.getBaseFaceToken());
            formData.append('liveness_frame_data', faceBase64);

            const resp = await fetch(matchUrl, {
                method: 'POST',
                credentials: 'include',
                body: formData
            });

            const text = await resp.text();
            console.log('[第二步] 后端响应:', resp.status);

            apiCallPending = false;

            if (text.trim().startsWith('<')) {
                showError('登录状态失效，请刷新页面重新登录');
                currentStatus = STATUS.INIT;
                startBtn.classList.add('hidden');
                restartBtn.classList.remove('hidden');
                updatePrompt('验证失败，请重新检测');
                return;
            }

            const data = JSON.parse(text);
            console.log('[第二步] 验证结果:', data);

            if (data.status === 'success') {
                console.log('[第二步] 人脸验证成功，相似度:', data.similarity);
                livenessPassedInput.value = 'true';
                currentStatus = STATUS.FINISH;

                updatePrompt("人脸验证成功");
                setTimeout(() => {
                    stepLiveness.classList.add('hidden');
                    stepComplete.classList.remove('hidden');
                }, 500);

            } else {
                let failReason = data.message || '人脸验证失败';
                // 检查是否是QPS限制错误
                if (failReason.includes('qps') || failReason.includes('QPS') || failReason.includes('request limit')) {
                    failReason = '百度云API请求频率超限，请等待2秒后点击"重新检测"';
                }
                if (data.similarity && data.similarity < 0.7) {
                    failReason = `人脸不一致，相似度: ${data.similarity.toFixed(2)}，阈值: 0.7`;
                }
                showError(failReason);
                updatePrompt('验证失败: ' + failReason);
                currentStatus = STATUS.INIT;
                startBtn.classList.add('hidden');
                restartBtn.classList.remove('hidden');
            }

        } catch (error) {
            console.error('[第二步] 采集人脸失败:', error);
            apiCallPending = false;
            showError('网络错误，请重试');
            updatePrompt('验证失败，请重新检测');
            currentStatus = STATUS.INIT;
            startBtn.classList.add('hidden');
            restartBtn.classList.remove('hidden');
        }
    }

    // 开始人脸验证
    startBtn.addEventListener('click', async () => {
        clearError();
        if (!window.isBasePhotoReady()) {
            showError('请先完成基础人脸采集');
            return;
        }

        currentStatus = STATUS.INIT;
        updatePrompt('正在打开摄像头...');

        startBtn.classList.add('hidden');
        restartBtn.classList.add('hidden');

        await startLivenessCamera();
    });

    // 重新检测
    restartBtn.addEventListener('click', async () => {
        clearError();

        stopLivenessCamera();

        currentStatus = STATUS.INIT;
        updatePrompt('请将面部对准画面中心');

        startBtn.classList.add('hidden');
        restartBtn.classList.add('hidden');

        startBtn.click();
    });

    // 页面卸载时关闭摄像头
    window.addEventListener('beforeunload', () => {
        stopLivenessCamera();
        if (baseCamera) baseCamera.stop();
        if (baseFaceMesh) baseFaceMesh.close();
    });
}

// ========== 人脸比对模块（非录入流程，保留原有逻辑） ==========

function initVerifyModule() {
    const verifyForm = document.getElementById('verify-form');
    if (!verifyForm) return;

    const tabs = verifyForm.querySelectorAll('.tab-btn');
    const verifyUpload = document.getElementById('verify-upload');
    const verifyCamera = document.getElementById('verify-camera');
    const verifyVideo = document.getElementById('verify-video');
    const startBtn = document.getElementById('verify-camera-start');
    const stopBtn = document.getElementById('verify-camera-stop');
    const captureBtn = document.getElementById('verify-capture');
    const verifyImg = document.getElementById('verify_preview_img');
    const verifyPlaceholder = verifyImg ? verifyImg.parentElement.querySelector('.preview-placeholder') : null;
    const verifyDataInput = document.getElementById('verify_image_data');

    let stream = null;

    // 标签切换
    tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            tabs.forEach(t => t.classList.remove('active'));
            tab.classList.add('active');

            const tabId = tab.dataset.tab;
            if (tabId === 'verify-upload') {
                verifyUpload.classList.add('active');
                verifyCamera.classList.remove('active');
                if (stream) stopStream();
            } else {
                verifyCamera.classList.add('active');
                verifyUpload.classList.remove('active');
            }
        });
    });

    function stopStream() {
        if (stream) {
            stream.getTracks().forEach(t => t.stop());
            stream = null;
        }
        if (verifyVideo) verifyVideo.srcObject = null;
        if (captureBtn) captureBtn.disabled = true;
    }

    if (startBtn) {
        startBtn.addEventListener('click', async () => {
            try {
                stream = await navigator.mediaDevices.getUserMedia({
                    video: { facingMode: 'user' }
                });
                if (verifyVideo) verifyVideo.srcObject = stream;
                if (captureBtn) captureBtn.disabled = false;
            } catch (e) {
                showError('无法开启摄像头');
            }
        });
    }

    if (stopBtn) {
        stopBtn.addEventListener('click', stopStream);
    }

    if (captureBtn) {
        captureBtn.addEventListener('click', async () => {
            const frame = captureFrame(verifyVideo);
            if (!frame) return;

            const compressed = await compressImage(frame);
            if (verifyImg) {
                verifyImg.src = compressed;
                verifyImg.style.display = 'block';
            }
            if (verifyPlaceholder) verifyPlaceholder.style.display = 'none';
            if (verifyDataInput) verifyDataInput.value = compressed;
        });
    }

    window.addEventListener('beforeunload', () => {
        if (stream) stopStream();
    });
}

// ========== 初始化 ==========

document.addEventListener('DOMContentLoaded', () => {
    initBaseFaceCapture();
    initLivenessDetection();
    initVerifyModule();
});