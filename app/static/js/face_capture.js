"use strict";

function notify(message, category) {
    if (typeof window.appNotify === "function") {
        window.appNotify(message, category || "danger");
        return;
    }
    window.alert(message);
}

/**
 * 功能：切换输入模式（上传/摄像头）。
 * 参数：
 *   - radioName: 单选框组名。
 *   - uploadBlockId: 上传区域元素 ID。
 *   - cameraBlockId: 摄像头区域元素 ID。
 * 返回值：无。
 * 注意事项：会根据当前选择动态隐藏或显示对应区域。
 */
function initModeSwitch(radioName, uploadBlockId, cameraBlockId) {
    const radios = document.querySelectorAll(`input[name="${radioName}"]`);
    const uploadBlock = document.getElementById(uploadBlockId);
    const cameraBlock = document.getElementById(cameraBlockId);

    const toggle = () => {
        const checkedRadio = document.querySelector(`input[name="${radioName}"]:checked`);
        const isCamera = checkedRadio && checkedRadio.value === "camera";

        if (uploadBlock) {
            uploadBlock.style.display = isCamera ? "none" : "grid";
        }
        if (cameraBlock) {
            cameraBlock.style.display = isCamera ? "grid" : "none";
        }
    };

    radios.forEach((radio) => {
        radio.addEventListener("change", toggle);
    });
    toggle();
}

/**
 * 功能：初始化摄像头采集区域。
 * 参数：
 *   - config: 摄像头区域配置对象。
 * 返回值：无。
 * 注意事项：支持启动、关闭和帧采集预览。
 */
function initCameraArea(config) {
    const video = document.getElementById(config.videoId);
    const startButton = document.getElementById(config.startButtonId);
    const stopButton = document.getElementById(config.stopButtonId);
    let mediaStream = null;

    const stopCamera = () => {
        if (mediaStream) {
            mediaStream.getTracks().forEach((track) => track.stop());
            mediaStream = null;
        }
        if (video) {
            video.srcObject = null;
        }
    };

    const startCamera = async () => {
        try {
            if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
                notify("当前浏览器不支持摄像头采集功能。", "danger");
                return;
            }

            mediaStream = await navigator.mediaDevices.getUserMedia({
                video: {
                    width: { ideal: 640 },
                    height: { ideal: 480 },
                    facingMode: "user",
                },
                audio: false,
            });
            video.srcObject = mediaStream;
        } catch (error) {
            notify("摄像头开启失败，请检查浏览器权限设置。", "danger");
            console.error(error);
        }
    };

    if (startButton) {
        startButton.addEventListener("click", () => {
            startCamera();
        });
    }

    if (stopButton) {
        stopButton.addEventListener("click", () => {
            stopCamera();
        });
    }

    document.querySelectorAll(config.captureSelector).forEach((button) => {
        button.addEventListener("click", () => {
            if (!video || !video.videoWidth || !video.videoHeight) {
                notify("摄像头尚未就绪，请先开启摄像头。", "danger");
                return;
            }

            const inputId = button.dataset.inputId;
            const previewId = button.dataset.previewId;
            const hiddenInput = document.getElementById(inputId);
            const previewImage = document.getElementById(previewId);

            if (!hiddenInput || !previewImage) {
                return;
            }

            const canvas = document.createElement("canvas");
            canvas.width = video.videoWidth;
            canvas.height = video.videoHeight;
            const context = canvas.getContext("2d");
            context.drawImage(video, 0, 0, canvas.width, canvas.height);

            const dataUrl = canvas.toDataURL("image/jpeg", 0.92);
            hiddenInput.value = dataUrl;
            previewImage.src = dataUrl;
        });
    });

    window.addEventListener("beforeunload", () => {
        stopCamera();
    });
}

document.addEventListener("DOMContentLoaded", () => {
    initModeSwitch("register_mode", "register-upload-block", "register-camera-block");
    initModeSwitch("verify_mode", "verify-upload-block", "verify-camera-block");

    initCameraArea({
        videoId: "register-video",
        startButtonId: "register-camera-start",
        stopButtonId: "register-camera-stop",
        captureSelector: "#register-camera-block .capture-button",
    });

    initCameraArea({
        videoId: "verify-video",
        startButtonId: "verify-camera-start",
        stopButtonId: "verify-camera-stop",
        captureSelector: "#verify-camera-block .capture-button",
    });
});
