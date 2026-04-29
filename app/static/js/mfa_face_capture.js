"use strict";

function notify(message, category) {
    if (typeof window.appNotify === "function") {
        window.appNotify(message, category || "danger");
        return;
    }
    window.alert(message);
}

/**
 * 功能：初始化双因子人脸验证阶段的摄像头采集。
 * 参数：无。
 * 返回值：无。
 * 注意事项：仅在用户选择摄像头采集时使用。
 */
document.addEventListener("DOMContentLoaded", () => {
    const video = document.getElementById("camera-video");
    const startButton = document.getElementById("camera-start");
    const stopButton = document.getElementById("camera-stop");
    const captureButtons = document.querySelectorAll(".capture-button");
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
                notify("当前浏览器不支持摄像头采集。", "danger");
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
            notify("摄像头开启失败，请检查权限设置。", "danger");
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

    captureButtons.forEach((button) => {
        button.addEventListener("click", () => {
            if (!video || !video.videoWidth || !video.videoHeight) {
                notify("摄像头未就绪，请先开启摄像头。", "danger");
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
});
