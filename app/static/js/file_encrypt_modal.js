"use strict";

/**
 * file_encrypt_modal.js
 * Handles the encrypt button click events and encrypt modal form submission.
 */

function initEncryptModal() {
    const encryptModal = document.getElementById("explorerEncryptModal");
    if (!encryptModal) {
        return;
    }

    const encryptForm = document.getElementById("explorerEncryptForm");
    const encryptFileGroupIdInput = document.getElementById("explorerEncryptFileGroupId");
    const encryptFileNameInput = document.getElementById("explorerEncryptFileName");
    const encryptLevelSelect = document.getElementById("explorerEncryptLevel");
    const encryptCloseButton = document.getElementById("explorerEncryptClose");
    const encryptCancelButton = document.getElementById("explorerEncryptCancel");
    const itemsContainer = document.getElementById("explorerItemsContainer");
    const progressPanel = document.getElementById("cryptoProgressPanel");
    const progressText = document.getElementById("cryptoProgressText");
    const progressBar = document.getElementById("cryptoProgressBar");
    const progressPercent = document.getElementById("cryptoProgressPercent");

    if (!encryptForm || !encryptFileGroupIdInput || !encryptFileNameInput || !encryptLevelSelect) {
        return;
    }

    const appRoot = document.getElementById("resourceExplorerApp");
    const csrfToken = appRoot ? appRoot.dataset.csrfToken || "" : "";

    const showModal = () => {
        encryptModal.classList.remove("is-hidden");
        encryptModal.setAttribute("aria-hidden", "false");
    };

    const hideModal = () => {
        encryptModal.classList.add("is-hidden");
        encryptModal.setAttribute("aria-hidden", "true");
        encryptFileGroupIdInput.value = "";
        encryptFileNameInput.value = "";
    };

    const showProgress = (text) => {
        if (!progressPanel || !progressText || !progressBar || !progressPercent) {
            return;
        }
        progressPanel.classList.remove("is-hidden");
        progressText.textContent = text || "正在处理...";
        progressBar.style.width = "0%";
        progressPercent.textContent = "0%";
    };

    const updateProgress = (value) => {
        if (!progressBar || !progressPercent) {
            return;
        }
        const normalized = Math.max(0, Math.min(100, Math.round(value)));
        progressBar.style.width = `${normalized}%`;
        progressPercent.textContent = `${normalized}%`;
    };

    const hideProgress = () => {
        if (!progressPanel) {
            return;
        }
        progressPanel.classList.add("is-hidden");
    };

    const notify = (message, category) => {
        if (typeof window.appNotify === "function") {
            window.appNotify(message, category);
            return;
        }
        window.alert(message);
    };

    const openEncryptModal = (fileGroupId, fileName) => {
        encryptFileGroupIdInput.value = fileGroupId || "";
        encryptFileNameInput.value = fileName || "";
        encryptLevelSelect.value = encryptLevelSelect.options[0]?.value || "秘密";
        showModal();
    };

    // Handle inline encrypt button clicks
    if (itemsContainer) {
        itemsContainer.addEventListener("click", (event) => {
            const encryptButton = event.target.closest("[data-inline-action='encrypt']");
            if (!encryptButton) {
                return;
            }

            event.preventDefault();
            const fileGroupId = encryptButton.dataset.fileGroupId || "";
            const fileName = encryptButton.dataset.fileName || "";

            if (!fileGroupId) {
                notify("文件ID无效。", "danger");
                return;
            }

            openEncryptModal(fileGroupId, fileName);
        });
    }

    // Handle encrypt modal close buttons
    if (encryptCloseButton) {
        encryptCloseButton.addEventListener("click", hideModal);
    }
    if (encryptCancelButton) {
        encryptCancelButton.addEventListener("click", hideModal);
    }

    // Close modal on backdrop click
    encryptModal.addEventListener("click", (event) => {
        if (event.target && event.target.hasAttribute("data-modal-close")) {
            hideModal();
        }
    });

    // Close modal on Escape key
    window.addEventListener("keydown", (event) => {
        if (event.key === "Escape" && !encryptModal.classList.contains("is-hidden")) {
            hideModal();
        }
    });

    // Handle encrypt form submission
    encryptForm.addEventListener("submit", async (event) => {
        event.preventDefault();

        const fileGroupId = encryptFileGroupIdInput.value;
        const level = encryptLevelSelect.value;

        if (!fileGroupId) {
            notify("文件ID无效。", "danger");
            return;
        }

        if (!level) {
            notify("请选择密级。", "danger");
            return;
        }

        const urlTemplate = appRoot?.dataset.manualEncryptUrlTemplate || "/files/{file_group_id}/manual/encrypt";
        const url = urlTemplate.replace("{file_group_id}", fileGroupId);

        showProgress("正在加密文件，请稍候...");

        let pseudoValue = 5;
        const pseudoTimer = window.setInterval(() => {
            pseudoValue = Math.min(86, pseudoValue + 3);
            updateProgress(pseudoValue);
        }, 150);

        try {
            const formData = new FormData();
            formData.append("csrf_token", csrfToken);
            formData.append("level", level);

            const response = await fetch(url, {
                method: "POST",
                credentials: "same-origin",
                headers: {
                    "X-Requested-With": "XMLHttpRequest",
                    Accept: "application/json",
                    "X-CSRF-Token": csrfToken,
                },
                body: formData,
            });

            window.clearInterval(pseudoTimer);

            let payload = null;
            try {
                payload = await response.json();
            } catch (_error) {
                payload = null;
            }

            if (response.ok && payload && payload.status === "success") {
                updateProgress(100);
                hideModal();
                notify(payload.message || "加密成功。", "success");
                window.setTimeout(() => {
                    window.location.reload();
                }, 150);
                return;
            }

            hideProgress();
            hideModal();
            notify((payload && payload.message) || "加密失败，请稍后重试。", "danger");
        } catch (_error) {
            window.clearInterval(pseudoTimer);
            hideProgress();
            hideModal();
            notify("网络异常，请稍后重试。", "danger");
        }
    });
}

document.addEventListener("DOMContentLoaded", () => {
    initEncryptModal();
});