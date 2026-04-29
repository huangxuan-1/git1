"use strict";

function notify(message, category) {
    if (typeof window.appNotify === "function") {
        window.appNotify(message, category);
        return;
    }
    window.alert(message);
}

/**
 * 功能：创建进度条上下文对象。
 * 参数：无。
 * 返回值：
 *   - Object | null: 进度条上下文。
 * 注意事项：页面不存在进度条节点时返回 null。
 */
function createProgressContext() {
    const panel = document.getElementById("cryptoProgressPanel");
    const textElement = document.getElementById("cryptoProgressText");
    const barElement = document.getElementById("cryptoProgressBar");
    const percentElement = document.getElementById("cryptoProgressPercent");

    if (!panel || !textElement || !barElement || !percentElement) {
        return null;
    }

    return {
        panel,
        textElement,
        barElement,
        percentElement,
        value: 0,
    };
}

/**
 * 功能：显示进度条面板。
 * 参数：
 *   - context: 进度条上下文。
 *   - text: 提示文本。
 * 返回值：无。
 * 注意事项：显示时会重置进度为 0。
 */
function showProgress(context, text) {
    if (!context) {
        return;
    }

    context.panel.classList.remove("is-hidden");
    context.textElement.textContent = text || "正在处理...";
    updateProgress(context, 0);
}

/**
 * 功能：更新进度条百分比。
 * 参数：
 *   - context: 进度条上下文。
 *   - value: 百分比。
 * 返回值：无。
 * 注意事项：自动限制在 0-100 范围内。
 */
function updateProgress(context, value) {
    if (!context) {
        return;
    }

    const normalized = Math.max(0, Math.min(100, Math.round(value)));
    context.value = normalized;
    context.barElement.style.width = `${normalized}%`;
    context.percentElement.textContent = `${normalized}%`;
}

/**
 * 功能：隐藏进度条面板。
 * 参数：
 *   - context: 进度条上下文。
 * 返回值：无。
 * 注意事项：隐藏时不清空文本。
 */
function hideProgress(context) {
    if (!context) {
        return;
    }
    context.panel.classList.add("is-hidden");
}

/**
 * 功能：解析 Content-Disposition 中的文件名。
 * 参数：
 *   - disposition: 响应头文本。
 * 返回值：
 *   - string | null: 解析出的文件名。
 * 注意事项：支持 RFC5987 filename* 语法。
 */
function parseFileNameFromDisposition(disposition) {
    if (!disposition) {
        return null;
    }

    const utf8Match = disposition.match(/filename\*=UTF-8''([^;]+)/i);
    if (utf8Match && utf8Match[1]) {
        try {
            return decodeURIComponent(utf8Match[1]);
        } catch (_error) {
            return utf8Match[1];
        }
    }

    const plainMatch = disposition.match(/filename="?([^";]+)"?/i);
    if (plainMatch && plainMatch[1]) {
        return plainMatch[1];
    }

    return null;
}

/**
 * 功能：触发浏览器保存 Blob 文件。
 * 参数：
 *   - blob: 二进制对象。
 *   - fileName: 下载文件名。
 * 返回值：无。
 * 注意事项：创建的临时 URL 会在触发后回收。
 */
function triggerBlobDownload(blob, fileName) {
    const anchor = document.createElement("a");
    const objectUrl = URL.createObjectURL(blob);
    anchor.href = objectUrl;
    anchor.download = fileName || "download.bin";
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(objectUrl);
}

/**
 * 功能：使用 XHR 提交表单并展示进度。
 * 参数：
 *   - formElement: 表单元素。
 *   - context: 进度条上下文。
 * 返回值：无。
 * 注意事项：用于上传、删除、手动加密等操作。
 */
function submitFormWithProgress(formElement, context) {
    const method = (formElement.method || "POST").toUpperCase();
    const action = formElement.action;
    const progressText = formElement.dataset.progressText || "正在处理...";
    const expectsJson = formElement.dataset.expectJson === "true";
    const csrfField = formElement.querySelector("input[name='csrf_token']");

    showProgress(context, progressText);

    let pseudoValue = 4;
    const pseudoTimer = window.setInterval(() => {
        pseudoValue = Math.min(88, pseudoValue + 3);
        updateProgress(context, pseudoValue);
    }, 140);

    const xhr = new XMLHttpRequest();
    xhr.open(method, action, true);
    xhr.responseType = "text";
    xhr.setRequestHeader("X-Requested-With", "XMLHttpRequest");
    if (expectsJson) {
        xhr.setRequestHeader("Accept", "application/json");
    }
    if (csrfField && csrfField.value) {
        xhr.setRequestHeader("X-CSRF-Token", csrfField.value);
    }

    xhr.upload.addEventListener("progress", (event) => {
        if (!event.lengthComputable) {
            return;
        }
        const uploadProgress = Math.min(92, Math.round((event.loaded / event.total) * 92));
        pseudoValue = Math.max(pseudoValue, uploadProgress);
        updateProgress(context, pseudoValue);
    });

    xhr.addEventListener("load", () => {
        window.clearInterval(pseudoTimer);
        let payload = null;
        if (expectsJson) {
            try {
                payload = JSON.parse(xhr.responseText || "{}");
            } catch (_error) {
                payload = null;
            }

            if (xhr.status >= 200 && xhr.status < 300 && payload && payload.status === "success") {
                updateProgress(context, 100);
                window.setTimeout(() => {
                    window.location.reload();
                }, 120);
                return;
            }

            hideProgress(context);
            notify((payload && payload.message) || "请求失败，请稍后重试。", "danger");
            return;
        }

        if (xhr.status >= 200 && xhr.status < 400) {
            updateProgress(context, 100);
            const nextUrl = xhr.responseURL || window.location.href;
            window.setTimeout(() => {
                window.location.assign(nextUrl);
            }, 120);
            return;
        }

        hideProgress(context);
        notify("请求失败，请稍后重试。", "danger");
    });

    xhr.addEventListener("error", () => {
        window.clearInterval(pseudoTimer);
        hideProgress(context);
        notify("请求失败，请稍后重试。", "danger");
    });

    xhr.send(new FormData(formElement));
}

/**
 * 功能：下载文件并显示解密/下载进度。
 * 参数：
 *   - linkElement: 下载链接。
 *   - context: 进度条上下文。
 * 返回值：
 *   - Promise<void>
 * 注意事项：若响应为 HTML（通常是重定向后的页面），将回退为页面跳转。
 */
async function downloadWithProgress(linkElement, context) {
    const progressText = linkElement.dataset.progressText || "正在下载...";
    showProgress(context, progressText);

    try {
        const response = await fetch(linkElement.href, {
            method: "GET",
            credentials: "same-origin",
        });

        if (!response.ok) {
            hideProgress(context);
            window.location.assign(linkElement.href);
            return;
        }

        const contentType = response.headers.get("content-type") || "";
        if (contentType.includes("text/html")) {
            hideProgress(context);
            window.location.assign(response.url || linkElement.href);
            return;
        }

        const contentLength = Number(response.headers.get("content-length") || "0");
        const reader = response.body ? response.body.getReader() : null;

        if (!reader) {
            const fallbackBlob = await response.blob();
            updateProgress(context, 100);
            const fallbackName =
                parseFileNameFromDisposition(response.headers.get("content-disposition")) ||
                linkElement.dataset.downloadName ||
                "download.bin";
            triggerBlobDownload(fallbackBlob, fallbackName);
            window.setTimeout(() => hideProgress(context), 200);
            return;
        }

        let loaded = 0;
        let pseudo = 8;
        const chunks = [];

        while (true) {
            const { done, value } = await reader.read();
            if (done) {
                break;
            }

            chunks.push(value);
            loaded += value.length;

            if (contentLength > 0) {
                updateProgress(context, Math.round((loaded / contentLength) * 100));
            } else {
                pseudo = Math.min(95, pseudo + 2);
                updateProgress(context, pseudo);
            }
        }

        const blob = new Blob(chunks, { type: contentType || "application/octet-stream" });
        const fileName =
            parseFileNameFromDisposition(response.headers.get("content-disposition")) ||
            linkElement.dataset.downloadName ||
            "download.bin";

        updateProgress(context, 100);
        triggerBlobDownload(blob, fileName);
        window.setTimeout(() => hideProgress(context), 200);
    } catch (_error) {
        hideProgress(context);
        window.location.assign(linkElement.href);
    }
}

/**
 * 功能：提交资源管理器操作并返回 JSON 结果。
 * 参数：
 *   - options: 请求参数对象。
 * 返回值：
 *   - Promise<Object>: 操作结果。
 * 注意事项：统一用于新建文件夹、重命名与删除。
 */
async function postExplorerAction(options) {
    const url = options.url;
    const csrfToken = options.csrfToken || "";
    const fields = options.fields || {};
    const progressContext = options.progressContext || null;
    const progressText = options.progressText || "正在处理...";

    if (!url) {
        return { ok: false, message: "请求地址无效。" };
    }

    let pseudoTimer = 0;
    let pseudoValue = 5;
    if (progressContext) {
        showProgress(progressContext, progressText);
        pseudoTimer = window.setInterval(() => {
            pseudoValue = Math.min(86, pseudoValue + 3);
            updateProgress(progressContext, pseudoValue);
        }, 150);
    }

    try {
        const formData = new FormData();
        Object.keys(fields).forEach((fieldName) => {
            formData.append(fieldName, fields[fieldName]);
        });

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

        let payload = null;
        try {
            payload = await response.json();
        } catch (_error) {
            payload = null;
        }

        if (pseudoTimer) {
            window.clearInterval(pseudoTimer);
        }

        if (response.ok && payload && payload.status === "success") {
            if (progressContext) {
                updateProgress(progressContext, 100);
            }
            return { ok: true, message: payload.message || "操作成功。" };
        }

        if (progressContext) {
            hideProgress(progressContext);
        }

        return {
            ok: false,
            message: (payload && payload.message) || "请求失败，请稍后重试。",
        };
    } catch (_error) {
        if (pseudoTimer) {
            window.clearInterval(pseudoTimer);
        }
        if (progressContext) {
            hideProgress(progressContext);
        }
        return { ok: false, message: "网络异常，请稍后重试。" };
    }
}

/**
 * 功能：初始化资源管理器交互（目录导航、右键菜单、置顶、列表/图标视图）。
 * 参数：
 *   - progressContext: 进度条上下文。
 * 返回值：无。
 * 注意事项：仅在文件列表页存在资源管理器容器时启用。
 */
function initResourceExplorer(progressContext) {
    const appRoot = document.getElementById("resourceExplorerApp");
    if (!appRoot) {
        return;
    }

    const csrfToken = appRoot.dataset.csrfToken || "";
    const parentId = appRoot.dataset.parentId || "0";
    const defaultNewFolderLevel = appRoot.dataset.defaultNewFolderLevel || "秘密";
    const createFolderUrl = appRoot.dataset.createFolderUrl || "";
    const rootUrl = appRoot.dataset.rootUrl || "";
    const parentUrl = appRoot.dataset.parentUrl || "";

    const itemsContainer = document.getElementById("explorerItemsContainer");
    const listHeader = document.getElementById("explorerListHeader");
    const contextMenu = document.getElementById("explorerContextMenu");
    const newFolderModal = document.getElementById("explorerNewFolderModal");
    const newFolderForm = document.getElementById("explorerNewFolderForm");
    const newFolderNameInput = document.getElementById("explorerNewFolderName");
    const newFolderLevelSelect = document.getElementById("explorerNewFolderLevel");
    const newFolderCloseButton = document.getElementById("explorerNewFolderClose");
    const newFolderCancelButton = document.getElementById("explorerNewFolderCancel");
    const backButton = appRoot.querySelector('[data-nav-action="back"]');
    const forwardButton = appRoot.querySelector('[data-nav-action="forward"]');
    const upButton = appRoot.querySelector('[data-nav-action="up"]');
    const homeButton = appRoot.querySelector('[data-nav-action="home"]');
    const uploadTrigger = document.getElementById("explorerUploadTrigger");
    const uploadInput = document.getElementById("explorerUploadInput");
    const uploadForm = document.getElementById("explorerUploadForm");
    const newFolderButton = document.getElementById("explorerNewFolderBtn");
    const advancedFiltersToggle = document.getElementById("advancedFiltersToggle");
    const advancedFiltersForm = document.getElementById("explorerAdvancedFilters");
    const viewModeButtons = Array.from(appRoot.querySelectorAll("[data-view-mode]"));

    if (!itemsContainer || !contextMenu) {
        return;
    }

    const pinStorageKey = `classifiedExplorerPinned:${parentId}`;
    const historyStorageKey = "classifiedExplorerNavHistory";
    let activeCard = null;

    const readExplorerHistory = () => {
        try {
            const cached = window.sessionStorage.getItem(historyStorageKey);
            if (!cached) {
                return { entries: [], index: -1 };
            }

            const parsed = JSON.parse(cached);
            if (!parsed || !Array.isArray(parsed.entries)) {
                return { entries: [], index: -1 };
            }

            return {
                entries: parsed.entries.map((item) => String(item)),
                index: Number.isInteger(parsed.index) ? parsed.index : -1,
            };
        } catch (_error) {
            return { entries: [], index: -1 };
        }
    };

    const saveExplorerHistory = (state) => {
        window.sessionStorage.setItem(historyStorageKey, JSON.stringify(state));
    };

    const syncExplorerHistory = () => {
        const currentUrl = `${window.location.pathname}${window.location.search}`;
        const state = readExplorerHistory();
        const existingIndex = state.entries.indexOf(currentUrl);

        if (existingIndex >= 0) {
            state.index = existingIndex;
        } else {
            if (state.index >= 0 && state.index < state.entries.length - 1) {
                state.entries = state.entries.slice(0, state.index + 1);
            }

            state.entries.push(currentUrl);
            state.index = state.entries.length - 1;
        }

        saveExplorerHistory(state);
        return state;
    };

    const updateNavButtonStates = () => {
        const state = readExplorerHistory();
        const hasBack = state.index > 0;
        const hasForward = state.index >= 0 && state.index < state.entries.length - 1;
        const isRootLevel = parentId === "0";

        if (backButton) {
            backButton.disabled = !hasBack;
        }
        if (forwardButton) {
            forwardButton.disabled = !hasForward;
        }
        if (upButton) {
            upButton.disabled = isRootLevel || !parentUrl;
        }
        if (homeButton) {
            homeButton.disabled = !rootUrl;
        }
    };

    const openNewFolderModal = () => {
        if (!newFolderModal || !newFolderForm) {
            return;
        }

        newFolderForm.reset();
        if (newFolderNameInput) {
            newFolderNameInput.value = "新建文件夹";
        }
        if (newFolderLevelSelect) {
            newFolderLevelSelect.value = defaultNewFolderLevel;
        }

        newFolderModal.classList.remove("is-hidden");
        newFolderModal.setAttribute("aria-hidden", "false");

        window.setTimeout(() => {
            if (newFolderNameInput) {
                newFolderNameInput.focus();
                newFolderNameInput.select();
            }
        }, 0);
    };

    const closeNewFolderModal = () => {
        if (!newFolderModal) {
            return;
        }

        newFolderModal.classList.add("is-hidden");
        newFolderModal.setAttribute("aria-hidden", "true");
    };

    syncExplorerHistory();
    updateNavButtonStates();

    if (backButton) {
        backButton.addEventListener("click", () => {
            window.history.back();
        });
    }

    if (forwardButton) {
        forwardButton.addEventListener("click", () => {
            window.history.forward();
        });
    }

    if (upButton && parentUrl) {
        upButton.addEventListener("click", () => {
            window.location.assign(parentUrl);
        });
    }

    if (homeButton && rootUrl) {
        homeButton.addEventListener("click", () => {
            window.location.assign(rootUrl);
        });
    }

    window.addEventListener("pageshow", () => {
        syncExplorerHistory();
        updateNavButtonStates();
    });

    const getPinnedSet = () => {
        try {
            const cached = window.localStorage.getItem(pinStorageKey);
            if (!cached) {
                return new Set();
            }
            const parsed = JSON.parse(cached);
            if (!Array.isArray(parsed)) {
                return new Set();
            }
            return new Set(parsed.map((item) => String(item)));
        } catch (_error) {
            return new Set();
        }
    };

    const savePinnedSet = (pinnedSet) => {
        window.localStorage.setItem(pinStorageKey, JSON.stringify(Array.from(pinnedSet)));
    };

    const cardKey = (cardElement) => String(cardElement.dataset.itemKey || "");

    const applyPinnedOrder = () => {
        const pinnedSet = getPinnedSet();
        const cards = Array.from(itemsContainer.querySelectorAll(".explorer-item-card"));
        cards.forEach((card, index) => {
            if (!card.dataset.originIndex) {
                card.dataset.originIndex = String(index);
            }
            card.classList.toggle("is-pinned", pinnedSet.has(cardKey(card)));
        });

        cards.sort((aCard, bCard) => {
            const aPinned = pinnedSet.has(cardKey(aCard));
            const bPinned = pinnedSet.has(cardKey(bCard));
            if (aPinned !== bPinned) {
                return aPinned ? -1 : 1;
            }
            return Number(aCard.dataset.originIndex) - Number(bCard.dataset.originIndex);
        });

        cards.forEach((card) => {
            itemsContainer.appendChild(card);
        });
    };

    const setViewMode = (mode) => {
        const nextMode = mode === "list" ? "list" : "icon";
        itemsContainer.dataset.viewMode = nextMode;
        itemsContainer.classList.toggle("is-list-view", nextMode === "list");
        itemsContainer.classList.toggle("is-icon-view", nextMode !== "list");

        if (listHeader) {
            listHeader.classList.toggle("is-hidden", nextMode !== "list");
            listHeader.setAttribute("aria-hidden", String(nextMode !== "list"));
        }

        viewModeButtons.forEach((button) => {
            const isActive = button.dataset.viewMode === nextMode;
            button.classList.toggle("btn-primary", isActive);
            button.classList.toggle("btn-secondary", !isActive);
        });

        window.localStorage.setItem("classifiedExplorerViewMode", nextMode);
    };

    const hideContextMenu = () => {
        contextMenu.classList.add("is-hidden");
        contextMenu.setAttribute("aria-hidden", "true");
        activeCard = null;
    };

    const syncContextMenuActions = (cardElement) => {
        const isFolder = cardElement.dataset.itemKind === "folder";
        const canDownload = cardElement.dataset.canDownload === "1";
        const canDelete = cardElement.dataset.canDelete === "1";
        const itemStatus = cardElement.dataset.itemStatus || "";
        const pinnedSet = getPinnedSet();

        const pinButton = contextMenu.querySelector("[data-menu-action='pin']");
        const openButton = contextMenu.querySelector("[data-menu-action='open']");
        const downloadButton = contextMenu.querySelector("[data-menu-action='download']");
        const encryptButton = contextMenu.querySelector("[data-menu-action='encrypt']");
        const renameButton = contextMenu.querySelector("[data-menu-action='rename']");
        const deleteButton = contextMenu.querySelector("[data-menu-action='delete']");

        if (pinButton) {
            pinButton.classList.remove("is-hidden", "is-disabled");
            pinButton.textContent = pinnedSet.has(cardKey(cardElement)) ? "取消置顶" : "置顶";
        }

        if (openButton) {
            openButton.classList.toggle("is-hidden", !isFolder);
        }
        if (downloadButton) {
            downloadButton.classList.toggle("is-hidden", isFolder);
            downloadButton.classList.toggle("is-disabled", !isFolder && !canDownload);
        }
        if (encryptButton) {
            encryptButton.classList.toggle("is-hidden", isFolder || itemStatus === "已加密" || itemStatus === "");
        }
        if (renameButton) {
            renameButton.classList.toggle("is-hidden", !isFolder);
        }
        if (deleteButton) {
            deleteButton.classList.toggle("is-hidden", !canDelete);
        }
    };

    const triggerCardPrimaryAction = (cardElement) => {
        const isFolder = cardElement.dataset.itemKind === "folder";
        if (isFolder) {
            const openUrl = cardElement.dataset.openUrl || "";
            if (openUrl) {
                window.location.assign(openUrl);
            }
            return;
        }

        if (cardElement.dataset.canDownload !== "1") {
            notify("权限不足：当前账号不可下载该文件。", "danger");
            return;
        }

        const downloadUrl = cardElement.dataset.downloadUrl || "";
        if (!downloadUrl) {
            notify("下载地址不存在。", "danger");
            return;
        }

        if (!progressContext) {
            window.location.assign(downloadUrl);
            return;
        }

        const virtualLink = {
            href: downloadUrl,
            dataset: {
                progressText: "正在下载文件，请稍候...",
                downloadName: cardElement.dataset.itemName || "download.bin",
            },
        };
        downloadWithProgress(virtualLink, progressContext);
    };

    const deleteCardItem = async (cardElement) => {
        if (cardElement.dataset.canDelete !== "1") {
            notify("权限不足：不可删除该文件或文件夹。", "danger");
            return;
        }

        const isFolder = cardElement.dataset.itemKind === "folder";
        const confirmed = window.confirm("确定要删除该文件/文件夹吗？此操作不可撤销");
        if (!confirmed) {
            return;
        }

        const result = await postExplorerAction({
            url: cardElement.dataset.deleteUrl || "",
            csrfToken,
            fields: {
                csrf_token: csrfToken,
            },
            progressContext,
            progressText: isFolder ? "正在删除文件夹及其子项..." : "正在删除文件...",
        });

        if (!result.ok) {
            notify(result.message, "danger");
            return;
        }

        notify(result.message || "删除成功。", "success");
        window.setTimeout(() => {
            window.location.reload();
        }, 150);
    };

    const renameFolder = async (cardElement) => {
        if (cardElement.dataset.itemKind !== "folder") {
            return;
        }

        const currentName = cardElement.dataset.itemName || "";
        const nextName = window.prompt("请输入新的文件夹名称：", currentName);
        if (nextName === null) {
            return;
        }

        const trimmedName = String(nextName).trim();
        if (!trimmedName) {
            notify("文件夹名称不能为空。", "warning");
            return;
        }

        const result = await postExplorerAction({
            url: cardElement.dataset.renameUrl || "",
            csrfToken,
            fields: {
                csrf_token: csrfToken,
                new_name: trimmedName,
            },
            progressContext,
            progressText: "正在重命名文件夹...",
        });

        if (!result.ok) {
            notify(result.message, "danger");
            return;
        }

        notify(result.message || "重命名成功。", "success");
        window.setTimeout(() => {
            window.location.reload();
        }, 150);
    };

    const togglePin = (cardElement) => {
        const pinnedSet = getPinnedSet();
        const currentKey = cardKey(cardElement);
        if (!currentKey) {
            return;
        }

        if (pinnedSet.has(currentKey)) {
            pinnedSet.delete(currentKey);
            notify("已取消置顶。", "info");
        } else {
            pinnedSet.add(currentKey);
            notify("已置顶该项目。", "success");
        }

        savePinnedSet(pinnedSet);
        applyPinnedOrder();
    };

    itemsContainer.addEventListener("click", (event) => {
        const deleteButton = event.target.closest("[data-inline-action='delete']");
        if (deleteButton) {
            event.preventDefault();
            const cardElement = deleteButton.closest(".explorer-item-card");
            if (cardElement) {
                deleteCardItem(cardElement);
            }
            return;
        }

        const cardHit = event.target.closest(".explorer-item-hit");
        if (!cardHit) {
            return;
        }

        const cardElement = cardHit.closest(".explorer-item-card");
        if (!cardElement) {
            return;
        }

        triggerCardPrimaryAction(cardElement);
    });

    itemsContainer.addEventListener("contextmenu", (event) => {
        const cardElement = event.target.closest(".explorer-item-card");
        if (!cardElement) {
            return;
        }

        event.preventDefault();
        activeCard = cardElement;
        syncContextMenuActions(cardElement);

        contextMenu.style.left = `${event.clientX + 2}px`;
        contextMenu.style.top = `${event.clientY + 2}px`;
        contextMenu.classList.remove("is-hidden");
        contextMenu.setAttribute("aria-hidden", "false");
    });

    contextMenu.addEventListener("click", (event) => {
        const actionButton = event.target.closest(".menu-item");
        if (!actionButton || !activeCard) {
            return;
        }

        const selectedCard = activeCard;
        const actionName = actionButton.dataset.menuAction || "";
        hideContextMenu();

        if (actionName === "pin") {
            togglePin(selectedCard);
            return;
        }

        if (actionName === "open") {
            const openUrl = selectedCard.dataset.openUrl || "";
            if (openUrl) {
                window.location.assign(openUrl);
            }
            return;
        }

        if (actionName === "download") {
            triggerCardPrimaryAction(selectedCard);
            return;
        }

        if (actionName === "encrypt") {
            const fileGroupId = selectedCard.dataset.fileGroupId || "";
            const fileName = selectedCard.dataset.itemName || "";
            if (fileGroupId) {
                const encryptModal = document.getElementById("explorerEncryptModal");
                const encryptFileGroupIdInput = document.getElementById("explorerEncryptFileGroupId");
                const encryptFileNameInput = document.getElementById("explorerEncryptFileName");
                if (encryptModal && encryptFileGroupIdInput && encryptFileNameInput) {
                    encryptFileGroupIdInput.value = fileGroupId;
                    encryptFileNameInput.value = fileName;
                    encryptModal.classList.remove("is-hidden");
                    encryptModal.setAttribute("aria-hidden", "false");
                }
            }
            return;
        }

        if (actionName === "rename") {
            renameFolder(selectedCard);
            return;
        }

        if (actionName === "delete") {
            deleteCardItem(selectedCard);
        }
    });

    document.addEventListener("click", (event) => {
        if (!contextMenu.contains(event.target)) {
            hideContextMenu();
        }
    });
    window.addEventListener("resize", hideContextMenu, { passive: true });
    window.addEventListener("scroll", hideContextMenu, { passive: true });

    if (newFolderButton) {
        newFolderButton.addEventListener("click", () => {
            openNewFolderModal();
        });
    }

    if (newFolderCloseButton) {
        newFolderCloseButton.addEventListener("click", closeNewFolderModal);
    }

    if (newFolderCancelButton) {
        newFolderCancelButton.addEventListener("click", closeNewFolderModal);
    }

    if (newFolderModal) {
        newFolderModal.addEventListener("click", (event) => {
            if (event.target && event.target.hasAttribute("data-modal-close")) {
                closeNewFolderModal();
            }
        });
    }

    window.addEventListener("keydown", (event) => {
        if (event.key === "Escape" && newFolderModal && !newFolderModal.classList.contains("is-hidden")) {
            closeNewFolderModal();
        }
    });

    if (uploadTrigger && uploadInput && uploadForm) {
        uploadTrigger.addEventListener("click", () => {
            uploadInput.click();
        });

        uploadInput.addEventListener("change", () => {
            if (!uploadInput.files || uploadInput.files.length === 0) {
                return;
            }
            if (typeof uploadForm.requestSubmit === "function") {
                uploadForm.requestSubmit();
                return;
            }
            uploadForm.submit();
        });
    }

    if (advancedFiltersToggle && advancedFiltersForm) {
        const syncAdvancedFiltersState = (isOpen) => {
            advancedFiltersForm.hidden = !isOpen;
            advancedFiltersToggle.setAttribute("aria-expanded", String(isOpen));
            advancedFiltersToggle.textContent = isOpen ? "收起筛选" : "高级筛选";
        };

        const uploadStartInput = advancedFiltersForm.querySelector("input[name='upload_start']");
        const uploadEndInput = advancedFiltersForm.querySelector("input[name='upload_end']");
        const isValidDateValue = (inputElement) => {
            if (!inputElement || !inputElement.value) {
                return true;
            }

            const value = inputElement.value;
            if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) {
                return false;
            }

            const parsedDate = new Date(`${value}T00:00:00`);
            if (Number.isNaN(parsedDate.getTime())) {
                return false;
            }

            const year = Number(value.slice(0, 4));
            const month = Number(value.slice(5, 7));
            const day = Number(value.slice(8, 10));

            return (
                parsedDate.getFullYear() === year &&
                parsedDate.getMonth() + 1 === month &&
                parsedDate.getDate() === day
            );
        };

        advancedFiltersForm.addEventListener("submit", (event) => {
            if (isValidDateValue(uploadStartInput) && isValidDateValue(uploadEndInput)) {
                return;
            }

            event.preventDefault();
            notify("请输入正确的日期格式（年/月/日）", "danger");
        });

        syncAdvancedFiltersState(!advancedFiltersForm.hidden);

        advancedFiltersToggle.addEventListener("click", () => {
            syncAdvancedFiltersState(advancedFiltersForm.hidden);
        });
    }

    const cachedViewMode = window.localStorage.getItem("classifiedExplorerViewMode") || "icon";
    setViewMode(cachedViewMode);
    viewModeButtons.forEach((button) => {
        button.addEventListener("click", () => {
            setViewMode(button.dataset.viewMode || "icon");
        });
    });

    applyPinnedOrder();
}

/**
 * 功能：为原生日期输入框提供可控占位符显示。
 * 参数：无。
 * 返回值：无。
 * 注意事项：不改变 type=date 的日期选择行为。
 */
function initDateInputPlaceholderFallback() {
    const wrappers = document.querySelectorAll(".date-input-wrapper");
    wrappers.forEach((wrapper) => {
        const input = wrapper.querySelector("input[type='date']");
        if (!input) {
            return;
        }

        input.setAttribute("placeholder", "年/月/日");

        const syncPlaceholderState = () => {
            wrapper.classList.toggle("has-value", Boolean(input.value));
        };

        input.addEventListener("focus", () => {
            wrapper.classList.add("is-focused");
        });

        input.addEventListener("blur", () => {
            wrapper.classList.remove("is-focused");
            syncPlaceholderState();
        });

        input.addEventListener("change", syncPlaceholderState);
        input.addEventListener("input", syncPlaceholderState);
        syncPlaceholderState();
    });
}

document.addEventListener("DOMContentLoaded", () => {
    const progressContext = createProgressContext();
    const progressForms = document.querySelectorAll("form.progress-form");
    const downloadLinks = document.querySelectorAll("a.progress-download");

    progressForms.forEach((formElement) => {
        formElement.addEventListener("submit", (event) => {
            const confirmText = formElement.dataset.confirmText || "";
            if (confirmText) {
                const approved = window.confirm(confirmText);
                if (!approved) {
                    event.preventDefault();
                    return;
                }
            }

            if (!progressContext) {
                return;
            }

            event.preventDefault();
            submitFormWithProgress(formElement, progressContext);
        });
    });

    downloadLinks.forEach((linkElement) => {
        linkElement.addEventListener("click", (event) => {
            if (!progressContext) {
                return;
            }

            event.preventDefault();
            downloadWithProgress(linkElement, progressContext);
        });
    });

    initDateInputPlaceholderFallback();
    initResourceExplorer(progressContext);
});
