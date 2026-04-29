"use strict";

/**
 * 功能：统一创建顶部通知。
 * 参数：
 *   - message: 提示文本。
 *   - category: 提示类别（success/danger/info/warning）。
 * 返回值：
 *   - void
 * 注意事项：所有通知默认 5 秒后自动消失。
 */
function showGlobalNotification(message, category) {
    const container = document.getElementById("globalFlashContainer");
    const list = document.getElementById("globalFlashList");
    if (!container || !list || !message) {
        return;
    }

    container.classList.remove("is-empty");

    const normalizedCategory = ["success", "danger", "warning", "info"].includes(category)
        ? category
        : "info";

    const item = document.createElement("div");
    item.className = `flash-item flash-${normalizedCategory}`;
    item.textContent = String(message);
    list.appendChild(item);

    window.setTimeout(() => {
        item.classList.add("is-fading");
        window.setTimeout(() => {
            item.remove();
            if (!list.children.length) {
                container.classList.add("is-empty");
            }
        }, 320);
    }, 5000);
}

/**
 * 功能：将文本安全转义为 HTML。
 * 参数：
 *   - value: 需要转义的文本。
 * 返回值：
 *   - string: 已转义文本。
 * 注意事项：用于动态构建表格和卡片，避免插入未转义内容。
 */
function escapeHtml(value) {
    return String(value)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/\"/g, "&quot;")
        .replace(/'/g, "&#39;");
}

/**
 * 功能：根据文件名推断文件类型。
 * 参数：
 *   - fileName: 文件名。
 * 返回值：
 *   - string: 类型文本。
 * 注意事项：无扩展名时默认返回 FILE。
 */
function inferFileType(fileName) {
    const segments = String(fileName).split(".");
    if (segments.length <= 1) {
        return "FILE";
    }
    return segments.pop().toUpperCase();
}

/**
 * 功能：字节数格式化为更易读的文件大小。
 * 参数：
 *   - bytes: 文件大小（字节）。
 * 返回值：
 *   - string: 格式化后的文本。
 * 注意事项：空值时返回 --。
 */
function formatBytes(bytes) {
    if (!Number.isFinite(bytes) || bytes <= 0) {
        return "--";
    }

    const units = ["B", "KB", "MB", "GB"];
    let value = bytes;
    let unitIndex = 0;

    while (value >= 1024 && unitIndex < units.length - 1) {
        value /= 1024;
        unitIndex += 1;
    }

    return `${value.toFixed(value >= 100 ? 0 : 1)} ${units[unitIndex]}`;
}

/**
 * 功能：返回当前时间的本地格式字符串。
 * 参数：无。
 * 返回值：
 *   - string: 时间字符串。
 * 注意事项：用于新建文件与文件夹的上传时间展示。
 */
function nowText() {
    return new Date().toLocaleString("zh-CN", { hour12: false });
}

/**
 * 功能：提取表格内初始文件数据。
 * 参数：
 *   - tableBody: 文件表格 tbody 元素。
 * 返回值：
 *   - Array<Object>: 文件项数组。
 * 注意事项：若无文件行则返回空数组。
 */
function parseInitialItems(tableBody) {
    return Array.from(tableBody.querySelectorAll(".file-row")).map((row) => ({
        name: row.dataset.name || "未命名",
        type: row.dataset.type || "FILE",
        size: row.dataset.size || "--",
        uploaded: row.dataset.uploaded || "--",
        level: row.dataset.level || "初级",
    }));
}

/**
 * 功能：根据当前文件列表和搜索关键字刷新视图。
 * 参数：
 *   - state: 视图状态对象。
 * 返回值：无。
 * 注意事项：列表与图标视图共用同一数据源。
 */
function renderFiles(state) {
    const keyword = state.searchKeyword.trim().toLowerCase();
    const visibleItems = state.items.filter((item) => {
        const text = `${item.name} ${item.type} ${item.level} ${item.uploaded}`.toLowerCase();
        return text.includes(keyword);
    });

    if (visibleItems.length === 0) {
        state.tableBody.innerHTML = "<tr class=\"file-empty-row\"><td colspan=\"5\">未找到匹配文件</td></tr>";
        state.iconGrid.innerHTML = "<article class=\"file-card empty-card\">未找到匹配文件</article>";
    } else {
        state.tableBody.innerHTML = visibleItems
            .map(
                (item) =>
                    `<tr class=\"file-row\" data-name=\"${escapeHtml(item.name)}\" data-type=\"${escapeHtml(item.type)}\" data-size=\"${escapeHtml(item.size)}\" data-uploaded=\"${escapeHtml(item.uploaded)}\" data-level=\"${escapeHtml(item.level)}\"><td>${escapeHtml(item.name)}</td><td>${escapeHtml(item.type)}</td><td>${escapeHtml(item.size)}</td><td>${escapeHtml(item.uploaded)}</td><td>${escapeHtml(item.level)}</td></tr>`
            )
            .join("");

        state.iconGrid.innerHTML = visibleItems
            .map(
                (item) =>
                    `<article class=\"file-card\" data-name=\"${escapeHtml(item.name)}\" data-type=\"${escapeHtml(item.type)}\" data-size=\"${escapeHtml(item.size)}\" data-uploaded=\"${escapeHtml(item.uploaded)}\" data-level=\"${escapeHtml(item.level)}\"><div class=\"file-card-name\">${escapeHtml(item.name)}</div><div class=\"file-card-meta\">${escapeHtml(item.type)} / ${escapeHtml(item.size)}</div><div class=\"file-card-meta\">${escapeHtml(item.level)}</div><div class=\"file-card-meta\">${escapeHtml(item.uploaded)}</div></article>`
            )
            .join("");
    }

    state.statusFileCount.textContent = `文件数量：${visibleItems.length}`;
}

/**
 * 功能：切换文件区域视图模式（列表/图标）。
 * 参数：
 *   - state: 视图状态对象。
 *   - mode: 目标模式。
 * 返回值：无。
 * 注意事项：模式会持久化到 localStorage。
 */
function setViewMode(state, mode) {
    const isIconView = mode === "icon";
    state.explorerMain.classList.toggle("is-icon-view", isIconView);

    state.viewButtons.forEach((button) => {
        button.classList.toggle("primary", button.dataset.view === mode);
    });

    state.statusViewMode.textContent = `当前视图：${isIconView ? "图标" : "列表"}`;
    window.localStorage.setItem("classifiedExplorerViewMode", mode);
}

/**
 * 功能：初始化全局动态水印，内容来自当前登录用户全局变量。
 * 参数：无。
 * 返回值：无。
 * 注意事项：仅在模板注入水印画布时启用，并在窗口缩放时重绘。
 */
function initGlobalDynamicWatermark() {
    const watermarkCanvas = document.getElementById("globalWatermarkCanvas");
    if (!watermarkCanvas) {
        window.currentUserInfo = null;
        return;
    }

    const context = watermarkCanvas.getContext("2d");
    if (!context) {
        return;
    }

    const systemName = watermarkCanvas.dataset.systemName || "涉密";
    const userName = watermarkCanvas.dataset.userName || "未知用户";
    const userId = String(watermarkCanvas.dataset.userId || "").trim();

    window.currentUserInfo = Object.freeze({
        用户: userName,
        ID: userId,
    });

    const rotationInRadians = (-30 * Math.PI) / 180;
    const fontSize = 14;
    const lineHeight = 24;
    const fontFamily = '"SimSun", "宋体", serif';
    const textColor = "rgba(204, 204, 204, 0.5)";
    const horizontalSpacing = 150;
    const verticalSpacing = 150;
    const watermarkLines = [
        systemName,
        window.currentUserInfo.用户,
        window.currentUserInfo.ID || "-",
    ];

    let resizeRafId = 0;

    const render = () => {
        const viewportWidth = Math.max(window.innerWidth, 1);
        const viewportHeight = Math.max(window.innerHeight, 1);
        const dpr = window.devicePixelRatio || 1;

        watermarkCanvas.width = Math.round(viewportWidth * dpr);
        watermarkCanvas.height = Math.round(viewportHeight * dpr);

        context.setTransform(dpr, 0, 0, dpr, 0, 0);
        context.clearRect(0, 0, viewportWidth, viewportHeight);

        context.font = `${fontSize}px ${fontFamily}`;
        context.fillStyle = textColor;
        context.textBaseline = "top";
        context.textAlign = "left";

        const maxTextWidth = watermarkLines.reduce(
            (maxWidth, line) => Math.max(maxWidth, context.measureText(line).width),
            0
        );
        const watermarkWidth = Math.ceil(maxTextWidth);
        const watermarkHeight = lineHeight * watermarkLines.length;
        const tileWidth = watermarkWidth + horizontalSpacing;
        const tileHeight = watermarkHeight + verticalSpacing;

        for (let x = -tileWidth; x < viewportWidth + tileWidth; x += tileWidth) {
            for (let y = -tileHeight; y < viewportHeight + tileHeight; y += tileHeight) {
                const centerX = x + tileWidth / 2;
                const centerY = y + tileHeight / 2;

                context.save();
                context.translate(centerX, centerY);
                context.rotate(rotationInRadians);
                context.translate(-watermarkWidth / 2, -watermarkHeight / 2);

                watermarkLines.forEach((line, index) => {
                    context.fillText(line, 0, index * lineHeight);
                });

                context.restore();
            }
        }
    };

    const scheduleRender = () => {
        if (resizeRafId) {
            window.cancelAnimationFrame(resizeRafId);
        }

        resizeRafId = window.requestAnimationFrame(() => {
            resizeRafId = 0;
            render();
        });
    };

    render();
    window.addEventListener("resize", scheduleRender, { passive: true });
}

/**
 * 功能：初始化文件资源管理器交互。
 * 参数：无。
 * 返回值：无。
 * 注意事项：仅在存在资源管理器壳层时执行。
 */
document.addEventListener("DOMContentLoaded", () => {
    window.appNotify = showGlobalNotification;
    initGlobalDynamicWatermark();

    const initialFlashItems = document.querySelectorAll("#globalFlashList .flash-item");
    initialFlashItems.forEach((item) => {
        window.setTimeout(() => {
            item.classList.add("is-fading");
            window.setTimeout(() => {
                item.remove();
                const container = document.getElementById("globalFlashContainer");
                const list = document.getElementById("globalFlashList");
                if (container && list && !list.children.length) {
                    container.classList.add("is-empty");
                }
            }, 320);
        }, 5000);
    });

    const explorerShell = document.querySelector("[data-explorer-shell='true']");
    if (!explorerShell) {
        return;
    }

    const explorerMain = document.getElementById("explorerMain");
    const tableBody = document.getElementById("fileTableBody");
    const iconGrid = document.getElementById("fileIconGrid");
    const searchInput = document.getElementById("toolbarSearch");
    const viewButtons = Array.from(explorerShell.querySelectorAll("[data-view]"));
    const uploadButton = document.getElementById("toolbarUploadBtn");
    const uploadInput = document.getElementById("toolbarUploadInput");
    const newFolderButton = document.getElementById("toolbarNewFolderBtn");
    const statusFileCount = document.getElementById("statusFileCount");
    const statusViewMode = document.getElementById("statusViewMode");

    if (!explorerMain || !tableBody || !iconGrid || !statusFileCount || !statusViewMode) {
        return;
    }

    const state = {
        explorerMain,
        tableBody,
        iconGrid,
        statusFileCount,
        statusViewMode,
        viewButtons,
        items: parseInitialItems(tableBody),
        searchKeyword: "",
    };

    renderFiles(state);

    const cachedMode = window.localStorage.getItem("classifiedExplorerViewMode") || "list";
    setViewMode(state, cachedMode === "icon" ? "icon" : "list");

    if (searchInput) {
        searchInput.addEventListener("input", (event) => {
            state.searchKeyword = event.target.value || "";
            renderFiles(state);
        });
    }

    viewButtons.forEach((button) => {
        button.addEventListener("click", () => {
            setViewMode(state, button.dataset.view === "icon" ? "icon" : "list");
        });
    });

    if (uploadButton && uploadInput) {
        uploadButton.addEventListener("click", () => {
            uploadInput.click();
        });

        uploadInput.addEventListener("change", (event) => {
            const files = Array.from(event.target.files || []);
            files.forEach((file) => {
                state.items.unshift({
                    name: file.name,
                    type: inferFileType(file.name),
                    size: formatBytes(file.size),
                    uploaded: nowText(),
                    level: "待分级",
                });
            });

            uploadInput.value = "";
            renderFiles(state);
        });
    }

    if (newFolderButton) {
        newFolderButton.addEventListener("click", () => {
            const folderName = window.prompt("请输入新文件夹名称：", "新建文件夹");
            if (!folderName) {
                return;
            }

            const normalizedName = folderName.trim();
            if (!normalizedName) {
                return;
            }

            state.items.unshift({
                name: normalizedName,
                type: "文件夹",
                size: "--",
                uploaded: nowText(),
                level: "初级",
            });
            renderFiles(state);
        });
    }
});
