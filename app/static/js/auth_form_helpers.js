function notifyAuthFormMessage(message, isError) {
    if (typeof window.appNotify === "function") {
        window.appNotify(message, isError ? "danger" : "info");
        return;
    }

    window.alert(message);
}

function initLoginUserIdToggle() {
    const accountTypeSelect = document.getElementById("account_type");
    const userIdWrapper = document.getElementById("loginUserIdField");
    const userIdInput = document.getElementById("customer_id");

    if (!accountTypeSelect || !userIdWrapper || !userIdInput) {
        return;
    }

    const syncUserIdVisibility = () => {
        const isCustomer = accountTypeSelect.value === "customer";
        userIdWrapper.hidden = !isCustomer;
        userIdInput.required = isCustomer;
        if (!isCustomer) {
            userIdInput.value = "";
        }
    };

    accountTypeSelect.addEventListener("change", syncUserIdVisibility);
    syncUserIdVisibility();
}

async function requestJson(url) {
    const response = await window.fetch(url, {
        method: "GET",
        headers: {
            Accept: "application/json",
        },
        credentials: "same-origin",
    });

    let payload = {};
    try {
        payload = await response.json();
    } catch (error) {
        payload = {};
    }

    if (!response.ok || payload.status === "error") {
        const message = payload.message || "请求失败，请稍后重试。";
        throw new Error(message);
    }

    return payload;
}

function initAdminCreateUserGenerators() {
    const userIdInput = document.getElementById("user_id");
    const generateUserIdButton = document.getElementById("generateUserIdBtn");
    const passwordInput = document.getElementById("password");
    const generatePasswordButton = document.getElementById("generatePasswordBtn");

    if (userIdInput && generateUserIdButton) {
        generateUserIdButton.addEventListener("click", async () => {
            generateUserIdButton.disabled = true;
            try {
                const payload = await requestJson("/admin/users/generate-id");
                userIdInput.value = String(payload.user_id || "");
            } catch (error) {
                notifyAuthFormMessage(error.message, true);
            } finally {
                generateUserIdButton.disabled = false;
            }
        });
    }

    if (passwordInput && generatePasswordButton) {
        generatePasswordButton.addEventListener("click", async () => {
            generatePasswordButton.disabled = true;
            try {
                const payload = await requestJson("/admin/users/generate-password");
                passwordInput.value = String(payload.password || "");
            } catch (error) {
                notifyAuthFormMessage(error.message, true);
            } finally {
                generatePasswordButton.disabled = false;
            }
        });
    }
}

document.addEventListener("DOMContentLoaded", () => {
    initLoginUserIdToggle();
    initAdminCreateUserGenerators();
});
