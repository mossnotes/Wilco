(() => {
    "use strict";

    const ui = JSON.parse(document.getElementById("ui-copy").textContent);
    const accountFields = ["username", "email", "phone", "country_code"];
    const secretFields = ["password", "api_key", "totp_seed"];
    const accountForm = document.getElementById("account-create-form");
    const accountDetails = document.getElementById("account-details");
    let sessionToken;
    let inputSession = document.body.dataset.inputSession;
    delete document.body.dataset.inputSession;

    function initializeTelegram() {
        const app = window.Telegram?.WebApp;
        if (!app) return;
        const background = getComputedStyle(document.documentElement).getPropertyValue("--background").trim();
        app.ready();
        app.expand();
        if (app.isVersionAtLeast("6.1")) {
            app.setHeaderColor(background);
            app.setBackgroundColor(background);
        }
        if (app.isVersionAtLeast("7.10")) app.setBottomBarColor(background);
    }

    const sdk = document.getElementById("telegram-sdk");
    const sdkReady = window.Telegram?.WebApp ? Promise.resolve() : new Promise(resolve => {
        const timeout = setTimeout(resolve, 5000);
        const done = () => { clearTimeout(timeout); resolve(); };
        sdk.addEventListener("load", done, { once: true });
        sdk.addEventListener("error", done, { once: true });
    });
    document.querySelectorAll("button").forEach(button => { button.disabled = true; });
    const authReady = (async () => {
        const status = document.getElementById("auth-status");
        try {
            if (document.body.dataset.publicPage) {
                status.hidden = true;
                return true;
            }
            await sdkReady;
            initializeTelegram();
            if (inputSession) {
                // The exchanged capability can submit this request only. It does
                // not establish a general vault session or survive navigation.
                const taskId = document.getElementById("resolve-form").dataset.taskId;
                history.replaceState(null, "", "/vault/input?" + new URLSearchParams({ task_id: taskId }));
            } else if (window.Telegram?.WebApp?.initData) {
                const response = await fetch("/vault/auth/telegram", {
                    method: "POST", credentials: "same-origin",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ init_data: window.Telegram.WebApp.initData }),
                    signal: AbortSignal.timeout(15000),
                });
                if (!response.ok) throw new Error();
                sessionToken = (await response.json()).session_token;
            } else if (!document.body.dataset.authUser) {
                throw new Error();
            }
            if (document.getElementById("accounts-container")) {
                const response = await request("/api/vault/accounts", "GET");
                const accounts = await response.json();
                document.getElementById("accounts-container").replaceChildren();
                accounts.forEach(renderAccount);
            }
            if (accountDetails) await loadAccount();
            document.querySelectorAll("button").forEach(button => { button.disabled = false; });
            document.body.classList.remove("auth-pending");
            status.hidden = true;
            return true;
        } catch (error) {
            status.textContent = error.status === 404 ? ui.account_not_found : ui.auth_failed;
            return false;
        }
    })();

    async function request(url, method, payload) {
        const response = await fetch(url, {
            method, credentials: "same-origin",
            headers: {
                "Content-Type": "application/json",
                ...(sessionToken ? { Authorization: `Bearer ${sessionToken}` } : {}),
                ...(inputSession && url.startsWith("/api/tasks/") ? { "X-Credential-Input": inputSession } : {}),
            },
            ...(payload === undefined ? {} : { body: JSON.stringify(payload) }),
            signal: AbortSignal.timeout(15000),
        });
        if (!response.ok) {
            // Show only local copy, never API payloads which may include input.
            const error = new Error();
            error.status = response.status;
            throw error;
        }
        return response;
    }

    async function send(url, method, payload) {
        if (!await authReady) throw new Error();
        return request(url, method, payload);
    }

    function setBusy(form, busy) {
        form.setAttribute("aria-busy", String(busy));
        form.querySelectorAll("button").forEach(button => { button.disabled = busy; });
    }

    function clearError(form) {
        const feedback = form.querySelector(".feedback");
        feedback.hidden = true;
        feedback.textContent = "";
    }

    function showError(form, message) {
        const feedback = form.querySelector(".feedback");
        feedback.textContent = message;
        feedback.hidden = false;
    }

    function validate(form, message) {
        clearError(form);
        const invalid = Array.from(form.elements).filter(field => field.validity && !field.validity.valid);
        invalid.forEach(field => field.setAttribute("aria-invalid", "true"));
        if (!invalid.length) return true;
        showError(form, message);
        invalid[0].focus();
        return false;
    }

    function initializeSiteIcon(img) {
        const monogram = img.parentElement.querySelector(".site-monogram");
        const show = () => {
            const loaded = img.naturalWidth > 0;
            img.hidden = !loaded;
            monogram.hidden = loaded;
        };
        img.addEventListener("load", show);
        img.addEventListener("error", show);
        if (img.complete) show();
    }
    document.querySelectorAll("[data-site-icon]").forEach(initializeSiteIcon);

    function renderAccount(account) {
        const row = document.getElementById("account-row-template").content.firstElementChild.cloneNode(true);
        row.querySelector(".domain").textContent = account.site_domain;
        row.querySelector(".account-identity").href = "/vault/accounts/" + encodeURIComponent(account.site_domain);
        row.querySelector(".site-monogram").textContent = account.site_domain[0].toUpperCase();
        const icon = row.querySelector("[data-site-icon]");
        initializeSiteIcon(icon);
        if (/^[a-z0-9.-]+$/i.test(account.site_domain) && account.site_domain.includes(".") && !/^[\d.]+$/.test(account.site_domain)) {
            icon.src = `https://${account.site_domain}/favicon.ico`;
        }
        document.getElementById("accounts-container").append(row);
    }

    async function loadAccount() {
        const response = await request("/api/vault/accounts/" + encodeURIComponent(accountDetails.dataset.targetDomain), "GET");
        const account = await response.json();
        accountDetails.replaceChildren();
        function appendDetail(field, value, masked = false) {
            const row = document.createElement("div");
            const label = document.createElement("dt");
            label.textContent = field === "totp_seed" ? ui.authenticator_key : ui[field];
            const detail = document.createElement("dd");
            detail.textContent = value;
            if (masked) detail.setAttribute("aria-label", ui.hidden_value);
            row.append(label, detail);
            accountDetails.append(row);
        }
        accountFields.forEach(field => {
            const value = account.details[field];
            if (typeof value === "string" && value.trim()) appendDetail(field, value);
        });
        secretFields.forEach(field => {
            if (account.stored_secrets.includes(field)) appendDetail(field, "••••••••", true);
        });
    }

    document.querySelectorAll("input, textarea, select").forEach(field => {
        field.addEventListener("input", () => field.removeAttribute("aria-invalid"));
    });
    document.querySelectorAll("[data-toggle-secret]").forEach(button => {
        const input = document.getElementById(button.getAttribute("aria-controls"));
        function mask() {
            input.type = "password";
            button.setAttribute("aria-pressed", "false");
            button.querySelector(".eye-slash").hidden = true;
        }
        button.addEventListener("click", () => {
            const visible = input.type === "password";
            input.type = visible ? "text" : "password";
            button.setAttribute("aria-pressed", String(visible));
            button.querySelector(".eye-slash").hidden = !visible;
        });
        input.form.addEventListener("reset", mask);
        document.addEventListener("visibilitychange", () => { if (document.hidden) mask(); });
        window.addEventListener("pagehide", () => { input.value = ""; mask(); });
    });
    document.querySelectorAll("dialog").forEach(dialog => {
        dialog.querySelectorAll("[data-close-dialog]").forEach(button => button.addEventListener("click", () => dialog.close()));
        dialog.addEventListener("cancel", event => {
            if (dialog.querySelector('[aria-busy="true"]')) event.preventDefault();
        });
        dialog.addEventListener("close", () => {
            const form = dialog.querySelector("form");
            form.reset();
            clearError(form);
        });
    });

    if (accountForm) {
        accountForm.addEventListener("submit", async event => {
            event.preventDefault();
            if (accountForm.getAttribute("aria-busy") === "true" || !validate(accountForm, ui.save_failed)) return;
            const payload = {};
            accountFields.forEach(field => {
                const value = document.getElementById(field).value.trim();
                if (value) payload[field] = value;
            });
            secretFields.forEach(field => {
                const value = document.getElementById(field).value;
                if (value) payload[field] = value;
            });
            setBusy(accountForm, true);
            try {
                const value = document.getElementById("site_domain").value.trim();
                const domain = new URL(value.includes("://") ? value : "https://" + value).hostname;
                const response = await send("/api/vault/accounts/" + encodeURIComponent(domain), "PUT", payload);
                const result = await response.json();
                window.location.assign("/vault/accounts/" + encodeURIComponent(result.site_domain));
            } catch {
                showError(accountForm, ui.save_failed);
            } finally {
                setBusy(accountForm, false);
            }
        });
    }

    const removeForm = document.getElementById("remove-form");
    if (removeForm && accountDetails) {
        const dialog = document.getElementById("remove-modal");
        document.getElementById("delete-account").addEventListener("click", () => dialog.showModal());
        removeForm.addEventListener("submit", async event => {
            event.preventDefault();
            if (removeForm.getAttribute("aria-busy") === "true") return;
            clearError(removeForm);
            setBusy(removeForm, true);
            try {
                await send("/api/vault/accounts/" + encodeURIComponent(accountDetails.dataset.targetDomain), "DELETE");
                window.location.assign("/vault/accounts");
            } catch {
                showError(removeForm, ui.remove_failed);
            } finally {
                setBusy(removeForm, false);
            }
        });
    }

    const resolveForm = document.getElementById("resolve-form");
    if (resolveForm) {
        const endpoint = `/api/tasks/${encodeURIComponent(resolveForm.dataset.taskId)}/resolve-input`;
        function finish(approved) {
            resolveForm.reset();
            document.getElementById("cancel-modal").close();
            inputSession = undefined;
            resolveForm.hidden = true;
            const message = document.createElement("p");
            message.className = "save-status";
            message.setAttribute("role", "status");
            message.textContent = approved ? ui.saved_continuing : ui.cancel_task;
            resolveForm.after(message);
            if (window.Telegram?.WebApp?.initData) window.Telegram.WebApp.close();
        }
        resolveForm.addEventListener("submit", async event => {
            event.preventDefault();
            if (resolveForm.getAttribute("aria-busy") === "true" || !validate(resolveForm, ui.submit_failed)) return;
            const payload = { approved: true };
            if (resolveForm.dataset.credentialType) {
                payload.credential_type = resolveForm.dataset.credentialType;
                payload.secret = document.getElementById("secret").value;
            } else if (resolveForm.dataset.targetDomain) {
                payload.credentials = { [resolveForm.dataset.targetDomain]: document.getElementById("password").value };
                payload.username = document.getElementById("username").value.trim() || null;
                payload.totp_seed = document.getElementById("totp_seed").value.trim() || null;
            } else {
                payload.user_input = document.getElementById("user_input").value.trim();
            }
            setBusy(resolveForm, true);
            try {
                await send(endpoint, "POST", payload);
                finish(true);
            } catch (error) {
                showError(resolveForm, [401, 409].includes(error.status) ? ui.expired : ui.submit_failed);
            } finally {
                setBusy(resolveForm, false);
            }
        });
        const cancelForm = document.getElementById("cancel-form");
        document.getElementById("cancel-task").addEventListener("click", () => document.getElementById("cancel-modal").showModal());
        cancelForm.addEventListener("submit", async event => {
            event.preventDefault();
            if (cancelForm.getAttribute("aria-busy") === "true") return;
            clearError(cancelForm);
            setBusy(cancelForm, true);
            try {
                await send(endpoint, "POST", { approved: false });
                finish(false);
            } catch {
                showError(cancelForm, ui.cancel_failed);
            } finally {
                setBusy(cancelForm, false);
            }
        });
    }
})();
