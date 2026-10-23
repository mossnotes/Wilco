(() => {
    "use strict";

    const ui = JSON.parse(document.getElementById("ui-copy").textContent);
    let sessionToken;

    function initializeTelegram() {
        const webApp = window.Telegram?.WebApp;
        if (!webApp) return;
        webApp.ready();
        webApp.expand();
        if (webApp.isVersionAtLeast("6.1")) {
            webApp.setHeaderColor("#ffffff");
            webApp.setBackgroundColor("#ffffff");
        }
        if (webApp.isVersionAtLeast("7.10")) webApp.setBottomBarColor("#ffffff");
    }

    const sdk = document.getElementById("telegram-sdk");
    const sdkReady = window.Telegram?.WebApp ? Promise.resolve() : new Promise(resolve => {
        const timeout = setTimeout(resolve, 5000);
        const done = () => { clearTimeout(timeout); resolve(); };
        sdk.addEventListener("load", done, { once: true });
        sdk.addEventListener("error", done, { once: true });
    });
    const initialButtons = Array.from(document.querySelectorAll("button"));
    initialButtons.forEach(button => { button.disabled = true; });
    const authReady = (async () => {
        const status = document.getElementById("auth-status");
        try {
            await sdkReady;
            initializeTelegram();
            const initData = window.Telegram?.WebApp?.initData;
            if (initData) {
                // Only the signed raw payload goes to our server. Never trust initDataUnsafe.
                const response = await fetch("/companion/auth/telegram", {
                    method: "POST", credentials: "same-origin",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ init_data: initData }),
                    signal: AbortSignal.timeout(15000),
                });
                if (!response.ok) throw new Error();
                const identity = await response.json();
                sessionToken = identity.session_token;
            } else if (!document.body.dataset.authUser) {
                throw new Error();
            }
            if (document.getElementById("credentials-container")) {
                const response = await request("/api/vault/credentials", "GET");
                const credentials = await response.json();
                document.getElementById("credentials-container").replaceChildren();
                credentials.forEach(renderCredential);
            }
            document.querySelectorAll("button").forEach(button => { button.disabled = false; });
            document.body.classList.remove("auth-pending");
            status.hidden = true;
            return true;
        } catch {
            status.textContent = ui.auth_failed;
            return false;
        }
    })();

    function setBusy(form, busy) {
        form.setAttribute("aria-busy", String(busy));
        form.querySelectorAll("button").forEach(button => { button.disabled = busy; });
    }

    function clearError(form) {
        const feedback = form.querySelector(".feedback");
        if (feedback) {
            feedback.hidden = true;
            feedback.textContent = "";
        }
    }

    function showError(form, message) {
        const feedback = form.querySelector(".feedback");
        feedback.textContent = message;
        feedback.hidden = false;
    }

    function validate(form, message) {
        clearError(form);
        const invalid = Array.from(form.elements).filter(field => field.validity && !field.validity.valid);
        invalid.forEach(field => { field.setAttribute("aria-invalid", "true"); });
        if (invalid.length) {
            showError(form, message);
            invalid[0].focus();
            return false;
        }
        return true;
    }

    async function send(url, method, payload) {
        if (!await authReady) throw new Error();
        return request(url, method, payload);
    }

    async function request(url, method, payload) {
        const response = await fetch(url, {
            method,
            credentials: "same-origin",
            headers: {
                "Content-Type": "application/json",
                ...(sessionToken ? { Authorization: `Bearer ${sessionToken}` } : {}),
            },
            ...(payload === undefined ? {} : { body: JSON.stringify(payload) }),
            signal: AbortSignal.timeout(15000),
        });
        // API details may contain unapproved text. Never put them on a page.
        if (!response.ok) throw new Error();
        return response;
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

    function renderCredential(credential) {
        let row = document.getElementById(`cred-card-${credential.id}`);
        if (!row) {
            row = document.getElementById("account-row-template").content.firstElementChild.cloneNode(true);
            row.id = `cred-card-${credential.id}`;
            document.getElementById("credentials-container").append(row);
        }
        row.querySelector(".domain").textContent = credential.site_domain;
        const label = { password: ui.password, api_key: ui.api_key, totp_seed: ui.authenticator_key }[credential.auth_type];
        const link = row.querySelector(".account-identity");
        if (label) {
            link.href = "/companion/credentials?" + new URLSearchParams({
                domain: credential.site_domain, credential_type: credential.auth_type,
            });
        }
        row.querySelector(".credential-kind").textContent = label || "";
        row.querySelector(".site-monogram").textContent = credential.site_domain[0].toUpperCase();
        const icon = row.querySelector("[data-site-icon]");
        initializeSiteIcon(icon);
        if (/^[a-z0-9.-]+$/i.test(credential.site_domain) && credential.site_domain.includes(".") && !/^[\d.]+$/.test(credential.site_domain)) {
            icon.src = `https://${credential.site_domain}/favicon.ico`;
        }
        const removeButton = row.querySelector("button");
        removeButton.dataset.removeId = credential.id;
        removeButton.dataset.domain = credential.site_domain;
    }

    document.querySelectorAll("input, textarea, select").forEach(field => {
        field.addEventListener("input", () => field.removeAttribute("aria-invalid"));
    });

    document.querySelectorAll("[data-toggle-secret]").forEach(button => {
        const input = document.getElementById(button.getAttribute("aria-controls"));
        function mask() {
            input.type = "password";
            button.setAttribute("aria-pressed", "false");
            button.querySelector(".eye-slash").setAttribute("hidden", "");
        }
        button.addEventListener("click", () => {
            const visible = input.type === "password";
            input.type = visible ? "text" : "password";
            button.setAttribute("aria-pressed", String(visible));
            button.querySelector(".eye-slash").toggleAttribute("hidden", !visible);
        });
        input.form.addEventListener("reset", mask);
        document.addEventListener("visibilitychange", () => { if (document.hidden) mask(); });
        window.addEventListener("pagehide", () => { input.value = ""; mask(); });
    });

    document.querySelectorAll("dialog").forEach(dialog => {
        dialog.querySelectorAll("[data-close-dialog]").forEach(button => {
            button.addEventListener("click", () => dialog.close());
        });
        dialog.addEventListener("cancel", event => {
            if (dialog.querySelector('[aria-busy="true"]')) event.preventDefault();
        });
        dialog.addEventListener("close", () => {
            const form = dialog.querySelector("form");
            form.reset();
            clearError(form);
            form.querySelectorAll("[aria-invalid]").forEach(field => field.removeAttribute("aria-invalid"));
        });
    });

    const addForm = document.getElementById("add-cred-form");
    if (addForm) {
        const addDialog = document.getElementById("add-modal");
        const authType = document.getElementById("auth_type");
        const identifier = document.getElementById("username_or_identifier");
        const identifierGroup = document.getElementById("identifier-group");

        function updateAuthType() {
            const password = authType.value === "password";
            identifierGroup.hidden = !password;
            identifier.disabled = !password;
            document.getElementById("secret-label").textContent = {
                password: ui.password,
                totp_seed: ui.authenticator_key,
                api_key: ui.api_key,
            }[authType.value];
        }

        authType.addEventListener("change", updateAuthType);
        document.getElementById("add-account").addEventListener("click", () => {
            updateAuthType();
            addDialog.showModal();
            document.getElementById("site_domain").focus();
        });

        addForm.addEventListener("submit", async event => {
            event.preventDefault();
            if (addForm.getAttribute("aria-busy") === "true" || !validate(addForm, ui.save_failed)) return;
            const payload = {
                site_domain: document.getElementById("site_domain").value.trim(),
                auth_type: authType.value,
                username_or_identifier: identifier.disabled ? null : identifier.value.trim() || null,
                secret: document.getElementById("secret").value,
            };
            if (!payload.site_domain) return showError(addForm, ui.save_failed);
            setBusy(addForm, true);
            try {
                const response = await send("/api/vault/credentials", "POST", payload);
                const credential = await response.json();
                renderCredential(credential);
                addDialog.close();
            } catch {
                showError(addForm, ui.save_failed);
            } finally {
                setBusy(addForm, false);
            }
        });

        const removeDialog = document.getElementById("remove-modal");
        const removeForm = document.getElementById("remove-form");
        let selectedCredentialId;

        document.getElementById("credentials-container").addEventListener("click", event => {
            const button = event.target.closest("[data-remove-id]");
            if (!button) return;
            selectedCredentialId = button.dataset.removeId;
            document.getElementById("remove-domain").textContent = button.dataset.domain;
            removeDialog.showModal();
        });

        removeForm.addEventListener("submit", async event => {
            event.preventDefault();
            if (removeForm.getAttribute("aria-busy") === "true") return;
            clearError(removeForm);
            setBusy(removeForm, true);
            try {
                await send(`/api/vault/credentials/${encodeURIComponent(selectedCredentialId)}`, "DELETE");
                document.getElementById(`cred-card-${selectedCredentialId}`)?.remove();
                removeDialog.close();
                document.getElementById("add-account").focus();
            } catch {
                showError(removeForm, ui.remove_failed);
            } finally {
                setBusy(removeForm, false);
            }
        });
    }

    const credentialForm = document.getElementById("credential-form");
    if (credentialForm) {
        const status = document.getElementById("save-status");
        credentialForm.addEventListener("input", () => { status.hidden = true; });
        credentialForm.addEventListener("submit", async event => {
            event.preventDefault();
            if (credentialForm.getAttribute("aria-busy") === "true" || !validate(credentialForm, ui.save_failed)) return;
            status.hidden = true;
            setBusy(credentialForm, true);
            try {
                const response = await send("/api/vault/credentials", "POST", {
                    site_domain: credentialForm.dataset.targetDomain,
                    auth_type: credentialForm.dataset.credentialType,
                    secret: document.getElementById("secret").value,
                });
                const result = await response.json();
                credentialForm.reset();
                status.textContent = result.resumed ? ui.saved_continuing : ui.saved;
                status.hidden = false;
            } catch {
                showError(credentialForm, ui.save_failed);
            } finally {
                setBusy(credentialForm, false);
            }
        });
    }

    const resolveForm = document.getElementById("resolve-form");
    if (resolveForm) {
        const targetDomain = resolveForm.dataset.targetDomain;
        const endpoint = `/api/tasks/${encodeURIComponent(resolveForm.dataset.taskId)}/resolve-input`;

        function finish() {
            resolveForm.reset();
            document.getElementById("cancel-modal").close();
            if (window.Telegram?.WebApp?.initData) window.Telegram.WebApp.close();
            else window.location.assign("/companion/accounts");
        }

        resolveForm.addEventListener("submit", async event => {
            event.preventDefault();
            if (resolveForm.getAttribute("aria-busy") === "true" || !validate(resolveForm, ui.submit_failed)) return;
            const payload = { approved: true };
            if (resolveForm.dataset.credentialType) {
                payload.credential_type = resolveForm.dataset.credentialType;
                payload.secret = document.getElementById("secret").value;
            } else if (targetDomain) {
                payload.credentials = { [targetDomain]: document.getElementById("password").value };
                payload.username = document.getElementById("username").value.trim() || null;
                payload.totp_seed = document.getElementById("totp_seed").value.trim() || null;
            } else {
                payload.user_input = document.getElementById("user_input").value.trim();
            }
            setBusy(resolveForm, true);
            try {
                await send(endpoint, "POST", payload);
                finish();
            } catch {
                showError(resolveForm, ui.submit_failed);
            } finally {
                setBusy(resolveForm, false);
            }
        });

        const cancelDialog = document.getElementById("cancel-modal");
        const cancelForm = document.getElementById("cancel-form");
        document.getElementById("cancel-task").addEventListener("click", () => cancelDialog.showModal());
        cancelForm.addEventListener("submit", async event => {
            event.preventDefault();
            if (cancelForm.getAttribute("aria-busy") === "true") return;
            clearError(cancelForm);
            setBusy(cancelForm, true);
            try {
                await send(endpoint, "POST", { approved: false });
                finish();
            } catch {
                showError(cancelForm, ui.cancel_failed);
            } finally {
                setBusy(cancelForm, false);
            }
        });
    }
})();
