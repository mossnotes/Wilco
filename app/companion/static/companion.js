(() => {
    "use strict";

    const ui = JSON.parse(document.getElementById("ui-copy").textContent);

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

    initializeTelegram();
    document.getElementById("telegram-sdk").addEventListener("load", initializeTelegram, { once: true });

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
        const response = await fetch(url, {
            method,
            credentials: "same-origin",
            headers: { "Content-Type": "application/json" },
            ...(payload === undefined ? {} : { body: JSON.stringify(payload) }),
            signal: AbortSignal.timeout(15000),
        });
        // API details may contain unapproved text. Never put them on a page.
        if (!response.ok) throw new Error();
        return response;
    }

    document.querySelectorAll("input, textarea, select").forEach(field => {
        field.addEventListener("input", () => field.removeAttribute("aria-invalid"));
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
                let row = document.getElementById(`cred-card-${credential.id}`);
                if (!row) {
                    row = document.getElementById("account-row-template").content.firstElementChild.cloneNode(true);
                    row.id = `cred-card-${credential.id}`;
                    document.getElementById("credentials-container").append(row);
                }
                row.querySelector(".domain").textContent = credential.site_domain;
                const removeButton = row.querySelector("button");
                removeButton.dataset.removeId = credential.id;
                removeButton.dataset.domain = credential.site_domain;
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

    const resolveForm = document.getElementById("resolve-form");
    if (resolveForm) {
        const deadline = Number(resolveForm.dataset.deadline) || null;
        const targetDomain = resolveForm.dataset.targetDomain;
        const submitButton = document.getElementById("submit-btn");
        const countdown = document.getElementById("input-countdown");
        const endpoint = `/api/tasks/${encodeURIComponent(resolveForm.dataset.taskId)}/resolve-input`;
        const expired = () => Boolean(deadline && deadline <= Date.now() / 1000);
        let countdownTimer;

        function updateCountdown() {
            if (!countdown || !deadline) return;
            const remaining = Math.max(0, Math.ceil(deadline - Date.now() / 1000));
            const clock = `${Math.floor(remaining / 60)}:${String(remaining % 60).padStart(2, "0")}`;
            countdown.textContent = remaining ? `${ui.time_remaining} ${clock}` : ui.expired;
            countdown.hidden = false;
            submitButton.disabled = !remaining || resolveForm.getAttribute("aria-busy") === "true";
            if (!remaining) clearInterval(countdownTimer);
        }

        if (countdown && deadline) {
            updateCountdown();
            if (!expired()) countdownTimer = setInterval(updateCountdown, 1000);
            window.addEventListener("pagehide", () => clearInterval(countdownTimer), { once: true });
        }

        function finish() {
            clearInterval(countdownTimer);
            resolveForm.reset();
            document.getElementById("cancel-modal").close();
            if (window.Telegram?.WebApp?.initData) window.Telegram.WebApp.close();
            else window.location.assign("/companion/accounts");
        }

        resolveForm.addEventListener("submit", async event => {
            event.preventDefault();
            if (expired() || resolveForm.getAttribute("aria-busy") === "true" || !validate(resolveForm, ui.submit_failed)) return;
            const payload = { approved: true };
            if (targetDomain) {
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
                submitButton.disabled = expired();
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
