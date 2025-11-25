(() => {
    const body = document.body;
    if (!body) return;

    const sessionKey = "efReviewerSession";
    const defaultTtl = 12 * 60 * 60 * 1000; // 12 hours
    const credentialStore = Array.isArray(window.EF_REVIEWER_HASHES) ? window.EF_REVIEWER_HASHES : [];
    if (!credentialStore.length) {
        console.error("Reviewer credential data failed to load.");
    }

    const encoder = window.TextEncoder ? new TextEncoder() : null;

    const toHex = buffer => Array.from(new Uint8Array(buffer)).map(byte => byte.toString(16).padStart(2, "0")).join("");
    const cleanValue = value => (typeof value === "string" ? value : "");

    const digest = async text => {
        if (!window.crypto?.subtle || !encoder) {
            throw new Error("Secure hashing is not available in this browser.");
        }
        const data = encoder.encode(text);
        const buffer = await window.crypto.subtle.digest("SHA-256", data);
        return toHex(buffer);
    };

    const matchCredential = async (username, password) => {
        const normalized = cleanValue(username).trim().toLowerCase();
        const passValue = cleanValue(password);
        if (!normalized || !passValue || !credentialStore.length) return false;
        const matches = credentialStore.filter(item => item.username === normalized);
        if (!matches.length) return false;
        const hashed = await digest(`${normalized}::${passValue}`);
        return matches.some(item => item.hash === hashed);
    };

    const readSession = () => {
        try {
            const raw = localStorage.getItem(sessionKey);
            return raw ? JSON.parse(raw) : null;
        } catch (error) {
            console.error("Failed to read reviewer session", error);
            return null;
        }
    };

    const persistSession = (username, remember) => {
        const now = Date.now();
        const ttl = remember ? defaultTtl : defaultTtl / 2;
        const payload = {
            username,
            loginAt: now,
            expiresAt: now + ttl
        };
        localStorage.setItem(sessionKey, JSON.stringify(payload));
    };

    const clearSession = () => {
        localStorage.removeItem(sessionKey);
    };

    const isSessionActive = session => {
        return Boolean(session?.username && session?.expiresAt && Date.now() < session.expiresAt);
    };

    const redirectToLogin = () => {
        window.location.href = "reviewer-login.html";
    };

    const redirectToCenter = () => {
        window.location.href = "reviewer-center.html";
    };

    const updateSessionDisplay = session => {
        if (!session) return;
        document.querySelectorAll("[data-session-user]").forEach(el => {
            el.textContent = session.username;
        });
        const hiddenField = document.querySelector("[data-reviewer-hidden-name]");
        if (hiddenField) {
            hiddenField.value = session.username;
        }
    };

    const handleLogout = event => {
        event.preventDefault();
        clearSession();
        redirectToLogin();
    };

    document.querySelectorAll("[data-logout]").forEach(button => {
        button.addEventListener("click", handleLogout);
    });

    const currentSession = readSession();

    if (body.dataset.view === "login") {
        if (isSessionActive(currentSession)) {
            redirectToCenter();
            return;
        }
        const form = document.getElementById("reviewer-login-form");
        const errorEl = document.querySelector("[data-auth-error]");
        const defaultErrorMessage = errorEl?.textContent?.trim() || "Incorrect account or password. Please try again.";
        form?.addEventListener("submit", async event => {
            event.preventDefault();
            errorEl?.setAttribute("hidden", "");
            const formData = new FormData(form);
            const username = formData.get("username");
            const password = formData.get("password");
            const remember = Boolean(formData.get("remember"));
            const submitButton = form.querySelector("button[type='submit']");
            submitButton?.setAttribute("disabled", "true");
            submitButton?.classList.add("is-busy");
            try {
                const ok = await matchCredential(username, password);
                if (!ok) {
                    if (!credentialStore.length) {
                        errorEl && (errorEl.textContent = "Reviewer credential data is not included in this build. Use the private link or request credentials from the editorial office.");
                    } else {
                        errorEl && (errorEl.textContent = defaultErrorMessage);
                    }
                    errorEl?.removeAttribute("hidden");
                    submitButton?.removeAttribute("disabled");
                    submitButton?.classList.remove("is-busy");
                    return;
                }
                persistSession(cleanValue(username).trim().toLowerCase(), remember);
                redirectToCenter();
            } catch (error) {
                console.error("Login failed", error);
                if (errorEl) {
                    errorEl.textContent = "Secure login is not supported in this browser. Please update your browser or switch devices.";
                }
                errorEl?.removeAttribute("hidden");
                submitButton?.removeAttribute("disabled");
                submitButton?.classList.remove("is-busy");
            }
        });
        return;
    }

    if (body.dataset.view === "center") {
        if (!isSessionActive(currentSession)) {
            clearSession();
            redirectToLogin();
            return;
        }
        updateSessionDisplay(currentSession);
    }
})();
