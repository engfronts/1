const navLinks = document.querySelectorAll(".nav-link");
const currentPage = document.body.dataset.page;

navLinks.forEach(link => {
    const targetPage = link.dataset.page;
    if (targetPage === currentPage) {
        link.classList.add("active");
        link.setAttribute("aria-current", "page");
    }
});

const backToTop = document.querySelector(".back-to-top");
backToTop?.addEventListener("click", event => {
    event.preventDefault();
    window.scrollTo({ top: 0, behavior: "smooth" });
});

const confirmForms = document.querySelectorAll("form[data-confirm]");
confirmForms.forEach(form => {
    form.addEventListener("submit", event => {
        const message = form.dataset.confirm || "Are you sure you want to submit?";
        if (!window.confirm(message)) {
            event.preventDefault();
        }
    });
});

const verificationForms = document.querySelectorAll("form[data-verify='code']");
verificationForms.forEach(form => {
    const input = form.querySelector("[data-code-input]");
    const canvas = form.querySelector("[data-code-canvas]");
    const refreshBtn = form.querySelector("[data-code-refresh]");
    const errorEl = form.querySelector(".form-error");
    const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    const ctx = canvas?.getContext ? canvas.getContext("2d") : null;

    const clearError = () => {
        errorEl?.setAttribute("hidden", "");
        input?.removeAttribute("aria-invalid");
    };

    const drawCode = code => {
        if (!canvas || !ctx) {
            return;
        }
        const { width, height } = canvas;
        ctx.clearRect(0, 0, width, height);
        const gradient = ctx.createLinearGradient(0, 0, width, height);
        gradient.addColorStop(0, "#f0f4ff");
        gradient.addColorStop(1, "#ffece1");
        ctx.fillStyle = gradient;
        ctx.fillRect(0, 0, width, height);

        for (let i = 0; i < 6; i += 1) {
            ctx.strokeStyle = `rgba(${Math.random() * 255}, ${Math.random() * 255}, ${Math.random() * 255}, 0.6)`;
            ctx.beginPath();
            ctx.moveTo(Math.random() * width, Math.random() * height);
            ctx.lineTo(Math.random() * width, Math.random() * height);
            ctx.stroke();
        }

        for (let i = 0; i < 40; i += 1) {
            ctx.fillStyle = `rgba(0,0,0,${Math.random() * 0.2})`;
            ctx.beginPath();
            ctx.arc(Math.random() * width, Math.random() * height, Math.random() * 2, 0, 2 * Math.PI);
            ctx.fill();
        }

        const charArray = code.split("");
        charArray.forEach((char, index) => {
            const angle = (Math.random() - 0.5) * 0.6;
            const x = (width / (charArray.length + 1)) * (index + 1);
            const y = height / 2 + (Math.random() * 12 - 6);
            ctx.save();
            ctx.translate(x, y);
            ctx.rotate(angle);
            ctx.fillStyle = `hsl(${Math.random() * 360}, 75%, 35%)`;
            ctx.font = "bold 28px 'Manrope', 'Segoe UI', sans-serif";
            ctx.textAlign = "center";
            ctx.fillText(char, 0, 10);
            ctx.restore();
        });
    };

    const generateCode = () => {
        let code = "";
        for (let i = 0; i < 6; i += 1) {
            code += chars[Math.floor(Math.random() * chars.length)];
        }
        form.dataset.expectedCode = code;
        drawCode(code);
        if (input) {
            input.value = "";
        }
    };

    refreshBtn?.addEventListener("click", event => {
        event.preventDefault();
        generateCode();
        clearError();
    });

    input?.addEventListener("input", () => {
        input.value = input.value.toUpperCase();
        clearError();
    });

    form.addEventListener("submit", event => {
        const expected = form.dataset.expectedCode || "";
        const provided = input?.value?.trim().toUpperCase() || "";
        if (!expected || provided !== expected) {
            event.preventDefault();
            errorEl?.removeAttribute("hidden");
            input?.setAttribute("aria-invalid", "true");
            input?.focus();
            generateCode();
            return;
        }
        clearError();
        generateCode();
    });

    generateCode();
});
