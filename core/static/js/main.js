// ------------------------------------------------------------
// MAIN.JS — базова логіка для твого Django сайту
// ------------------------------------------------------------

// Перевірка підключення JS
console.log("main.js loaded successfully");


// ------------------------------------------------------------
// 1) Автоматичне закриття мобільного меню після кліку
// ------------------------------------------------------------
document.addEventListener("click", function (event) {
    const navbar = document.querySelector(".navbar-collapse");

    // якщо меню відкрите
    const isOpen = navbar.classList.contains("show");

    // якщо клік поза меню → закрити меню
    if (isOpen && !event.target.closest(".navbar")) {
        const collapse = bootstrap.Collapse.getInstance(navbar);
        collapse.hide();
    }
});


// ------------------------------------------------------------
// 2) Кнопка "Scroll to top"
// ------------------------------------------------------------
function scrollToTop() {
    window.scrollTo({ top: 0, behavior: "smooth" });
}

// Авто-добавлення кнопки при прокрутці
window.addEventListener("scroll", function () {
    let btn = document.getElementById("scrollTopBtn");

    if (!btn) {
        btn = document.createElement("button");
        btn.id = "scrollTopBtn";
        btn.innerText = "↑";
        btn.style.position = "fixed";
        btn.style.bottom = "25px";
        btn.style.right = "25px";
        btn.style.padding = "10px 15px";
        btn.style.fontSize = "20px";
        btn.style.border = "none";
        btn.style.borderRadius = "8px";
        btn.style.background = "#0d6efd";
        btn.style.color = "#fff";
        btn.style.cursor = "pointer";
        btn.style.display = "none";
        btn.style.zIndex = "999";
        btn.onclick = scrollToTop;

        document.body.appendChild(btn);
    }

    // показ/приховування
    if (window.scrollY > 200) {
        btn.style.display = "block";
    } else {
        btn.style.display = "none";
    }
});


// ------------------------------------------------------------
// 3) Універсальна функція показу Bootstrap alert
// ------------------------------------------------------------
function showAlert(message, type = "info", timeout = 4000) {
    const container = document.createElement("div");
    container.className = `alert alert-${type}`;
    container.role = "alert";
    container.style.position = "fixed";
    container.style.top = "20px";
    container.style.right = "20px";
    container.style.zIndex = 10000;
    container.innerText = message;

    document.body.appendChild(container);

    setTimeout(() => container.remove(), timeout);
}


// ------------------------------------------------------------
// 4) Місце для майбутніх функцій DSS
// ------------------------------------------------------------

// async function loadSecurityData() {
//     const response = await fetch("/api/security-status/");
//     const data = await response.json();
//     console.log("Security data:", data);
// }

// async function updateDashboard() {
//     // Логіка отримання даних з CrowdStrike/Nexpose у майбутньому
// }


// ------------------------------------------------------------
// Кінець main.js
// ------------------------------------------------------------
