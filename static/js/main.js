// main.js - Общие функции JavaScript для всего приложения

// Константы
const SERVER_URL = "{{ SERVER_URL }}"; // Этот шаблон будет заменен Flask'ом
let translations = {};
let currentLang = localStorage.getItem('language') || 'uz_lat'; // Язык по умолчанию

/**
 * Асинхронно загружает переводы для указанного языка.
 * @param {string} lang - Код языка (например, 'uz_lat', 'ru', 'en').
 */
async function loadTranslations(lang) {
    try {
        const response = await fetch(`${SERVER_URL}/api/translations/${lang}`);
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        translations = await response.json();
    } catch (error) {
        console.error("Error loading translations:", error);
        // Fallback to default messages if translations fail to load
        translations = {
            error_fetch: 'Ошибка загрузки данных:',
            // ... другие базовые переводы, которые могут понадобиться при ошибке
        };
        showNotification(`${translations.error_fetch} ${error.message}`, 'danger');
    }
}

/**
 * Применяет загруженные переводы ко всем элементам на странице
 * с атрибутами data-translate и data-translate-placeholder.
 */
function applyTranslations() {
    document.querySelectorAll('[data-translate]').forEach(element => {
        const key = element.getAttribute('data-translate');
        if (translations[key]) {
            element.innerText = translations[key];
        }
    });
    document.querySelectorAll('[data-translate-placeholder]').forEach(element => {
        const key = element.getAttribute('data-translate-placeholder');
        if (translations[key]) {
            element.placeholder = translations[key];
        }
    });
}

/**
 * Настраивает переключение тем (светлая, темная, дальтоническая).
 * Ожидает, что на странице есть кнопка с id="themeToggle".
 */
function setupThemeToggle() {
    const themeToggleBtn = document.getElementById('themeToggle');
    if (!themeToggleBtn) {
        console.warn("Theme toggle button with ID 'themeToggle' not found.");
        return;
    }

    const themes = ['light', 'dark', 'daltonic'];
    let currentThemeIndex = themes.indexOf(localStorage.getItem('theme') || 'light');
    if (currentThemeIndex === -1) currentThemeIndex = 0; // По умолчанию светлая тема

    const applyTheme = (theme) => {
        document.body.classList.remove(...themes); // Удаляем все классы тем
        document.body.classList.add(theme);
        localStorage.setItem('theme', theme);
        themeToggleBtn.innerText = {
            'light': '🌙',
            'dark': '☀️',
            'daltonic': '👁️'
        }[theme];
    };

    // Применяем начальную тему
    applyTheme(themes[currentThemeIndex]);

    // Добавляем слушатель события для переключения темы
    themeToggleBtn.addEventListener('click', () => {
        currentThemeIndex = (currentThemeIndex + 1) % themes.length;
        applyTheme(themes[currentThemeIndex]);
    });
}

/**
 * Отображает всплывающее уведомление.
 * @param {string} message - Текст сообщения.
 * @param {string} type - Тип уведомления ('info' или 'danger').
 */
function showNotification(message, type = 'info') {
    // Удаляем существующие уведомления, чтобы не нагромождать
    const existing = document.querySelector(".notification");
    if (existing) existing.remove();

    const notification = document.createElement('div');
    notification.className = `notification ${type}`; // Классы Tailwind CSS для цвета фона
    notification.innerText = message;
    document.body.appendChild(notification);

    // Удаляем уведомление через 3 секунды
    setTimeout(() => {
        notification.remove();
    }, 3000);
}

/**
 * Отображает модальное окно подтверждения.
 * @param {string} message - Сообщение для отображения в модальном окне.
 * @param {Function} onConfirm - Функция, вызываемая при подтверждении.
 */
function showModal(message, onConfirm) {
    const modal = document.createElement('div');
    modal.className = 'modal'; // Класс для затемнения фона и центрирования
    modal.innerHTML = `
        <div class="modal-content">
            <p>${message}</p>
            <div class="modal-buttons">
                <button id="confirmBtn" class="btn-primary" data-translate="confirm_button">${translations.confirm_button || 'Подтвердить'}</button>
                <button id="cancelBtn" class="btn-danger" data-translate="cancel_button">${translations.cancel_button || 'Отмена'}</button>
            </div>
        </div>
    `;
    document.body.appendChild(modal);

    // Применяем переводы к содержимому модального окна
    applyTranslations();

    document.getElementById('confirmBtn').onclick = () => {
        onConfirm();
        modal.remove(); // Закрываем модальное окно после подтверждения
    };
    document.getElementById('cancelBtn').onclick = () => {
        modal.remove(); // Закрываем модальное окно при отмене
    };
}

// Инициализация общих функций при загрузке DOM
document.addEventListener('DOMContentLoaded', async () => {
    // Загружаем переводы перед применением
    await loadTranslations(currentLang);
    applyTranslations();
    setupThemeToggle(); // Настраиваем переключение тем
});

// Экспортируем функции, если main.js будет использоваться как модуль
// export { loadTranslations, applyTranslations, setupThemeToggle, showNotification, showModal };
