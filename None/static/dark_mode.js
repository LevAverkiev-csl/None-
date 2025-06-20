// Функция для проверки и применения предпочтений
function checkDarkModePreference() {
    const darkModeToggle = document.getElementById('dark-mode-toggle');
    if (!darkModeToggle) {
        console.error('Переключатель темного режима не найден');
        return;
    }

    const savedDarkMode = localStorage.getItem('darkMode') === 'enabled';
    const isDarkMode = userSettings.darkMode || savedDarkMode;

    // Применяем тему
    document.body.classList.toggle('dark-mode', isDarkMode);
    darkModeToggle.checked = isDarkMode;

    // Синхронизируем с localStorage
    localStorage.setItem('darkMode', isDarkMode ? 'enabled' : 'disabled');
}

async function toggleDarkMode() {
    const body = document.body;
    const darkModeToggle = document.getElementById('dark-mode-toggle');
    if (!darkModeToggle) {
        console.error('Переключатель темного режима не найден');
        return;
    }

    const isDarkMode = !body.classList.contains('dark-mode');

    // Обновляем локальное состояние
    body.classList.toggle('dark-mode', isDarkMode);
    darkModeToggle.checked = isDarkMode;
    localStorage.setItem('darkMode', isDarkMode ? 'enabled' : 'disabled');

    // Отправляем на сервер
    try {
        const csrfToken = document.querySelector('meta[name="csrf-token"]').content;
        const response = await fetch('/toggle_dark_mode', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': csrfToken
            },
            body: JSON.stringify({
                dark_mode: isDarkMode
            })
        });

        if (!response.ok) throw new Error('Ошибка сети');
        const data = await response.json();
        if (!data.success) console.error('Ошибка сервера');
    } catch (error) {
        console.error('Ошибка:', error);
        // Откатываем изменения при ошибке
        body.classList.toggle('dark-mode', !isDarkMode);
        darkModeToggle.checked = !isDarkMode;
        localStorage.setItem('darkMode', !isDarkMode ? 'enabled' : 'disabled');
    }
}

// Инициализация при загрузке
document.addEventListener('DOMContentLoaded', () => {
    checkDarkModePreference();
});