function translatePost(postId) {
    const modal = document.getElementById('translate-modal');
    const translateButton = document.getElementById('translate-button');
    const sourceLang = document.getElementById('source-lang');
    const targetLang = document.getElementById('target-lang');
    
    if (!modal || !translateButton || !sourceLang || !targetLang) {
        console.error('Не найдены элементы модального окна перевода');
        return;
    }

    let currentPostId = postId;
    const postContentElement = document.querySelector(`#post-${postId} .post-content`);
    
    if (!postContentElement) {
        console.error(`Не найден элемент поста с ID ${postId}`);
        return;
    }

    const csrfToken = document.querySelector('meta[name="csrf-token"]');
    if (!csrfToken) {
        console.error('CSRF токен не найден');
        return;
    }

    // Показываем модальное окно
    modal.style.display = 'flex';

    // Функция проверки состояния выбора языков
    const checkSelection = () => {
        translateButton.disabled = !(sourceLang.value && targetLang.value);
    };

    // Обработчики изменений
    sourceLang.addEventListener('change', checkSelection);
    targetLang.addEventListener('change', checkSelection);

    // Обработчик клика по кнопке перевода
    const translateHandler = async () => {
        const originalText = postContentElement.textContent.trim();
        
        if (!originalText) {
            alert('Текст поста пуст');
            return;
        }

        try {
            const response = await fetch('/translate', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken.content
                },
                body: JSON.stringify({
                    text: originalText,
                    source_lang: sourceLang.value,
                    target_lang: targetLang.value
                })
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.error || `HTTP error! status: ${response.status}`);
            }

            const data = await response.json();
            
            if (!data.translated_text) {
                throw new Error('Сервер не вернул переведенный текст');
            }

            postContentElement.textContent = data.translated_text;
            closeModal();
            
        } catch (error) {
            console.error('Ошибка перевода:', error);
            alert(`Ошибка перевода: ${error.message}`);
        }
    };

    translateButton.addEventListener('click', translateHandler);

    // Закрытие модального окна
    const closeModal = () => {
        modal.style.display = 'none';
        sourceLang.value = '';
        targetLang.value = '';
        translateButton.disabled = true;
        translateButton.removeEventListener('click', translateHandler);
        sourceLang.removeEventListener('change', checkSelection);
        targetLang.removeEventListener('change', checkSelection);
    };

    // Закрытие по клику вне модального окна
    modal.addEventListener('click', (e) => {
        if (e.target === modal) closeModal();
    });
}