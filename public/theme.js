// public/theme.js
document.addEventListener('DOMContentLoaded', () => {
    const themeSelect = document.getElementById('theme-select');
    const themeStylesheet = document.getElementById('theme-stylesheet');
    const currentTheme = localStorage.getItem('theme') || 'default';

    function applyTheme(themeName) {
        let themePath = '';
        if (themeName !== 'default') {
            themePath = `/themes/${themeName}-theme.css`;
        }
        themeStylesheet.setAttribute('href', themePath);
        localStorage.setItem('theme', themeName);
        if (themeSelect) {
            themeSelect.value = themeName;
        }
        // Add a class to body for more specific CSS overrides if needed
        document.body.className = ''; // Clear previous theme classes
        if (themeName !== 'default') {
            document.body.classList.add(`${themeName}-theme`);
        }
    }

    if (themeSelect) {
        themeSelect.addEventListener('change', (event) => {
            applyTheme(event.target.value);
        });
    }

    // Apply the stored theme on page load
    applyTheme(currentTheme);
});
