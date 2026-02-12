// Script de validation pour vérifier tous les thèmes
(function () {
    const themes = [
        'neon', 'onyx-glass', 'cyber-tactical',
        'win31', 'win95', 'xp', 'macos',
        'terminal', 'c64', 'nes', 'snes',
        'dsfr', 'compact', 'aero', 'amber'
    ];

    const issues = [];

    themes.forEach(theme => {
        // Switch theme
        document.documentElement.setAttribute('data-theme', theme);

        // Wait for CSS to load
        setTimeout(() => {
            const header = document.querySelector('.main-header');
            if (!header) return;

            const rect = header.getBoundingClientRect();

            // Check if header is cut off
            if (rect.top < 0) {
                issues.push(`${theme}: Header cut off (top: ${rect.top}px)`);
            }

            // Check if header overflows
            if (rect.right > window.innerWidth) {
                issues.push(`${theme}: Header overflow (right: ${rect.right}px)`);
            }

            // Check font size
            const fontSize = parseFloat(window.getComputedStyle(document.body).fontSize);
            if (fontSize < 11) {
                issues.push(`${theme}: Font too small (${fontSize}px)`);
            }

            // Check contrast (basic)
            const bg = window.getComputedStyle(header).backgroundColor;
            const color = window.getComputedStyle(header).color;
            if (bg === color) {
                issues.push(`${theme}: Same bg/text color`);
            }

        }, 100);
    });

    setTimeout(() => {
        if (issues.length === 0) {
            console.log('✅ All themes validated!');
        } else {
            console.error('❌ Issues found:');
            issues.forEach(issue => console.error(`  - ${issue}`));
        }
    }, themes.length * 150);
})();
