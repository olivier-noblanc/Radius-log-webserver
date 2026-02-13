const fs = require('fs');
const path = require('path');

const THEMES_TO_SCOPE = ['macos', 'win31'];

function scopeCSS(css, theme) {
    const selector = `[data-theme="${theme}"]`;
    const lines = css.split('\n');
    const result = [];

    let inMediaQuery = false;
    let braceDepth = 0;

    for (let line of lines) {
        const trimmed = line.trim();

        // Empty lines, comments
        if (!trimmed || trimmed.startsWith('/*') || trimmed.startsWith('*')) {
            result.push(line);
            continue;
        }

        // Media queries
        if (trimmed.startsWith('@media')) {
            inMediaQuery = true;
            braceDepth = 0;
            result.push(line);
            continue;
        }

        if (inMediaQuery) {
            for (let c of trimmed) {
                if (c === '{') braceDepth++;
                if (c === '}') braceDepth--;
            }
            if (braceDepth === 0 && trimmed.endsWith('}')) {
                inMediaQuery = false;
            }
        }

        // :root → [data-theme="xxx"]
        if (trimmed.startsWith(':root')) {
            result.push(line.replace(':root', selector));
            continue;
        }

        // body → [data-theme="xxx"] body
        if (trimmed.startsWith('body') && trimmed.includes('{')) {
            result.push(line.replace('body', `${selector} body`));
            continue;
        }

        // Skip @-rules
        if (trimmed.startsWith('@')) {
            result.push(line);
            continue;
        }

        // Scope regular selectors
        if (trimmed.includes('{') && !trimmed.startsWith('}')) {
            const bracePos = line.indexOf('{');
            const selectorsPartRaw = line.substring(0, bracePos);
            const propsPartRaw = line.substring(bracePos);
            const selectorsPart = selectorsPartRaw.trim();

            if (selectorsPart && !selectorsPart.endsWith('}')) {
                // Already scoped?
                if (selectorsPart.includes(`[data-theme="${theme}"]`)) {
                    result.push(line);
                    continue;
                }

                const scopedSelectors = selectorsPart
                    .split(',')
                    .map(s => `${selector} ${s.trim()}`)
                    .join(', ');

                const indentation = line.length - line.trimStart().length;
                result.push(' '.repeat(indentation) + scopedSelectors + propsPartRaw);
                continue;
            }
        }

        result.push(line);
    }

    return result.join('\n');
}

function fixScrollbars(css, theme) {
    const scrollbarPatterns = [
        '::-webkit-scrollbar',
        '::-webkit-scrollbar-track',
        '::-webkit-scrollbar-thumb',
        '::-webkit-scrollbar-thumb:hover',
        '::-webkit-scrollbar-button',
        '::-webkit-scrollbar-corner'
    ];

    let result = css;
    for (let pattern of scrollbarPatterns) {
        const regex = new RegExp(`\\[data-theme="${theme}"\\]\\s*${pattern.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`, 'g');
        result = result.replace(regex, `body[data-theme="${theme}"]${pattern}`);
    }

    return result;
}

// Main
console.log('🔨 Building scoped theme files...\n');

for (let theme of THEMES_TO_SCOPE) {
    const inputPath = `assets/css/themes/${theme}.css`;
    const outputPath = `assets/css/themes/${theme}-scoped.css`;

    if (!fs.existsSync(inputPath)) {
        console.warn(`⚠️  ${theme}.css not found, skipping`);
        continue;
    }

    console.log(`Processing ${theme}.css...`);

    let content = fs.readFileSync(inputPath, 'utf8');

    // Step 1: Scope all rules
    content = scopeCSS(content, theme);

    // Step 2: Fix scrollbar syntax
    content = fixScrollbars(content, theme);

    // Step 3: Write output
    fs.writeFileSync(outputPath, content);

    const inputSize = fs.statSync(inputPath).size;
    const outputSize = fs.statSync(outputPath).size;

    console.log(`  ✅ Generated ${theme}-scoped.css (${inputSize} → ${outputSize} bytes)\n`);
}

console.log('🎉 Theme build complete!');
