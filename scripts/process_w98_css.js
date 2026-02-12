const fs = require('fs');
const path = require('path');

const cssPath = 'C:\\Users\\raver\\AppData\\Local\\Temp\\98css_temp\\style.css';
const outputPath = 'c:\\Users\\raver\\source\\repos\\Radius-log-webserver\\assets\\css\\themes\\w98.css';

let css = fs.readFileSync(cssPath, 'utf8');

// 1. Replace fonts path
css = css.replace(/fonts\/converted\//g, '/fonts/w98/');

// 2. Replace svg-load with url
css = css.replace(/svg-load\("([^"]+)"\)/g, 'url("$1")');

// 3. Replace relative icon paths
css = css.replace(/\.\/icon\//g, '/img/themes/w98/');

// 4. Scoping
// This is a bit naive but should work for most rules
// We want to prefix every top-level selector with [data-theme="w98"]
// Except for @rules like @font-face, @media

const lines = css.split('\n');
const scopedLines = lines.map(line => {
    const trimmed = line.trim();
    // Skip empty lines, comments, properties (indented), and @rules
    if (!trimmed || trimmed.startsWith('/*') || trimmed.startsWith('*') || trimmed.startsWith('@') || line.startsWith(' ') || line.startsWith('\t') || trimmed.startsWith('}') || trimmed.startsWith('{')) {
        return line;
    }

    // Check if it's a selector: either ends with { or ends with ,
    if (trimmed.endsWith('{') || trimmed.endsWith(',')) {
        return trimmed.split(',').map(s => {
            let selector = s.trim();
            if (!selector) return '';
            if (selector === ':root' || selector === 'body') {
                return '[data-theme="w98"]';
            }
            // If it already has the prefix (unlikely but safe)
            if (selector.startsWith('[data-theme="w98"]')) return selector;

            // Handle selectors that might have { at the end
            let suffix = '';
            if (selector.endsWith('{')) {
                selector = selector.slice(0, -1).trim();
                suffix = ' {';
            }
            return `[data-theme="w98"] ${selector}${suffix}`;
        }).filter(s => s).join(', ') + (trimmed.endsWith(',') ? ',' : '');
    }

    return line;
});

const header = `/* ==========================================
   WINDOWS 98 (SECOND EDITION)
   Full 98.css integration
   ========================================== */\n\n`;

fs.writeFileSync(outputPath, header + scopedLines.join('\n'));
console.log('w98.css generated successfully');
