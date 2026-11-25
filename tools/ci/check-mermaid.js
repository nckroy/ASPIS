// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

// Checks that every Mermaid diagram in the given Markdown files renders
// with the newest stable Mermaid (ADR 0024; CLAUDE.md, "Check that every
// diagram renders").
//
// Mermaid's C4 layout wraps rows at screen.availWidth, and headless Chrome
// reports a narrow screen, so this pins it to 1512, a laptop's logical
// width. The pin only takes effect on a page loaded with page.goto, so the
// host page is a file:// URL.
//
// Usage: NODE_PATH=<dir with mermaid and puppeteer-core> \
//        node check-mermaid.js <file.md>...
// CHROME_PATH names the browser; the default is Google Chrome's usual path.
// With SCREENSHOTS=<dir>, each diagram is also saved as a PNG to look at.

const fs = require('fs');
const os = require('os');
const path = require('path');
const puppeteer = require('puppeteer-core');

const CHROME =
  process.env.CHROME_PATH ||
  (process.platform === 'darwin'
    ? '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
    : '/usr/bin/google-chrome');

(async () => {
  const files = process.argv.slice(2);
  const shots = process.env.SCREENSHOTS;
  if (shots) fs.mkdirSync(shots, { recursive: true });
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mermaid-check-'));
  const host = path.join(dir, 'host.html');
  fs.writeFileSync(host, '<!doctype html><html><body></body></html>');

  const browser = await puppeteer.launch({
    executablePath: CHROME,
    headless: true,
    args: ['--no-sandbox'],
  });
  const page = await browser.newPage();
  await page.evaluateOnNewDocument(() => {
    Object.defineProperty(window.screen, 'availWidth', { get: () => 1512 });
  });
  await page.setViewport({ width: 1512, height: 1000 });
  await page.goto('file://' + host);
  await page.addScriptTag({ path: require.resolve('mermaid/dist/mermaid.min.js') });
  const version = await page.evaluate(() => {
    mermaid.initialize({ startOnLoad: false });
    return mermaid.version ? mermaid.version : 'unknown';
  });
  console.log(`Mermaid ${version}`);

  let count = 0;
  let failures = 0;
  for (const file of files) {
    const md = fs.readFileSync(file, 'utf8');
    const blocks = [...md.matchAll(/```mermaid\n([\s\S]*?)```/g)].map((m) => m[1]);
    for (let i = 0; i < blocks.length; i++) {
      count++;
      const name = `${file} #${i + 1}`;
      const res = await page.evaluate(
        async (code, id) => {
          try {
            await mermaid.parse(code);
            const { svg } = await mermaid.render(id, code);
            // Every Mermaid SVG has an .error-icon CSS rule, so look for the
            // error text instead.
            if (svg.includes('Syntax error in text')) return { ok: false, err: 'syntax error' };
            document.body.innerHTML = '<div id="out">' + svg + '</div>';
            const el = document.querySelector('#out svg');
            const vb = el.viewBox.baseVal;
            el.setAttribute('width', vb.width);
            el.setAttribute('height', vb.height);
            el.style.maxWidth = 'none';
            return { ok: true, w: Math.round(vb.width), h: Math.round(vb.height) };
          } catch (e) {
            return { ok: false, err: String(e).split('\n')[0] };
          }
        },
        blocks[i],
        'diagram' + count,
      );
      if (!res.ok) {
        failures++;
        console.log(`FAIL ${name}: ${res.err}`);
        continue;
      }
      if (shots) {
        const el = await page.$('#out svg');
        const out = path.join(shots, `${path.basename(file, '.md')}-${i + 1}.png`);
        await el.screenshot({ path: out });
      }
      console.log(`ok   ${name} (${res.w}x${res.h})`);
    }
  }
  await browser.close();
  console.log(`${count} diagrams, ${failures} failures`);
  process.exit(failures ? 1 : 0);
})().catch((e) => {
  console.error(e);
  process.exit(2);
});
