<!-- SPDX-FileCopyrightText: 2026 Nicole Roy -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# 0034. Fonts: Noto, under the SIL Open Font License, with atlases at 16, 24 and 32 pixels

- **Status:** Accepted. Amends [0008](0008-mpl-2.0-license.md) (rule 4). Amended by [0046](0046-fallback-fonts-for-wgl4-symbols.md) (rules 1 and 4).
- **Date:** 2026-11-25

## Context

[0009](0009-text-as-graphics-console.md), rule 3 has the kernel draw its console from glyph atlases rasterized at build time from the same OpenType family the SVG layer uses. It names no family, and no atlas sizes ([design backlog, D06](../design/design-backlog.md#m1-first-light)). The console needs a monospace face. The SVG layer, and dm's text, need a proportional face and many scripts.

[0008](0008-mpl-2.0-license.md), rule 4 admits dependencies under MIT, Apache-2.0, BSD or MPL-2.0. Most maintained open font families use the SIL Open Font License 1.1 instead. A survey on 2026-11-25, reading each family's own license file, found:

- **Go fonts** (BSD-3-Clause) are the only actively maintained family under an admitted license with both a monospace and a proportional face. They cover WGL4: Latin, Greek and Cyrillic. Go Mono has 40 of the 128 box-drawing characters (U+2500–257F) and 8 of the 32 block elements (U+2580–259F). The fonts haven't changed since June 2022.
- **Families that were once Apache-2.0 have moved to OFL-1.1:** Roboto in 2020, Open Sans in 2022, Roboto Mono in 2025, and Arimo and Cousine in 2026. Commit Mono's fonts are OFL too, although its repository's top-level license is MIT.
- **Noto Sans Mono and Noto Sans** (OFL-1.1, from the Noto project's Latin, Greek and Cyrillic repository) declare no Reserved Font Name. Noto Sans Mono has every box-drawing and block character. The Noto families together reach more scripts than any other open family.

About the OFL:

- It is OSI-approved. The FSF lists it as a free license for fonts, and Debian treats it as free.
- Its copyleft covers the font software only, not programs or documents that use it.
- Fonts may be bundled with any software. They may not be sold by themselves.
- A copy, original or modified, must carry the font's copyright notice and the license, as a text file or in metadata the user can easily view.
- A Reserved Font Name may not be used by a modified version. Noto declares none.

The project owner decided on 2026-11-25: Noto, admitting the OFL for fonts by amending 0008, with atlases at 16, 24 and 32 pixels. The rules below spell that decision out.

## Decision

1. **The family is Noto.**
   - The kernel console's atlases are rasterized from Noto Sans Mono.
   - The SVG layer uses Noto Sans Mono and Noto Sans, the same family, as [0009](0009-text-as-graphics-console.md), rule 3 requires. Other Noto families can be added as fallbacks for scripts that these two don't cover.
   - The build pins each font file by release and SHA-512 hash, and fetches nothing at build time.
2. **Fonts may be licensed under OFL-1.1.** This amends [0008](0008-mpl-2.0-license.md), rule 4.
   - OFL-1.1 is admitted for fonts only: font files and the data derived from them, such as glyph atlases. It is never admitted for code.
   - Any font ASPIS adopts later must declare no Reserved Font Name, or ASPIS must keep its name on any subset or derivative it ships.
3. **Atlases are derived font data, under OFL-1.1.**
   - A glyph atlas is a modified version of the font in OFL's terms, so it stays under OFL-1.1, with Noto's copyright notice.
   - The atlases are generated at build time, not committed. Their source is the pinned font files.
   - `aspis.efi` holds MPL-2.0 code and OFL-1.1 font data. Each distribution of it, such as a release or a node image, carries the OFL text and Noto's notice with it, in its license files and its SBOM.
4. **There are three atlases, with cells 16, 24 and 32 pixels high.**
   - Each atlas holds 8-bit coverage values, which the kernel blends with the console's colors. There is no subpixel rendering.
   - The kernel picks the atlas by framebuffer width: 16 pixels below 1280, 24 pixels from 1280 to below 2560, and 32 pixels from 2560. If the chosen size doesn't give at least 80 columns and 25 rows, it falls back to the next smaller one. A kernel argument can choose the size instead (D09).
   - Each atlas covers WGL4, the box-drawing characters, the block elements and U+FFFD REPLACEMENT CHARACTER. The kernel draws any other character as U+FFFD.

## Consequences

- **One family, from the first message to dm.** The console looks the same before and after Display SVG takes over, as [0009](0009-text-as-graphics-console.md) rule 4 intends, and the SVG layer has a path to many scripts.
- **The images carry two licenses.** Release tooling (C69) has to put the OFL text and Noto's notice beside every image, and the REUSE configuration (C01) has to name OFL-1.1 for the font files. The license check that enforces rule 4 has to tell font data from code.
- **The console covers Latin, Greek and Cyrillic.** Other scripts reach the screen only through the SVG layer.
- **The atlases add to the image's size.** WGL4 and the box and block characters come to about 810 glyphs. At one byte per pixel, the three atlases take about 900 KiB together, uncompressed. That figure is an estimate; C03 will measure it, and may store the atlases compressed.
- **The glyph atlas tool (C03) can start.** It rasterizes with a permissively licensed Rust rasterizer at build time. The kernel holds no rasterizer ([0009](0009-text-as-graphics-console.md), rule 3).

## References

- [Noto: Latin, Greek and Cyrillic](https://github.com/notofonts/latin-greek-cyrillic) and its [OFL.txt](https://github.com/notofonts/latin-greek-cyrillic/blob/main/OFL.txt)
- [SIL Open Font License 1.1](https://openfontlicense.org/open-font-license-official-text/) and its [FAQ](https://openfontlicense.org/ofl-faq/)
- [OSI: OFL-1.1](https://opensource.org/license/ofl-1-1); [FSF license list: SIL OFL](https://www.gnu.org/licenses/license-list.html#SILOFL); [Debian: DFSG licenses](https://wiki.debian.org/DFSGLicenses)
- [Go fonts](https://go.dev/blog/go-fonts) and their [license](https://raw.githubusercontent.com/golang/image/master/font/gofont/ttfs/README)
- [0008. License: MPL-2.0](0008-mpl-2.0-license.md); [0009. Console: text as graphics](0009-text-as-graphics-console.md)
