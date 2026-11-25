<!-- SPDX-FileCopyrightText: 2026 Nicole Roy -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# 0046. Fallback Noto fonts for the WGL4 symbols Noto Sans Mono lacks

- **Status:** Accepted
- **Date:** 2026-11-25

## Context

The console's atlases are rasterized from Noto Sans Mono ([0034](0034-noto-fonts-under-ofl.md), rule 1), and were meant to cover all of WGL4, the box-drawing characters, the block elements and U+FFFD.

Generating M1's atlases on 2026-11-25 showed that Noto Sans Mono v2.014 lacks 23 of WGL4's code points:

- **18 symbols:** ♠ ♣ ♥ ♦ (U+2660, 2663, 2665, 2666), ☺ ☻ ☼ (U+263A to 263C), ♀ ♂ (U+2640, 2642), ♪ ♫ (U+266A, 266B), ∏ ∑ ∫ ∕ ∟ (U+220F, 2211, 222B, 2215, 221F), ⌂ (U+2302) and ↨ (U+21A8). Most come from the IBM PC's code page 437.
- **The soft hyphen,** U+00AD.
- **The ligatures ﬁ and ﬂ** (U+FB01, FB02).
- **Two private-use code points,** U+F001 and U+F002, which some vendors used for the same ligatures.

The atlases drew all 23 as U+FFFD.

A check of the other Noto families' character maps on the same day found:

- **Noto Sans Math v3.000** has 17 of the 18 symbols: all but ☺.
- **Noto Sans Symbols v2.003** has ☺, U+263A.
- Both are under OFL-1.1, and their license files declare no Reserved Font Name, as [0034](0034-noto-fonts-under-ofl.md), rule 2 requires of any font ASPIS adopts.

The project owner decided on 2026-11-25 to fill the gap from fallback Noto fonts. [0034](0034-noto-fonts-under-ofl.md), rule 1 names them: the atlas generator takes each glyph from Noto Sans Mono when it has one, then from Noto Sans Math, then from Noto Sans Symbols. [0034](0034-noto-fonts-under-ofl.md), rule 4 gives the set each atlas covers. The rules below settle the five code points that no fallback fills.

## Decision

1. **The soft hyphen is drawn as a hyphen.** A console shows the characters it's given, so U+00AD gets the glyph of U+002D.
2. **The ligatures and the private-use code points leave the set.** A monospace console never ligates, and private-use code points have no standard meaning. The kernel draws them as U+FFFD, as it does any character outside its atlases.

## Consequences

- **The console draws every character it promises.** No WGL4 symbol in the set falls back to U+FFFD.
- **Three font files are vendored, not one.** The release's license files and SBOM name all three ([0034](0034-noto-fonts-under-ofl.md), rule 3), and `REUSE.toml` covers them.
- **The symbols look slightly different from the text.** They come from fonts with their own proportions, scaled into the mono cell. The atlas tool's preview is where to judge them.
- **The SVG layer can use the same fallbacks** when it draws these characters, so the console and the SVG layer still match ([0009](0009-text-as-graphics-console.md), rule 3).

## References

- [Noto Sans Math](https://github.com/notofonts/math) (release NotoSansMath-v3.000); [Noto Sans Symbols](https://github.com/notofonts/symbols) (release NotoSansSymbols-v2.003)
- [WGL4.0 character set](https://learn.microsoft.com/en-us/typography/opentype/otspec150/wgl4)
- [0034. Fonts: Noto, under the SIL Open Font License, with atlases at 16, 24 and 32 pixels](0034-noto-fonts-under-ofl.md)
