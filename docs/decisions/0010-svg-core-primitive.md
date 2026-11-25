<!-- SPDX-FileCopyrightText: 2026 Nicole Roy -->

# 0010. SVG as a core primitive: the native SVG layer and Display SVG

- **Status:** Accepted
- **Date:** 2026-11-24

## Context

The brief: SVG is a core graphics primitive, and the windowing system, `dm`, is built on "Display SVG", which runs on a native SVG layer.

Prior art ([research §4.4](../research/aegis-domain-os.md#44-prior-art-vector-imaging-models-for-displays)):

- Sun's NeWS and Adobe's Display PostScript made PostScript the imaging model of the window system. Neither caught on widely.
- Apple replaced Display PostScript with Quartz and its PDF imaging model. Secondary sources cite licensing costs, and that PDF needs no interpreter because it isn't a programming language.
- The model outlived the language.

Rust rendering options ([research §4.5](../research/aegis-domain-os.md#45-vector-rendering-in-rust)): resvg with usvg and tiny-skia (CPU, 0.47), and Vello's renderers (vello_cpu in alpha, vello_hybrid at 0.0.x).

## Decision

### The native SVG layer

1. **SVG documents are a first-class object type.** They have IDs ([0001](0001-object-identifiers.md)) and a type manager whose traits cover editing a document and rendering it.
2. **Imaging model.** The static rendering model of SVG 2:
   - paths and basic shapes, text, and raster images;
   - solid, gradient and pattern paint;
   - clipping, masking, group opacity and blending;
   - transforms and a defined subset of filters.

   Styling uses presentation attributes and a subset of CSS. The design session specifies the exact profile as the "ASPIS SVG profile".
3. **Excluded permanently:** scripting, `foreignObject`, and references to external URLs. Images, fonts and other documents are referenced by object ID, which requires a capability. Animation will come later through a separate declarative API rather than SMIL.
4. **Any program can render.** The renderer is a library and service available to every program, not only the display: for example to render into an image object or for printing.
5. **Text is text.** Text stays as Unicode in `<text>` elements, shaped and laid out with OpenType fonts, which are themselves objects. Any text on screen can be selected, copied, searched, and read by assistive technology.

### Display SVG

6. **A display server built on the native SVG layer.** It runs in user space, one instance per display. It holds each client's document as a retained tree, composites the documents into the screen, rasterizes, and presents frames through the display driver ([0009](0009-text-as-graphics-console.md)). It tracks damage per element and caches rasterized layers, so an update redraws only what changed.
7. **Protocol.** Clients change their documents with a compact binary protocol of DOM operations: create, set attribute, insert, remove, set text and commit. The protocol is defined in the ASPIS IDL and carried by ASPIS RPC. XML is for import, export and storage, never the hot path.
8. **Network transparency.** A client on another node can own a surface on this display over the secure transport ([0003](0003-hybrid-post-quantum-cryptography.md), [0004](0004-network-transparency-and-failure.md)). Creating a surface needs a capability granted under dm's policy.
9. **Input.** The server hit-tests pointer events against SVG geometry. It delivers each event to the owning client, tagged with the ID of the element hit. Keyboard focus and grabs follow dm's policy ([0011](0011-dm-window-system.md)).
10. **Rendering backend.** CPU rasterization in pure Rust comes first; GPU acceleration comes later through virtio-gpu on QEMU and native drivers. The library is chosen in the design session; candidates are resvg/usvg/tiny-skia, vello_cpu and vello_hybrid.
11. **Hardening.**
    - Each client has limits on element count, path complexity, filter area, image memory and text size.
    - XML, font and image decoders run in isolated servers, without the display server's authority.

## Consequences

- Resolution independence and HiDPI scaling come with the imaging model.
- Remote display is built in and authenticated.
- A rendering, text-shaping and font stack has to exist before dm can run.
- CPU rendering limits performance until GPU drivers exist, and the Pi 4's GPU stack is a large project.
- The ASPIS SVG profile has to be specified and kept stable. SVG files from elsewhere may need conversion or may render only partly.

## References

- [Research notes §4.4, §4.5](../research/aegis-domain-os.md)
- [SVG 2](https://www.w3.org/TR/SVG2/)
