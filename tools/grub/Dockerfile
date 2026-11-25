# SPDX-FileCopyrightText: 2026 Nicole Roy
# SPDX-License-Identifier: MPL-2.0

# Builds GRUB 2.14 for arm64-efi from source (ADR 0036, rule 1), as the
# ESP's /EFI/BOOT/BOOTAA64.EFI, set to read /aspis/grub.cfg (ADR 0035, rule 6).
# The base image is named by digest, and the source by its SHA-256, which was
# checked against the release's signature from GNU's keyring.

FROM debian:trixie-slim@sha256:8aa5a7bf5a1955bddbe7d74fcdd0b91ab30e74362a8b73af672b0481b35b44a0

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      build-essential bison flex gawk gettext python3 ca-certificates curl xz-utils \
 && rm -rf /var/lib/apt/lists/*

ARG GRUB_VERSION=2.14
ARG GRUB_SHA256=bc8d3c73535b8838d8c8e2654d73edc4e6ae8c8acdb45d5df5dc9a1547446d43

WORKDIR /src
RUN curl -fsSL -o grub.tar.xz https://mirrors.kernel.org/gnu/grub/grub-${GRUB_VERSION}.tar.xz \
 && echo "${GRUB_SHA256}  grub.tar.xz" | sha256sum -c - \
 && tar xf grub.tar.xz

WORKDIR /src/grub-${GRUB_VERSION}
RUN ./configure --with-platform=efi --target=aarch64 --disable-werror --prefix=/opt/grub \
 && make -j"$(nproc)" \
 && make install

COPY early.cfg /early.cfg
# gfxterm (with the video and font modules it needs) lets the menu set the
# firmware's video mode, which the stub keeps: `cargo xtask run --resolution`.
RUN /opt/grub/bin/grub-mkimage -O arm64-efi -o /BOOTAA64.EFI -p /aspis -c /early.cfg \
      part_gpt part_msdos fat normal linux chain configfile echo search search_fs_file \
      efi_gop gfxterm videoinfo test ls cat sleep reboot halt
