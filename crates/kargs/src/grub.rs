// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Undoing GRUB's rewriting of the command line (ADR 0044).
//!
//! GRUB's arm64 `linux` command builds the load options from the menu
//! entry's words: it puts `BOOT_IMAGE=<path>` first, puts a backslash
//! before every `\`, `'` and `"` in a word, and wraps a word that contains a
//! space in double quotes (`grub_create_loader_cmdline` in GRUB 2.14). The
//! stub recovers the words and writes each one again in the grammar's own
//! form (ADR 0041, rule 5): a `key=value` whose value holds a space or a
//! double quote becomes `key="value"`, with `\"` and `\\` escapes.

/// Why GRUB's command line couldn't be converted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrubError {
    /// The output buffer is too small.
    TooLong,
    /// A double quote is never closed, or the line ends in a backslash.
    Unbalanced,
}

/// Whether `line`, as the stub received it, comes from GRUB's `linux`
/// command: it starts with `BOOT_IMAGE=`, after any spaces.
pub fn is_grub(line: &[u8]) -> bool {
    let start = line.iter().position(|&b| b != b' ').unwrap_or(line.len());
    line.get(start..)
        .is_some_and(|l| l.starts_with(b"BOOT_IMAGE="))
}

struct Out<'a> {
    buf: &'a mut [u8],
    len: usize,
}

impl Out<'_> {
    fn push(&mut self, b: u8) -> Result<(), GrubError> {
        let slot = self.buf.get_mut(self.len).ok_or(GrubError::TooLong)?;
        *slot = b;
        self.len = self.len.saturating_add(1);
        Ok(())
    }

    fn extend(&mut self, bytes: &[u8]) -> Result<(), GrubError> {
        bytes.iter().try_for_each(|&b| self.push(b))
    }
}

/// Converts GRUB's command line into the grammar's form, dropping the
/// leading `BOOT_IMAGE=` word. Returns the length written to `out`.
///
/// `word` is scratch space for one word; a word longer than it is an error.
pub fn from_grub(line: &[u8], out: &mut [u8], word: &mut [u8]) -> Result<usize, GrubError> {
    let mut o = Out { buf: out, len: 0 };
    let mut i = 0;
    let mut first = true;
    loop {
        while line.get(i) == Some(&b' ') {
            i = i.saturating_add(1);
        }
        if i >= line.len() {
            break;
        }
        // One word: backslash escapes the next byte; double quotes group.
        let mut n = 0usize;
        let mut quoted = false;
        while let Some(&b) = line.get(i) {
            match b {
                b' ' if !quoted => break,
                b'"' => quoted = !quoted,
                b'\\' => {
                    i = i.saturating_add(1);
                    let &next = line.get(i).ok_or(GrubError::Unbalanced)?;
                    *word.get_mut(n).ok_or(GrubError::TooLong)? = next;
                    n = n.saturating_add(1);
                }
                _ => {
                    *word.get_mut(n).ok_or(GrubError::TooLong)? = b;
                    n = n.saturating_add(1);
                }
            }
            i = i.saturating_add(1);
        }
        if quoted {
            return Err(GrubError::Unbalanced);
        }
        let w = word.get(..n).ok_or(GrubError::TooLong)?;
        if first && w.starts_with(b"BOOT_IMAGE=") {
            first = false;
            continue;
        }
        first = false;
        if o.len > 0 {
            o.push(b' ')?;
        }
        let needs_quotes = |v: &[u8]| v.is_empty() || v.iter().any(|&b| b == b' ' || b == b'"');
        match w.iter().position(|&b| b == b'=') {
            Some(eq) if needs_quotes(w.get(eq.saturating_add(1)..).unwrap_or(&[])) => {
                let (key, value) = (
                    w.get(..eq).unwrap_or(&[]),
                    w.get(eq.saturating_add(1)..).unwrap_or(&[]),
                );
                o.extend(key)?;
                o.extend(b"=\"")?;
                for &b in value {
                    if b == b'"' || b == b'\\' {
                        o.push(b'\\')?;
                    }
                    o.push(b)?;
                }
                o.push(b'"')?;
            }
            _ => o.extend(w)?,
        }
    }
    Ok(o.len)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::panic)]
    use super::*;

    fn conv(s: &str) -> Result<std::string::String, GrubError> {
        let mut out = [0u8; 512];
        let mut word = [0u8; 256];
        let n = from_grub(s.as_bytes(), &mut out, &mut word)?;
        Ok(std::string::String::from_utf8(out[..n].to_vec()).unwrap())
    }

    extern crate std;

    #[test]
    fn drops_boot_image_and_keeps_plain_words() {
        assert!(is_grub(b"  BOOT_IMAGE=/aspis/a/aspis.efi a=1"));
        assert!(!is_grub(b"a=1 BOOT_IMAGE=x"));
        assert_eq!(
            conv("BOOT_IMAGE=/aspis/a/aspis.efi console=uart test.panic").unwrap(),
            "console=uart test.panic"
        );
        assert_eq!(conv("BOOT_IMAGE=/x").unwrap(), "");
    }

    #[test]
    fn requotes_values_with_spaces() {
        // GRUB turns `root.name="a b"` in a menu entry into `"root.name=a b"`.
        assert_eq!(
            conv("BOOT_IMAGE=/x \"root.name=a b\" x=1").unwrap(),
            "root.name=\"a b\" x=1"
        );
    }

    #[test]
    fn undoes_grub_escapes() {
        // GRUB escapes \, ' and " in every word.
        assert_eq!(
            conv("BOOT_IMAGE=/x a=b\\\\c d=it\\'s").unwrap(),
            "a=b\\c d=it's"
        );
        assert_eq!(
            conv("BOOT_IMAGE=/x \"q=say \\\"hi\\\"\"").unwrap(),
            "q=\"say \\\"hi\\\"\""
        );
        assert_eq!(conv("BOOT_IMAGE=/x e=").unwrap(), "e=\"\"");
    }

    #[test]
    fn the_result_parses() {
        let out =
            conv("BOOT_IMAGE=/x \"root.name=a b\" a=b\\\\c \"q=say \\\"hi\\\"\" flag").unwrap();
        let args: std::vec::Vec<_> = crate::parse(out.as_bytes()).collect();
        assert!(args.iter().all(|a| a.is_ok()), "{out}");
        assert_eq!(args.len(), 4);
    }

    #[test]
    fn rejects_unbalanced_input() {
        assert_eq!(conv("BOOT_IMAGE=/x \"a=b"), Err(GrubError::Unbalanced));
        assert_eq!(conv("BOOT_IMAGE=/x a=b\\"), Err(GrubError::Unbalanced));
        let mut out = [0u8; 4];
        let mut word = [0u8; 64];
        assert_eq!(
            from_grub(b"BOOT_IMAGE=/x abcdef", &mut out, &mut word),
            Err(GrubError::TooLong)
        );
    }
}
