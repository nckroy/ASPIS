<!-- SPDX-FileCopyrightText: 2026 Nicole Roy -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Fuzz targets

This is ASPIS's fuzzing gate ([0068](../docs/decisions/0068-the-fuzzing-and-differential-testing-gate.md)). The mechanism is in [call-language.md, "The fuzzing gate"](../docs/design/call-language.md#the-fuzzing-gate), and the harness's own in ["The harness"](../docs/design/call-language.md#the-harness). This file is the runbook.

`fuzz/` is a separate Cargo workspace with its own `Cargo.lock`, so fuzz dependencies never enter the product lock file, the images or the SBOM (rule 3).

## Layout

- `fuzz_targets/<target>.rs`: one file per target. Each declares the target's memory bound and calls its entry function.
- `gate/` (crate `fuzz-gate`): the entry functions and their oracles, the target table (`fuzz_gate::TARGETS`), the generated seeds, and the harness that `cargo xtask fuzz` runs. It holds `crypto-differential`'s oracle, libcrux (`gate/src/crypto_oracle.rs`), and embeds `crates/crypto/tests/data`'s vectors, from which the `crypto-` targets' seeds are made (`gate/src/crypto_repo.rs`).
- `alloc/` (crate `fuzz-alloc`): the memory bound, a counting global allocator. Without a sanitizer, libFuzzer's `-malloc_limit_mb` does nothing.
- `seeds/<target>/`: small hand-made seeds, committed. Every vector line is a seed as well. Those are generated from the embedded vector files, so they can't drift.
- `regressions/<target>/`: minimized findings, committed.
- `differential/`: minimized disagreements between the two ABNF checkers, with RFC-correct tags, committed. It exists once a finding needs it.
- `deny.toml`: cargo-deny's license and source checks for this workspace. It lists the targets the workspace builds for, so crates behind libcrux's custom cfgs, which are never built, aren't counted, and has one license exception besides the engine's: `unicode-ident`'s Unicode-3.0, in the build-time proc-macro stacks.

Names under `seeds/` and `regressions/` are lowercase letters, digits, hyphens and dots, with no spaces. The tools list them with `git ls-files`, so iCloud's conflict copies are never read.

## Commands

Run fuzzing through `cargo xtask fuzz`. Never use `cargo fuzz run`, `tmin` or `coverage`: they write under `fuzz/`, which iCloud syncs in the working copy. Everything that grows lives under `build/fuzz/`.

| Command | What it does |
|---|---|
| `cargo xtask fuzz list [--shard i/n] [--names]` | The targets, with their chunks, records, limits, paths and extra paths; `--shard` gives a nightly shard's |
| `cargo xtask fuzz install` | Installs the pinned cargo-fuzz and cargo-deny (`[workspace.metadata.aspis]` in `Cargo.toml`) |
| `cargo xtask fuzz build` | Checks the tools, the product lock and the fuzz lock; builds every target with `-s none`; checks the oracle; writes the seeds and regressions to `build/fuzz/` |
| `cargo xtask fuzz replay [<target> [<file>…]] [--repeat <n>]` | Runs every seed, regression and corpus input once (`-runs=0`), or the given files |
| `cargo xtask fuzz measure [<target>] [--corpus]` | Each target's slowest seeds (and corpus inputs) and peak memory, in-process |
| `cargo xtask fuzz kinds [<target>] [--each]` | The error kinds the seeds reach, against the table's |
| `cargo xtask fuzz run <target> [--time s] [--jobs n] [--seed s]` | Fuzzes one target for `--time` seconds (60 by default) after libFuzzer has loaded its corpus, with its dictionary, and records the run in `build/fuzz/runs/<target>.tsv`. The harness stops libFuzzer with SIGINT when the time is up. `--jobs` above 1 is libFuzzer's fork mode. It fails on any finding. |
| `cargo xtask fuzz smoke --base <rev> [--budget s] [--seed s]` | Fuzzes each target the change since the merge base with `<rev>` selects, 60 s each and 600 s in all, each after its corpus load, as CI does per change. A target that got under half its time box fails it |
| `cargo xtask fuzz tmin <target> <input>` | Minimizes a crashing input for a minute, to `build/fuzz/artifacts/<target>/minimized-<name>` |
| `cargo xtask fuzz differential [--seed S] [--cases N] [--jobs n] [--timeout s] [--budget s]` | The two ABNF checkers on generated grammars (rule 6). Set `ASPIS_PYTHON` to a Python with `abnf==2.9.1`. `--budget` stops starting batches after that many seconds. `--self-test` shows it detects a flipped tag and a Python that runs out of time |
| `cargo xtask fuzz report [<target>…]` | Each target's runs of the binary built now (its build is the SHA-256 of the binary): measured CPU-hours, CPU-hours since the last finding, executions, coverage, and the error kinds reached. Runs of other builds are counted apart, and don't count |
| `cargo xtask fuzz coverage [<target>…]` | Builds the targets with coverage instrumentation, replays their seeds, regressions and corpus, and reports lines, regions and functions of each target's crates, and of each crate over all its targets |
| `cargo xtask fuzz nightly [--time s] [--budget s] [--jobs n] [--seed s] [--shard i/n]` | What the nightly job runs: `build`, `replay`, then each target for `--time` (600 s), or its share of `--budget`, with its corpus merged after, then `coverage` and `report`. It keeps going after a finding and fails at the end. CI runs it in two shards, `--shard 1/2` and `--shard 2/2`, as a matrix |

`cargo xtask test` also replays every target's seeds and regressions through the same entry functions under plain `cargo test`, without libFuzzer (rule 7).

Building the targets needs a C++ compiler, for libFuzzer. The fuzz build always has debug assertions and overflow checks: never pass `-O`. `fuzz build` sets its own `RUSTFLAGS`, ignoring yours, so RustCrypto's and dalek's crates run the backends `aarch64-unknown-none` ships, not your CPU's. One exception: on an x86_64 host, ChaCha20 still detects the CPU and runs its AVX2 or SSE2 code, so only an aarch64 host, as CI's are, fuzzes the ChaCha20 that ships. Run cargo over this workspace from the repository: its `.cargo/config.toml` keeps libcrux to its portable code, and `fuzz-gate` refuses to build without that.

## Under build/fuzz/

| Path | What |
|---|---|
| `target/` | The fuzz build (`cargo fuzz build`) |
| `target-coverage/` | The coverage build |
| `target-host/` | The harness, its tests, and clippy |
| `seeds/<target>/`, `regressions/<target>/` | What libFuzzer reads: the committed files and the generated seeds |
| `corpus/<target>/` | The growing corpus; in CI, the nightly's Actions cache, one per nightly shard. The per-change job restores both; each nightly shard restores both and keeps only its own targets'. `nightly` merges it through `corpus.new/<target>/` |
| `artifacts/<target>/` | Findings: crash, timeout and out-of-memory inputs |
| `dict/targets/<target>.dict` | The target's libFuzzer dictionary. C07's per-grammar dictionaries (`cargo xtask fuzz-dict`) go beside it, in `dict/`. |
| `logs/<target>-<seed>.log` | The last run's whole libFuzzer log |
| `runs/<target>.tsv` | One line a run: the target binary's build, the commit, the seed, seconds of fuzzing after the load, measured and asked CPU seconds, executions, coverage and findings. In fork mode the figures are the parent's, over the jobs it has merged, never the one job's log it prints on a finding (and, on macOS, usually at a stop). The jobs still running at the end, up to one a worker and each at most 300 s, aren't merged, so their executions and coverage are missing from the record, though `/usr/bin/time` counts their CPU time. Under `run`'s flags a fork-mode record's crash, timeout and OOM counts stay 0, even on a finding. Fork-mode records made before C71's fork-mode fix (an earlier commit, or a dirty tree without it) undercount executions, coverage, features and corpus if their run's log held such an inner log; their CPU-hours and recorded findings stand. On macOS a fork-mode run exits 0 on a finding as on a stop, so in fork mode an inner log is recorded unclean, whatever the exit status, unless it begins after the harness's SIGINT and is a stopped job's: it has the job's `run interrupted` line and no `ERROR: libFuzzer` or `SUMMARY: libFuzzer` line. Two findings still rest on a new artifact: one whose job ended just before the stop, when the SIGINT stops the parent before it prints that job's log (exit 72, no inner log), and one whose job was still in its crash handler at the stop, when a job the stop interrupted exits first and the parent prints that job's log instead. The parent ignores SIGINT while any job or merge subprocess runs and stops itself only when none runs; a SIGINT that lands while only a merge subprocess runs stops just the merge, and the run goes on to the `-max_total_time` backstop, recorded clean but past its time box ([Run records](../docs/design/call-language.md#the-harness)) |
| `differential/<seed>/` | The differential's cases and the Python checker's directories |
| `coverage/summary.md`, `coverage/<target>/` | The coverage table, and each target's `report.txt`, `summary.json` and `html/`; `coverage/crates/<crate>/` for each crate over its targets |
| `probe/` | The oracle probe's inputs and crashes |

## Passing the gate

A parser's chunk passes the gate for each of its targets ([0068](../docs/decisions/0068-the-fuzzing-and-differential-testing-gate.md), rule 5), and its pull request records the evidence:

1. Add the target: a row in `gate/src/lib.rs`'s `TARGETS`, an entry function and its `kinds_of` in `gate/`, a file in `fuzz_targets/`, a `[[bin]]` in `Cargo.toml`, and committed seeds for the error kinds the vector lines don't reach. `cargo xtask fuzz kinds <target>` shows what is missing. The row's `paths` select it per change and count in its coverage; for a target that a crate or file other than its own selects, such as the reference matcher, a crate generated into `OUT_DIR` or an ASPIS crate the entry calls, list that in `extra_paths`.
2. `cargo xtask fuzz build` and `cargo xtask fuzz measure <target>`. Set the timeout and the memory bound so the slowest seed takes under a quarter of the timeout, and record any override, with its reason, in the table and in "The harness". `measure` runs the seeds in the test build (opt-level 1), which can be about twice as fast as the fuzz binary, as it is on `idl-front-end`: time the slowest seed in the fuzz binary too, with `cargo xtask fuzz replay <target> <file>`.
3. Fuzz until `cargo xtask fuzz report <target>` shows at least 1 measured CPU-hour since the last finding, on the binary built from the code under review: a change to the target's code makes a new build, whose count starts from zero, so fuzz last. For example, `cargo xtask fuzz run <target> --time 2400 --jobs 2`. Slow targets do better as two in-process runs with different `--seed`s on the shared corpus. Leave cores free for other work on the machine.
4. `cargo xtask fuzz coverage <target>`. Put the report's table, and `report`'s, in the pull request, and review the lines the corpus never reaches. The HTML stays under `build/fuzz/coverage/`.

C71's first campaigns are recorded in [call-language L36](../docs/design/call-language.md#l36-coverage-thresholds).

## Triage and disclosure

1. **Get the input.** A failing CI job uploads `build/fuzz/artifacts/`, the logs and the differential's cases, kept for 7 days; the job log itself, with the backtrace, stays for the repository's 90 days. Each run prints its `-seed`.
2. **Reproduce it:** `cargo xtask fuzz replay <target> <file> --repeat 10`. A finding that doesn't reproduce in 10 runs is itself a bug, since parsers are deterministic. `cargo xtask fuzz run <target> --time <s> --seed <n>` repeats a run.
3. **Minimize it:** `cargo xtask fuzz tmin <target> <file>`, which writes `build/fuzz/artifacts/<target>/minimized-<name>`.
4. **Fix it in the parser.** Fix the oracle in `gate/` only if the oracle is wrong, and then add a case to `gate/tests/oracles.rs` that hands the check a broken subject.
5. **Commit the minimized input** as `regressions/<target>/<what-it-was>`, and, where it helps, a named unit test in the crate. Regressions replay on every change, under `cargo xtask test` and in CI. A regression that holds octets of a licensed vector, as the `crypto-` targets' inputs may (their seeds come from RFC and ACVP files), needs its own `[[annotations]]` in `REUSE.toml`, with `precedence = "override"` and the source's notice and license, as `crates/crypto/tests/data/` has.
6. **Fuzz the target for another CPU-hour** before the gate counts again: `report` counts only the CPU time since the last finding.

A disagreement in the ABNF differential is triaged the same way. A Rust bug is fixed in `crates/abnf`, and the minimized case goes in `differential/` with RFC-correct tags. A divergence of the Python library from RFC 5234 is recorded in "The harness", and the generator steers around the construct. Neither is waved through. A Python-limit event, where the Python checker gives no answer in time, isn't a disagreement: under 1 % of a run's cases they are logged with their cases, and above it the run fails and the generator is steered.

**Until ASPIS's first release**, fuzzing runs in public CI, and findings are fixed in the open (rule 13). **From the first release**, a finding goes into a private security advisory ([SECURITY.md](../SECURITY.md)), and long campaigns run on a private fork or runner. A `--redact` mode, to be built before then, will make the public logs name only the target and its crash count, and encrypt the input and backtrace with `age` to the triagers' keys, kept for 1 day ([Triage and disclosure](../docs/design/call-language.md#triage-and-disclosure)).
