symbool — design and algorithm
==============================

`symbool` reads a unified diff (typically `git diff` / `git show` / `git
format-patch` output) on standard input and reports three things about
it:

  * **files**       — every pathname the diff touches
  * **functions**   — every function the diff is inside, adds, or removes
  * **identifiers** — every C/Rust identifier that appears on an added or
                      removed line, minus language keywords

It is a heuristic text filter, not a parser.  The target corpus is the
Linux kernel tree (C with a small but growing amount of Rust), and the
heuristics are tuned for kernel coding style first and general C/Rust
second.  On other inputs it will still produce *something*, just with a
higher false-positive / false-negative rate.


1. Program flow
---------------

```
            stdin (bytes)
                 │
                 ▼
      lossy UTF-8 conversion          ── non-UTF-8 bytes become U+FFFD,
                 │                       the run never aborts on encoding
                 ▼
          parse_diff()                ── single linear pass, line by line
                 │
                 ▼
   DiffInfo { files, functions, identifiers }   (three BTreeSets)
                 │
        ┌────────┴────────┐
        ▼                 ▼
   --json ?           plain text
   render_json()      emit() ×N       ── `# section` headers added only
        │                 │              when more than one section is
        ▼                 ▼              selected
              stdout
```

`main()` does four things, in order:

  1. On Unix, restore the default `SIGPIPE` disposition so that
     `git show … | symbool | head` exits 141 silently instead of panicking on
     a broken pipe.
  2. Parse command-line flags with `clap`.  If no selector
     (`-f`/`-F`/`-i`) was given, behave as if `--all` was.
  3. Slurp stdin, convert with `String::from_utf8_lossy`, and hand the
     whole buffer to `parse_diff()`.
  4. Print the requested subsets either as JSON (`-j`) or as plain text.

There is no streaming of output: the entire diff is consumed before
anything is printed, because deduplication and sorting require seeing
every line first.  Memory use is therefore O(input + result-set), which
in practice is fine for any single-commit kernel diff.


2. Command-line interface
-------------------------

| Short | Long            | Effect                                        |
|-------|-----------------|-----------------------------------------------|
| `-f`  | `--files`       | print changed file paths                      |
| `-F`  | `--functions`   | print enclosing / added / removed functions   |
| `-i`  | `--identifiers` | print identifiers on `+`/`-` lines            |
| `-a`  | `--all`         | all of the above (default when none given)    |
| `-j`  | `--json`        | emit a JSON object instead of plain text      |

Plain-text output rules:

  * Exactly one selector → bare list, one entry per line, suitable for
    `xargs`, `grep -f`, etc.
  * Two or more selectors → each section is preceded by `# files`,
    `# functions`, `# identifiers` so a reader can tell them apart.

JSON output is a single pretty-printed object whose keys are the
selected sections and whose values are sorted arrays of strings.  Keys
for unselected sections are omitted entirely (so a consumer can tell
"not asked for" from "asked for and empty").


3. The diff state machine
-------------------------

`parse_diff()` is a single `for line in input.lines()` loop with one bit
of state, `in_hunk`.

```
                 ┌──────────────────────────────┐
                 │   header state               │◄── start
                 │   (in_hunk = false)          │
                 └───────┬───────────────▲──────┘
        line starts "@@" │               │ line starts "diff --git"
                         ▼               │
                 ┌───────────────────────┴──────┐
                 │   hunk state                 │
                 │   (in_hunk = true)           │
                 └──────────────────────────────┘
```

Every line is classified by trying matchers **in this order** and acting
on the first hit:

  1. `^diff --git a/X b/Y`
       → record `X` and `Y` as files (both, to catch renames),
         set `in_hunk = false`.

  2. *(only when `!in_hunk`)* `^--- a/X` or `^+++ b/X`
       → record `X` as a file.
       The regex requires the `a/`, `b/`, `i/`, `w/` prefix, so
       `--- /dev/null` and `+++ /dev/null` fall through harmlessly.
       The `!in_hunk` guard exists because a *body* line whose original
       content begins with `-- ` or `++ ` becomes `--- ` / `+++ ` once
       the diff marker is prepended and would otherwise be mistaken for a
       new file header.

  3. `^@@ … @@ ctx`
       → set `in_hunk = true`; pass `ctx` to `function_from_context()`.

  4. *(only when `in_hunk`)* line starts with `+` or `-`
       → strip the marker, then:
         * pass the body to `function_from_body()`
         * pass the body to `strip_non_code()` and tokenise the result
           for identifiers.

  5. anything else (context lines, `index …`, `similarity index …`,
     `rename from …`, mode lines, `Binary files … differ`, mbox
     headers from `git format-patch`, blank lines)
       → ignored.

After the loop, every collected function name is removed from the
identifier set so that a name does not appear in both lists.


4. File detection
-----------------

A path is recorded from any of:

  * the `a/` and `b/` sides of a `diff --git` line
  * a `--- a/…` or `--- i/…` or `--- w/…` line
  * a `+++ b/…` or `+++ w/…` line

Duplicates collapse in the `BTreeSet`.  For an in-place edit all four
sources agree and one path is reported; for a rename or copy the old and
new paths are both reported.

`--- /dev/null` / `+++ /dev/null` (new and deleted files) carry no
prefix, do not match the regex, and are therefore not recorded — which
is what you want, since the *real* path is on the other header line.

Paths containing whitespace are truncated at the first whitespace
character.  This is a known limitation; the kernel tree has no such
paths.


5. Function detection
---------------------

Functions come from two independent sources and are unioned.

### 5.1 Hunk-header context — `function_from_context()`

Git's `@@ … @@` line ends with the nearest preceding line that matches
its per-language *funcname* pattern.  For kernel C and Rust this is
almost always the signature of the enclosing function, so it tells us
which function a change is *inside* even when the change itself is
something anonymous like `return -EINVAL;`.

The context string is matched against, in order:

  1. `rust_fn` — optional `pub`/`default`/`const`/`async`/`unsafe`/
     `extern "abi"` qualifiers, then `fn NAME`.  Captures `NAME`.

  2. `macro_fn` — `SYSCALL_DEFINEn(NAME, …)` or
     `COMPAT_SYSCALL_DEFINEn(NAME, …)`.  Captures `NAME`.

  3. `call_like` — every `IDENT(` on the line; the **first** one whose
     `IDENT` is neither a language keyword nor a C type/storage keyword
     is taken as the function name.

Rule 3 is the C path.  "First non-keyword `ident(`" is chosen over the
two obvious alternatives because:

  * "last `ident(`" picks the callback parameter in
    `int foo(int (*cb)(void))` → `cb`, wrong;
  * "first `ident(` unconditionally" picks the attribute in
    `__attribute__((cold)) void bar(void)` → `__attribute__`, wrong;
  * "first non-keyword `ident(`" gets `foo` and `bar` respectively.

If the context is a `struct`, `enum`, variable, or `impl` block header,
none of the patterns match and no function is recorded for that hunk —
correctly, since there is no enclosing function.

### 5.2 Added/removed body lines — `function_from_body()`

A `+`/`-` line that is itself a function signature means a function is
being added, removed, or having its prototype changed.  The body
(marker stripped) is matched against, in order:

  1. `rust_fn` — as above.
  2. `macro_fn` — as above.
  3. `c_fn` — but only if **all** of the following hold:

       * the line starts at column 0 (kernel style puts definitions
         there; anything indented is a call site inside another
         function);
       * the first identifier on the line is not a control-flow keyword
         (`if (…)` at column 0 in a macro body would otherwise match);
       * the captured name is not itself a keyword or type keyword.

     `c_fn` is
     `^IDENT [more type-ish chars]  NAME (  …no ';' to EOL…`
     The "no `;` to end of line" tail rejects prototypes, which in
     kernel style end with `;` on the same line as the `(`.

Known false negatives: K&R-style definitions, definitions whose return
type and name are on separate lines and only the name line appears in
the diff, and anything hidden behind a wrapper macro `symbool` does not
know about.  Known false positives: function-like macro invocations at
column zero that span multiple lines (rare in kernel C).


6. Identifier detection
-----------------------

For every `+`/`-` body line:

  1. `strip_non_code()` removes things that look like code but are not:

       * a line that *begins* (after whitespace) with `//`, `/*`, ` * `,
         ` */`, or ` **` is dropped entirely — these are whole-line
         comments or kernel-style block-comment continuation lines.
         A leading `*` immediately followed by an identifier character
         (`*ptr = …`) is kept; that is a pointer dereference, not a
         comment.
       * within the remaining text, `// …` ends the line, `/* … */` is
         replaced by a single space, and the contents of `"…"` and
         `'…'` literals are replaced by a single space.  Backslash
         escapes inside literals are honoured so `"\""` and `'\\'` close
         where they should.
       * `'` followed by an identifier character is treated as a Rust
         lifetime/label (`'a`, `'static`) rather than the start of a
         char literal, because misreading it as a literal would swallow
         everything up to the next apostrophe and lose real identifiers.
         If a closing `'` immediately follows the identifier it was a
         char literal after all (`'x'`); the single leaked letter is
         accepted as harmless noise.

     `strip_non_code()` operates on one line at a time and has no
     cross-line state, so a `/*` that opens on one diff line and closes
     on another is handled by the whole-line ` * ` heuristic above
     rather than by tracking comment depth.  This is deliberate: a diff
     fragment may show the middle of a block comment without ever
     showing the `/*` that opened it.

  2. The surviving text is tokenised with `[A-Za-z_][A-Za-z0-9_]*`.

  3. Each token is kept unless it appears in `is_keyword()`, a combined
     C + Rust keyword list that also blacklists `NULL`, `bool`, `true`,
     `false`.  Using one merged list means a Rust variable called `int`
     would be dropped; that is an acceptable price for never reporting
     `if`/`return`/`let`.

Finally, any identifier that was also recorded as a function name is
removed from the identifier set so it is reported once, under
`# functions`.

Numeric literals, operators and punctuation never match the token regex
and are ignored.  Identifiers on context (` `-prefixed) lines are
ignored because they were not changed by this diff.


7. Output
---------

All three result sets are `BTreeSet<String>`, so output is deduplicated
and sorted lexicographically for free, and is deterministic across runs.

`render_json()` builds a `serde_json::Map` containing only the requested
keys and pretty-prints it.  `serde_json::to_string_pretty` cannot fail
on a value built purely from `String`s, hence the `unwrap()`.

Plain-text `emit()` prints an optional `# label` header followed by one
entry per line.


8. Robustness and security notes
--------------------------------

  * **Input encoding** — stdin is read as raw bytes and converted with
    `from_utf8_lossy`, so a stray Latin-1 byte in a context line cannot
    abort the run.
  * **Regex safety** — the `regex` crate guarantees linear-time matching.
    None of the patterns can exhibit catastrophic backtracking on
    adversarial input.
  * **SIGPIPE** — default disposition is restored so downstream pipe
    closure terminates the process cleanly instead of via a Rust panic.
  * **No external execution** — `symbool` reads stdin and writes stdout.
    It spawns no subprocesses and opens no files, so a hostile diff can at
    worst produce garbage output.


9. Testing
----------

`cargo test` runs an in-crate suite (`src/main.rs`, `mod tests`) of
22 cases covering: C and Rust file/function/identifier extraction,
renames, `/dev/null` headers, hunk-header function-pointer parameters,
`SYSCALL_DEFINEx`, comment and string stripping, Rust lifetimes vs char
literals, pointer dereference vs comment continuation, multibyte UTF-8,
in-hunk `---`/`+++` body lines, and JSON output with and without
selectors.
