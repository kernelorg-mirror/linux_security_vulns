// SPDX-License-Identifier: GPL-2.0
//
// symbool - extract files, functions, and identifiers touched by a unified diff.
//
// Reads `git diff` / `git show` output on stdin and reports what changed.
// Intended for C and Rust source as found in the Linux kernel tree, but the
// heuristics are generic enough for most C-like languages.
//
// Design overview
// ---------------
// The program is a single linear pass over the diff text. It does not build a
// parse tree of either the diff or the underlying source language; instead it
// classifies each line by its position in the unified-diff state machine
// (file header, hunk header, hunk body) and applies a small set of regular
// expressions and lexical heuristics to that line. This keeps memory bounded
// to one line at a time plus three deduplicated result sets, and means the
// tool degrades gracefully on malformed or non-git diffs rather than failing
// outright.
//
// All language detection is heuristic. The goal is "good enough for kernel C
// and kernel Rust" rather than full correctness; see documentation/DESIGN.md
// for the precise rules and their known false-positive/negative trade-offs.

use clap::Parser;
use regex::Regex;
use std::collections::BTreeSet;
use std::io::{self, Read};
use std::sync::OnceLock;

#[derive(Parser, Debug)]
#[command(
    name = "symbool",
    about = "Extract files, functions and identifiers changed by a diff read on stdin"
)]
struct Args {
    /// Show changed file paths
    #[arg(short = 'f', long)]
    files: bool,

    /// Show changed/enclosing function names
    #[arg(short = 'F', long)]
    functions: bool,

    /// Show changed identifiers
    #[arg(short = 'i', long)]
    identifiers: bool,

    /// Show everything (default if no selector is given)
    #[arg(short = 'a', long)]
    all: bool,

    /// Emit output as JSON
    #[arg(short = 'j', long)]
    json: bool,
}

/// The collected result of parsing one diff.
///
/// `BTreeSet` is used for all three so that output is automatically
/// deduplicated and sorted; a single diff can mention the same path or
/// symbol many times across hunks and we only want to report it once.
#[derive(Debug, Default, PartialEq, Eq)]
struct DiffInfo {
    files: BTreeSet<String>,
    functions: BTreeSet<String>,
    identifiers: BTreeSet<String>,
}

fn main() -> io::Result<()> {
    // Rust's runtime installs a SIGPIPE handler that turns a broken pipe
    // into an Err on the next write, which println!() then unwraps into a
    // panic. For a filter that is routinely piped into `head`, `grep -q`,
    // etc., the Unix convention of "die quietly on SIGPIPE" is the right
    // behaviour, so put the default disposition back before doing any I/O.
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }

    let mut args = Args::parse();

    // Selector defaulting: if the caller asked for nothing in particular
    // they almost certainly want everything, so treat the bare invocation
    // as `--all`. `--all` then fans back out into the individual flags so
    // the rest of main() only has to look at one set of booleans.
    if !args.files && !args.functions && !args.identifiers {
        args.all = true;
    }
    if args.all {
        args.files = true;
        args.functions = true;
        args.identifiers = true;
    }

    // Kernel diffs occasionally contain non-UTF-8 bytes (Latin-1 author
    // names in context lines, binary noise in firmware patches). Reading
    // as bytes and converting lossily means those bytes degrade to U+FFFD
    // rather than aborting the whole run with an "invalid utf-8" error.
    let mut raw = Vec::new();
    io::stdin().read_to_end(&mut raw)?;
    let input = String::from_utf8_lossy(&raw);

    let info = parse_diff(&input);

    if args.json {
        println!(
            "{}",
            render_json(&info, args.files, args.functions, args.identifiers)
        );
        return Ok(());
    }

    // Plain-text mode: when only one section is selected the output is a
    // bare list (easy to feed into xargs / grep -f). With two or more, each
    // section gets a `# name` header so the reader can tell them apart.
    let labelled = [args.files, args.functions, args.identifiers]
        .iter()
        .filter(|b| **b)
        .count()
        > 1;

    if args.files {
        emit("files", &info.files, labelled);
    }
    if args.functions {
        emit("functions", &info.functions, labelled);
    }
    if args.identifiers {
        emit("identifiers", &info.identifiers, labelled);
    }

    Ok(())
}

/// Render the selected parts of `info` as a pretty-printed JSON object.
///
/// Only the keys whose selector is `true` appear in the object at all, so a
/// consumer can distinguish "not requested" from "requested but empty".
fn render_json(info: &DiffInfo, files: bool, functions: bool, identifiers: bool) -> String {
    let mut obj = serde_json::Map::new();
    if files {
        obj.insert("files".into(), set_to_json(&info.files));
    }
    if functions {
        obj.insert("functions".into(), set_to_json(&info.functions));
    }
    if identifiers {
        obj.insert("identifiers".into(), set_to_json(&info.identifiers));
    }
    serde_json::to_string_pretty(&serde_json::Value::Object(obj)).unwrap()
}

/// Convert a sorted string set into a JSON array, preserving order.
fn set_to_json(set: &BTreeSet<String>) -> serde_json::Value {
    serde_json::Value::Array(
        set.iter()
            .map(|s| serde_json::Value::String(s.clone()))
            .collect(),
    )
}

/// Print one result section to stdout, one entry per line.
///
/// `labelled` controls whether a `# label` header precedes the list; main()
/// sets it only when more than one section is being emitted.
fn emit(label: &str, set: &BTreeSet<String>, labelled: bool) {
    if labelled {
        println!("# {label}");
    }
    for s in set {
        println!("{s}");
    }
}

/// Lazily compile and cache the regex set on first use.
///
/// Regex compilation is the most expensive part of startup; doing it once
/// and handing out a `&'static` reference keeps `parse_diff()` allocation
/// free in its hot path and lets the test suite share the same compiled
/// patterns across every case.
fn regexes() -> &'static Regexes {
    static R: OnceLock<Regexes> = OnceLock::new();
    R.get_or_init(Regexes::new)
}

/// All regular expressions used by the parser, compiled once.
///
/// The `regex` crate guarantees linear-time matching, so none of these are
/// vulnerable to catastrophic backtracking on hostile input.
struct Regexes {
    diff_git: Regex,
    plus_file: Regex,
    minus_file: Regex,
    hunk: Regex,
    word: Regex,
    rust_fn: Regex,
    c_fn: Regex,
    macro_fn: Regex,
    call_like: Regex,
}

impl Regexes {
    fn new() -> Self {
        Self {
            // `diff --git a/path b/path` — first line of every per-file
            // section in git output. Capturing both sides catches renames.
            diff_git: Regex::new(r"^diff --git a/(\S+) b/(\S+)").unwrap(),

            // `+++ b/path` (or `w/` with some mnemonic-prefix configs).
            // Requiring the prefix is what makes `/dev/null` fall through.
            plus_file: Regex::new(r"^\+\+\+ [bw]/(\S+)").unwrap(),

            // `--- a/path` (or `i/`, `w/`). Same /dev/null reasoning.
            minus_file: Regex::new(r"^--- [aiw]/(\S+)").unwrap(),

            // `@@ -l,c +l,c @@ optional context`. The line/column numbers
            // are not used; only the trailing context string is captured.
            hunk: Regex::new(r"^@@[^@]*@@ ?(.*)$").unwrap(),

            // A C/Rust identifier token.
            word: Regex::new(r"[A-Za-z_][A-Za-z0-9_]*").unwrap(),

            // Rust function definition: every qualifier that can legally
            // precede `fn` is optional and order-fixed, then `fn name`.
            // Anchored at line start (after optional indent) so call sites
            // and trait-object `dyn Fn` types are not picked up.
            rust_fn: Regex::new(
                r#"^\s*(?:pub(?:\s*\([^)]*\))?\s+)?(?:default\s+)?(?:const\s+)?(?:async\s+)?(?:unsafe\s+)?(?:extern\s+(?:"[^"]*"\s+)?)?fn\s+([A-Za-z_][A-Za-z0-9_]*)"#,
            )
            .unwrap(),

            // C function definition: an identifier at column 0 (the return
            // type), an arbitrary run of type-ish characters (more type
            // words, `*`, whitespace), then `name(`. After the `(` there
            // must be no `;` before either end-of-line or an opening `{`;
            // that rejects `type name(args);` prototypes while still
            // accepting one-liner inlines `type name(args) { return x; }`.
            c_fn: Regex::new(
                r"^[A-Za-z_][A-Za-z0-9_]*[\sA-Za-z0-9_\*]*?\b([A-Za-z_][A-Za-z0-9_]*)\s*\([^;{]*(?:$|\{)",
            )
            .unwrap(),

            // Kernel syscall wrappers: SYSCALL_DEFINE3(openat, ...) defines
            // sys_openat. The macro name is uninteresting; the first macro
            // argument is the function name.
            macro_fn: Regex::new(
                r"^(?:COMPAT_)?SYSCALL_DEFINE\d+\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)",
            )
            .unwrap(),

            // Any `ident(` — used to scan hunk-header context strings where
            // we have no column-0 anchor to rely on.
            call_like: Regex::new(r"([A-Za-z_][A-Za-z0-9_]*)\s*\(").unwrap(),
        }
    }
}

/// Walk a unified diff line by line and collect everything of interest.
///
/// This is the core of the program. It implements a tiny two-state machine:
///
/// * **header state** (`in_hunk == false`) — between a `diff --git` line and
///   the first `@@` line. Here `---`/`+++` lines are file headers and body
///   markers have no meaning.
/// * **hunk state** (`in_hunk == true`) — after an `@@` line. Here `+`/`-`
///   prefixed lines are added/removed source and are mined for function
///   definitions and identifiers; ` ` prefixed lines are context and ignored.
///
/// A new `diff --git` line always forces the machine back to header state so
/// that multi-file diffs are handled, and another `@@` line simply re-enters
/// hunk state for the next hunk of the same file.
///
/// No attempt is made to track which file or function a given identifier
/// belongs to; the three result sets are flat and global to the whole diff.
fn parse_diff(input: &str) -> DiffInfo {
    let re = regexes();
    let mut info = DiffInfo::default();
    let mut in_hunk = false;
    // Function named in the most recent `@@ ... @@` trailer, held until we
    // see a `+`/`-` line that actually lands inside it. Git's funcname is
    // "nearest preceding definition", so a hunk that only adds new code
    // *after* that function would otherwise wrongly report it as modified.
    let mut pending_ctx_fn: Option<String> = None;

    for line in input.lines() {
        // `diff --git a/x b/y` — start of a new per-file section. Record
        // both paths (they differ on rename/copy) and drop back to header
        // state so the upcoming ---/+++ lines are parsed as headers, not
        // body content.
        //
        // The state reset must fire even when the path regex does not
        // match (mnemonic prefixes `i/`/`w/`/`c/`/`o/`, --no-prefix,
        // `diff --cc`, plain `diff -u`); otherwise the next file's
        // `--- `/`+++ ` headers are still treated as hunk body and their
        // path components leak into the identifier set. A body line can
        // never begin with `diff ` because hunk bodies always carry a
        // `+`, `-` or ` ` marker in column 0.
        if line.starts_with("diff ") {
            if let Some(c) = re.diff_git.captures(line) {
                info.files.insert(c[1].to_string());
                info.files.insert(c[2].to_string());
            }
            in_hunk = false;
            continue;
        }
        if !in_hunk && (line.starts_with("--- ") || line.starts_with("+++ ")) {
            // git emits "--- /dev/null" / "+++ /dev/null" for added or
            // deleted files; those carry no a/ b/ prefix and the regexes
            // below intentionally do not match them. Inside a hunk, a body
            // line whose content begins with "-- " or "++ " also yields
            // "--- " / "+++ " here, so only treat these as headers between
            // the "diff --git" line and the first @@.
            if let Some(c) = re
                .plus_file
                .captures(line)
                .or_else(|| re.minus_file.captures(line))
            {
                info.files.insert(c[1].to_string());
            }
            continue;
        }
        // `@@ -l,c +l,c @@ ctx` — hunk header. The trailing `ctx` is git's
        // best guess at the enclosing top-level construct (driven by its
        // funcname xfuncname machinery) and is the primary source of
        // function names: it tells us which function a change is *inside*
        // even when the change itself is just a `return -EINVAL;` line.
        if let Some(c) = re.hunk.captures(line) {
            in_hunk = true;
            let ctx = c.get(1).map(|m| m.as_str()).unwrap_or("");
            pending_ctx_fn = function_from_context(ctx);
            continue;
        }
        if !in_hunk {
            // Extended-header noise between `diff --git` and `@@`: index
            // lines, mode changes, `similarity index`, `rename from`, GIT
            // binary patch markers, and so on. None of it is interesting.
            continue;
        }

        // Body lines: only +/- lines describe a change. File headers cannot
        // reach here for git-format diffs (the "diff --git" line resets
        // in_hunk before the next ---/+++ pair), so treat any '+'/'-' as a
        // change line — including content that itself begins with "++"/"--".
        //
        // Context (` `) lines are not themselves changes but they tell us
        // where in the file the change sits: a column-0 `}` closes the
        // pending function before any change touched it, and a new
        // definition appearing as context means subsequent changes belong
        // to *that* function rather than the one git named in the trailer.
        let body = match line.as_bytes().first() {
            Some(b'+') | Some(b'-') => {
                if let Some(name) = pending_ctx_fn.take() {
                    info.functions.insert(name);
                }
                &line[1..]
            }
            Some(b' ') => {
                let ctx_body = &line[1..];
                if ctx_body.starts_with('}') {
                    pending_ctx_fn = None;
                } else if let Some(name) = function_from_body(ctx_body) {
                    pending_ctx_fn = Some(name);
                }
                continue;
            }
            _ => continue,
        };

        // Secondary function source: a definition that is itself being
        // added or removed. This catches functions whose signature line is
        // part of the change rather than merely surrounding it.
        if let Some(name) = function_from_body(body) {
            info.functions.insert(name);
        }

        // Identifier extraction: scrub comments and string/char literals so
        // that prose words and printf format strings do not pollute the
        // result, then take every remaining identifier-shaped token that is
        // not a language keyword.
        let code = strip_non_code(body);

        // On a preprocessor line the first token is the directive itself
        // (`define`, `include`, `ifdef`, `endif`, ...) and `defined` is an
        // operator, not an identifier. These are valid C identifiers in
        // ordinary code, so filter them contextually rather than via the
        // global keyword list.
        let pp = code.trim_start().starts_with('#');
        let mut skip_directive = pp;

        for m in re.word.find_iter(&code) {
            if skip_directive {
                skip_directive = false;
                continue;
            }
            // The word regex starts at a letter, so the alphabetic tail of
            // a numeric literal — `0xDEAD`, `0b1010`, `100UL`, `1.5f`,
            // `42u32` — matches as a freestanding token. A real identifier
            // can never be immediately preceded by a digit, so use that to
            // tell the two apart. m.start() is a byte offset; a multi-byte
            // UTF-8 predecessor's trailing byte is never an ASCII digit.
            if m.start() > 0 && code.as_bytes()[m.start() - 1].is_ascii_digit() {
                continue;
            }
            let w = m.as_str();
            if pp && w == "defined" {
                continue;
            }
            if !is_keyword(w) {
                info.identifiers.insert(w.to_string());
            }
        }
    }

    // Function names are identifiers too, but listing them twice is noise.
    for f in &info.functions {
        info.identifiers.remove(f);
    }

    info
}

/// Extract a function name from a hunk-header context string.
///
/// Git fills this with the nearest preceding top-level construct, so for C
/// it is usually a function signature and for Rust it is `fn foo(...)` or
/// an `impl` block.
fn function_from_context(ctx: &str) -> Option<String> {
    let ctx = ctx.trim();
    if ctx.is_empty() {
        return None;
    }
    let re = regexes();

    if let Some(c) = re.rust_fn.captures(ctx) {
        return Some(c[1].to_string());
    }
    if let Some(c) = re.macro_fn.captures(ctx) {
        return Some(c[1].to_string());
    }

    // C: a context line ending in `;` is a statement (EXPORT_SYMBOL(x);,
    // DEFINE_MUTEX(y);, a prototype, a global initialiser), not a function
    // definition — git just happened to pick it as the nearest column-0
    // line. Reporting the macro name as the "enclosing function" is wrong.
    if ctx.ends_with(';') {
        return None;
    }

    // C: pick the first `ident(` that is not a keyword or storage/type
    // specifier. Taking the last match instead would land on a parameter
    // for signatures like `int foo(int (*cb)(void))`, and taking the first
    // unconditionally would land on `__attribute__` for decorated ones.
    re.call_like
        .captures_iter(ctx)
        .map(|c| c[1].to_string())
        .find(|name| !is_keyword(name) && !is_c_type_kw(name))
}

/// Extract a function name from an added/removed body line.
///
/// Heuristics tuned for kernel C style (definitions start at column 0) and
/// idiomatic Rust (`fn name`).
fn function_from_body(body: &str) -> Option<String> {
    let re = regexes();

    if let Some(c) = re.rust_fn.captures(body) {
        return Some(c[1].to_string());
    }
    if let Some(c) = re.macro_fn.captures(body) {
        return Some(c[1].to_string());
    }

    // C definitions live at column 0; anything indented is a call site.
    if body
        .chars()
        .next()
        .map(|c| c.is_ascii_whitespace())
        .unwrap_or(true)
    {
        return None;
    }

    // Skip obvious non-definitions.
    let first = re.word.find(body)?.as_str();
    if is_c_control_kw(first) || first == "return" {
        return None;
    }

    let c = re.c_fn.captures(body)?;
    let name = c[1].to_string();
    if is_keyword(&name) || is_c_type_kw(&name) {
        return None;
    }
    Some(name)
}

/// Strip comments and string/char literal contents from a single diff body
/// line so that identifier extraction only sees real code.
///
/// Block comments spanning multiple lines can't be tracked reliably across a
/// diff fragment, so kernel-style ` * text` continuation lines are dropped
/// wholesale.
fn strip_non_code(body: &str) -> String {
    let trimmed = body.trim_start();
    if trimmed.starts_with("//") {
        return String::new();
    }
    // Kernel-style block-comment continuation: ` * text`. A leading `*`
    // immediately followed by an identifier char is a pointer dereference, and
    // a leading `*/` may have real code after it on the same line; let both of
    // those fall through to the char scanner, which copes with stray `*/`.
    if let Some(rest) = trimmed.strip_prefix('*') {
        match rest.chars().next() {
            None | Some(' ') | Some('\t') | Some('*') => return String::new(),
            _ => {}
        }
    }

    // Character-by-character scan of the remainder. Iterating `chars()`
    // rather than bytes keeps multi-byte UTF-8 sequences intact; the only
    // bytes that drive state transitions are ASCII so there is no need for
    // a full grapheme iterator.
    let mut out = String::with_capacity(body.len());
    let mut it = body.chars().peekable();

    while let Some(c) = it.next() {
        match c {
            // `//` — line comment, nothing after this is code.
            '/' if it.peek() == Some(&'/') => break,

            // `/* ... */` — inline block comment. Consume through the
            // closing `*/` (or end of line if it is unterminated on this
            // line) and replace the whole span with a single space so that
            // `a/*x*/b` still tokenises as two identifiers.
            '/' if it.peek() == Some(&'*') => {
                it.next();
                while let Some(d) = it.next() {
                    if d == '*' && it.peek() == Some(&'/') {
                        it.next();
                        break;
                    }
                }
                out.push(' ');
            }

            // `'` followed by an identifier character is ambiguous between
            // a Rust lifetime/label (`'a`, `'static`, `'outer:`) and a C
            // char literal (`'x'`).
            '\'' if matches!(it.peek(), Some(d) if d.is_alphabetic() || *d == '_') => {
                // Assume lifetime: copy the identifier through so it is
                // still picked up by the tokenizer, and crucially do *not*
                // enter string-skipping mode — treating `'a` as an open
                // char literal would swallow everything up to the next
                // apostrophe on the line and lose real identifiers.
                out.push(' ');
                while matches!(it.peek(), Some(d) if d.is_alphanumeric() || *d == '_') {
                    out.push(it.next().unwrap());
                }
                // If the very next char is a closing `'` it was actually a
                // char literal after all (`'x'`). Consume the quote; the
                // single letter already emitted is harmless noise that the
                // keyword filter or the user can ignore.
                if it.peek() == Some(&'\'') {
                    it.next();
                }
            }

            // String literal, or a char literal that did not match the
            // lifetime arm above (e.g. `'\n'`, `'"'`). Skip to the matching
            // quote, honouring backslash escapes so that `"\""` and `'\\'`
            // terminate at the right place, and replace with a space.
            '"' | '\'' => {
                let quote = c;
                while let Some(d) = it.next() {
                    if d == '\\' {
                        it.next();
                        continue;
                    }
                    if d == quote {
                        break;
                    }
                }
                out.push(' ');
            }

            // Ordinary code character — copy verbatim.
            _ => out.push(c),
        }
    }

    out
}

/// C control-flow keywords that can appear at column 0 followed by `(` and
/// would otherwise be misread as function definitions by `c_fn`.
fn is_c_control_kw(w: &str) -> bool {
    matches!(
        w,
        "if" | "for" | "while" | "switch" | "do" | "else" | "case" | "goto" | "sizeof"
    )
}

/// C type, storage and qualifier keywords. These can legitimately sit in the
/// "name" slot of the `c_fn` / `call_like` patterns (e.g. `static (*foo)()`,
/// `__attribute__((...))`) and must be skipped over to reach the real name.
fn is_c_type_kw(w: &str) -> bool {
    matches!(
        w,
        "struct" | "union" | "enum" | "void" | "int" | "char" | "long" | "short"
            | "unsigned" | "signed" | "const" | "static" | "inline" | "extern"
            | "volatile" | "register" | "typedef" | "__attribute__"
    )
}

/// Combined C and Rust keyword list used to filter identifier output.
///
/// This is intentionally the union of both languages plus a few ubiquitous
/// pseudo-keywords (`NULL`, `bool`, `true`, `false`): the cost of dropping a
/// Rust variable that happens to be called `int` is far lower than the cost
/// of reporting `if`/`return`/`let` on every diff. The list is a flat slice
/// because at this size a linear `contains` is competitive with a hash set
/// and keeps the table readable.
fn is_keyword(w: &str) -> bool {
    static KW: &[&str] = &[
        // C
        "auto", "break", "case", "char", "const", "continue", "default", "do", "double",
        "else", "enum", "extern", "float", "for", "goto", "if", "inline", "int", "long",
        "register", "restrict", "return", "short", "signed", "sizeof", "static", "struct",
        "switch", "typedef", "union", "unsigned", "void", "volatile", "while", "_Bool",
        "_Static_assert", "_Alignof", "_Alignas", "_Atomic", "_Noreturn", "_Generic",
        "_Thread_local", "true", "false", "NULL", "bool",
        // Rust
        "as", "async", "await", "box", "crate", "dyn", "fn", "impl", "in", "let", "loop",
        "match", "mod", "move", "mut", "pub", "ref", "self", "Self", "super", "trait",
        "type", "unsafe", "use", "where", "yield",
    ];
    KW.contains(&w)
}

#[cfg(test)]
mod tests {
    use super::*;

    const C_DIFF: &str = r#"diff --git a/fs/eventpoll.c b/fs/eventpoll.c
index eeaadb0..a3090b4 100644
--- a/fs/eventpoll.c
+++ b/fs/eventpoll.c
@@ -148,13 +148,6 @@ struct epitem {
 	struct epoll_filefd ffd;

-	/*
-	 * Protected by file->f_lock.
-	 */
-	bool dying;
-
 	struct eppoll_entry *pwqlist;

@@ -918,13 +908,10 @@ static void ep_remove(struct eventpoll *ep, struct epitem *epi)

 	ep_unregister_pollwait(ep, epi);

-	if (unlikely(READ_ONCE(epi->dying)))
-		return;
-
 	file = epi_fget(epi);
@@ -1200,6 +1187,12 @@ void eventpoll_release_file(struct file *file)
 	struct epitem *epi;
+
+static int ep_new_helper(struct eventpoll *ep)
+{
+	return refcount_read(&ep->refcount);
+}
"#;

    const RUST_DIFF: &str = r#"diff --git a/rust/kernel/sync/lock.rs b/rust/kernel/sync/lock.rs
index 1111111..2222222 100644
--- a/rust/kernel/sync/lock.rs
+++ b/rust/kernel/sync/lock.rs
@@ -40,7 +40,7 @@ impl<T: ?Sized, B: Backend> Lock<T, B> {
-    pub fn lock(&self) -> Guard<'_, T, B> {
+    pub fn lock_irqsave(&self) -> Guard<'_, T, B> {
         let state = unsafe { B::lock(self.state.get()) };
         Guard::new(self, state)
     }
@@ -88,6 +88,10 @@ pub unsafe fn access(&self) -> &T {
         unsafe { &*self.data.get() }
     }
+
+    fn helper(x: u32) -> u32 {
+        x + EXTRA_OFFSET
+    }
 }
"#;

    const RENAME_DIFF: &str = r#"diff --git a/old/path.c b/new/path.c
similarity index 95%
rename from old/path.c
rename to new/path.c
--- a/old/path.c
+++ b/new/path.c
@@ -1,3 +1,3 @@ int frob(void)
-	return OLD_CONST;
+	return NEW_CONST;
"#;

    const NEW_FUNCTIONS_DIFF: &str = r#"
diff --git a/drivers/usb/cdns3/cdns3-plat.c b/drivers/usb/cdns3/cdns3-plat.c
index 735df88774e4..3fe3109a3688 100644
--- a/drivers/usb/cdns3/cdns3-plat.c
+++ b/drivers/usb/cdns3/cdns3-plat.c
@@ -44,6 +45,19 @@ static void set_phy_power_off(struct cdns *cdns)
 	phy_power_off(cdns->usb2_phy);
 }
 
+static int cdns3_plat_gadget_init(struct cdns *cdns)
+{
+	if (cdns->version < CDNSP_CONTROLLER_V2)
+		return cdns3_gadget_init(cdns);
+	else
+		return cdnsp_gadget_init(cdns);
+}
+
+static int cdns3_plat_host_init(struct cdns *cdns)
+{
+	return cdns_host_init(cdns);
+}
+
 /**
  * cdns3_plat_probe - probe for cdns3 core device
  * @pdev: Pointer to cdns3 core platform device
"#;

    #[test]
    fn c_files() {
        let i = parse_diff(C_DIFF);
        assert!(i.files.contains("fs/eventpoll.c"));
        assert_eq!(i.files.len(), 1);
    }

    #[test]
    fn c_functions_from_hunk_header() {
        let i = parse_diff(C_DIFF);
        assert!(i.functions.contains("ep_remove"));
        assert!(i.functions.contains("eventpoll_release_file"));
    }

    #[test]
    fn c_functions_from_body() {
        let i = parse_diff(C_DIFF);
        assert!(i.functions.contains("ep_new_helper"));
    }

    #[test]
    fn c_one_liner_inline_is_a_function() {
        let d = "diff --git a/k.h b/k.h\n--- a/k.h\n+++ b/k.h\n@@ -1 +1,3 @@\n\
                 +static inline int foo_one(void) { return 0; }\n\
                 +static inline void foo_two(void) { }\n\
                 +static inline int foo_proto(void);\n";
        let i = parse_diff(d);
        assert!(i.functions.contains("foo_one"));
        assert!(i.functions.contains("foo_two"));
        assert!(!i.functions.contains("foo_proto"));
    }

    #[test]
    fn c_function_with_fnptr_param_in_context() {
        assert_eq!(
            function_from_context("int foo(int (*cb)(void))").as_deref(),
            Some("foo")
        );
        assert_eq!(
            function_from_context("__attribute__((cold)) void bar(void)").as_deref(),
            Some("bar")
        );
    }

    #[test]
    fn c_statement_context_is_not_a_function() {
        assert_eq!(function_from_context("EXPORT_SYMBOL_GPL(some_func);"), None);
        assert_eq!(function_from_context("DEFINE_MUTEX(lock);"), None);
        assert_eq!(function_from_context("static int foo(void);"), None);
        // Rust trait method decl still goes through rust_fn first.
        assert_eq!(function_from_context("fn required(&self);").as_deref(), Some("required"));
    }

    #[test]
    fn c_struct_context_is_not_a_function() {
        let i = parse_diff(C_DIFF);
        assert!(!i.functions.contains("epitem"));
        assert!(!i.functions.contains("struct"));
    }

    #[test]
    fn c_identifiers() {
        let i = parse_diff(C_DIFF);
        assert!(i.identifiers.contains("dying"));
        assert!(i.identifiers.contains("READ_ONCE"));
        assert!(i.identifiers.contains("refcount_read"));
        assert!(i.identifiers.contains("eventpoll"));
        assert!(!i.identifiers.contains("return"));
        assert!(!i.identifiers.contains("if"));
        assert!(!i.identifiers.contains("ep_remove"));
        // words from the removed block comment must not leak through
        assert!(!i.identifiers.contains("Protected"));
    }

    #[test]
    fn preprocessor_directives_are_not_identifiers() {
        let d = "diff --git a/k.c b/k.c\n--- a/k.c\n+++ b/k.c\n@@ -1 +1,6 @@\n\
                 +#define MY_MACRO 1\n\
                 +#include <linux/slab.h>\n\
                 +#ifdef CONFIG_FOO\n\
                 +#endif\n\
                 +#if defined(BAR) || defined(BAZ)\n\
                 +\tobj->defined = true;\n";
        let i = parse_diff(d);
        assert!(i.identifiers.contains("MY_MACRO"));
        assert!(i.identifiers.contains("CONFIG_FOO"));
        assert!(i.identifiers.contains("BAR"));
        assert!(i.identifiers.contains("BAZ"));
        // struct field named `defined` on a non-# line must survive
        assert!(i.identifiers.contains("defined"));
        assert!(i.identifiers.contains("obj"));
        assert!(!i.identifiers.contains("define"));
        assert!(!i.identifiers.contains("include"));
        assert!(!i.identifiers.contains("ifdef"));
        assert!(!i.identifiers.contains("endif"));
    }

    #[test]
    fn numeric_literal_tails_are_not_identifiers() {
        let d = "diff --git a/k.c b/k.c\n--- a/k.c\n+++ b/k.c\n@@ -1 +1,2 @@\n\
                 +\taaa = 0xDEADBEEF + 100UL + 0b1010 + 1.5f;\n\
                 +\tbbb: u32 = 42u32;\n";
        let i = parse_diff(d);
        assert!(i.identifiers.contains("aaa"));
        assert!(i.identifiers.contains("bbb"));
        // the standalone type annotation is a real identifier
        assert!(i.identifiers.contains("u32"));
        assert!(!i.identifiers.contains("xDEADBEEF"));
        assert!(!i.identifiers.contains("UL"));
        assert!(!i.identifiers.contains("b1010"));
        assert!(!i.identifiers.contains("f"));
        // suffix u32 on 42u32 must not add a second entry beyond the
        // standalone one — covered by the set semantics; check that the
        // mechanism also rejects a suffix that appears nowhere else.
        let d2 = "diff --git a/k.c b/k.c\n--- a/k.c\n+++ b/k.c\n@@ -1 +1 @@\n+\tq = 7usize;\n";
        assert!(!parse_diff(d2).identifiers.contains("usize"));
    }

    #[test]
    fn comments_and_strings_are_stripped() {
        let d = "diff --git a/k.c b/k.c\n--- a/k.c\n+++ b/k.c\n@@ -1 +1,3 @@\n\
                 +	foo = bar; /* ignore_me */\n\
                 +	baz(); // also_ignore\n\
                 +	puts(\"string_word\");\n";
        let i = parse_diff(d);
        assert!(i.identifiers.contains("foo"));
        assert!(i.identifiers.contains("bar"));
        assert!(i.identifiers.contains("baz"));
        assert!(i.identifiers.contains("puts"));
        assert!(!i.identifiers.contains("ignore_me"));
        assert!(!i.identifiers.contains("also_ignore"));
        assert!(!i.identifiers.contains("string_word"));
    }

    #[test]
    fn code_after_comment_close_is_kept() {
        let d = "diff --git a/k.c b/k.c\n--- a/k.c\n+++ b/k.c\n@@ -1 +1,3 @@\n\
                 +\t */ tail_one();\n\
                 +\t/**/ tail_two();\n\
                 +\t/* still_dropped\n";
        let i = parse_diff(d);
        assert!(i.identifiers.contains("tail_one"));
        assert!(i.identifiers.contains("tail_two"));
        assert!(!i.identifiers.contains("still_dropped"));
    }

    #[test]
    fn pointer_deref_is_not_a_comment_line() {
        let d = "diff --git a/k.c b/k.c\n--- a/k.c\n+++ b/k.c\n@@ -1 +1,3 @@\n\
                 +\t*ptr = compute();\n\
                 +\t * actual_comment\n\
                 +\t*/\n";
        let i = parse_diff(d);
        assert!(i.identifiers.contains("ptr"));
        assert!(i.identifiers.contains("compute"));
        assert!(!i.identifiers.contains("actual_comment"));
    }

    #[test]
    fn strip_non_code_preserves_multibyte_utf8() {
        assert_eq!(strip_non_code("αβ = γδ;"), "αβ = γδ;");
        assert_eq!(strip_non_code("x /* αβ */ y"), "x   y");
    }

    #[test]
    fn rust_files() {
        let i = parse_diff(RUST_DIFF);
        assert!(i.files.contains("rust/kernel/sync/lock.rs"));
    }

    #[test]
    fn rust_functions() {
        let i = parse_diff(RUST_DIFF);
        assert!(i.functions.contains("lock"));
        assert!(i.functions.contains("lock_irqsave"));
        assert!(i.functions.contains("helper"));
        assert!(i.functions.contains("access"));
    }

    #[test]
    fn rust_identifiers() {
        let i = parse_diff(RUST_DIFF);
        assert!(i.identifiers.contains("Guard"));
        assert!(i.identifiers.contains("EXTRA_OFFSET"));
        assert!(!i.identifiers.contains("fn"));
        assert!(!i.identifiers.contains("pub"));
    }

    #[test]
    fn rust_lifetimes_do_not_swallow_identifiers() {
        let d = "diff --git a/x.rs b/x.rs\n--- a/x.rs\n+++ b/x.rs\n@@ -1 +1 @@\n\
                 +    let r: &'a MyType<'b> = make();\n";
        let i = parse_diff(d);
        assert!(i.identifiers.contains("MyType"));
        assert!(i.identifiers.contains("make"));
        assert!(i.identifiers.contains("a"));
        assert!(i.identifiers.contains("b"));
    }

    #[test]
    fn char_literals_still_stripped() {
        assert_eq!(strip_non_code("x = '\\n';").trim(), "x =  ;");
        assert_eq!(strip_non_code("x = 'y';").trim(), "x =  y;");
        assert!(!strip_non_code("x = '\\n'; // gone").contains("gone"));
    }

    #[test]
    fn rename_tracks_both_paths() {
        let i = parse_diff(RENAME_DIFF);
        assert!(i.files.contains("old/path.c"));
        assert!(i.files.contains("new/path.c"));
        assert!(i.functions.contains("frob"));
        assert!(i.identifiers.contains("OLD_CONST"));
        assert!(i.identifiers.contains("NEW_CONST"));
    }

    #[test]
    fn new_c_function() {
        let i = parse_diff(NEW_FUNCTIONS_DIFF);
        assert!(i.functions.contains("cdns3_plat_gadget_init"));
        assert!(i.functions.contains("cdns3_plat_host_init"));
        assert!(!i.functions.contains("set_phy_power_off"));
    }

    #[test]
    fn syscall_define_macro() {
        let d = "diff --git a/k.c b/k.c\n--- a/k.c\n+++ b/k.c\n\
                 @@ -1,1 +1,1 @@\n+SYSCALL_DEFINE2(openat, int, dfd, const char __user *, filename)\n";
        let i = parse_diff(d);
        assert!(i.functions.contains("openat"));
    }

    #[test]
    fn indented_call_is_not_a_definition() {
        let d = "diff --git a/k.c b/k.c\n--- a/k.c\n+++ b/k.c\n\
                 @@ -1,1 +1,1 @@ void outer(void)\n+\tdo_something(arg1, arg2)\n";
        let i = parse_diff(d);
        assert!(i.functions.contains("outer"));
        assert!(!i.functions.contains("do_something"));
        assert!(i.identifiers.contains("do_something"));
    }

    #[test]
    fn json_output() {
        let i = parse_diff(RENAME_DIFF);
        let s = render_json(&i, true, true, true);
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();

        assert_eq!(
            v["files"],
            serde_json::json!(["new/path.c", "old/path.c"])
        );
        assert_eq!(v["functions"], serde_json::json!(["frob"]));
        assert_eq!(
            v["identifiers"],
            serde_json::json!(["NEW_CONST", "OLD_CONST"])
        );
    }

    #[test]
    fn json_output_respects_selectors() {
        let i = parse_diff(RENAME_DIFF);
        let s = render_json(&i, false, true, false);
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();

        assert!(v.get("files").is_none());
        assert!(v.get("identifiers").is_none());
        assert_eq!(v["functions"], serde_json::json!(["frob"]));
    }

    #[test]
    fn body_line_starting_with_dashes_is_not_a_header() {
        let d = "diff --git a/k.c b/k.c\n--- a/k.c\n+++ b/k.c\n@@ -1,3 +1,2 @@\n\
                 --- separator ---\n\
                 -gone_ident;\n\
                 +++count;\n";
        let i = parse_diff(d);
        assert!(i.identifiers.contains("gone_ident"));
        assert!(i.identifiers.contains("separator"));
        assert!(i.identifiers.contains("count"));
        assert_eq!(i.files.len(), 1);
    }

    #[test]
    fn unusual_diff_prefix_resets_state() {
        // Second file uses diff.mnemonicprefix-style i/ w/ prefixes; the
        // diff --git regex won't capture paths from it but the state machine
        // must still reset so the --- i/ and +++ w/ headers are not parsed as
        // hunk body and leaked as identifiers.
        let d = "diff --git a/a.c b/a.c\n--- a/a.c\n+++ b/a.c\n@@ -1 +1 @@\n+x;\n\
                 diff --git i/b.c w/b.c\nindex 1..2 100644\n--- i/b.c\n+++ w/b.c\n\
                 @@ -1 +1 @@\n+y;\n";
        let i = parse_diff(d);
        assert!(i.files.contains("a.c"));
        assert!(i.files.contains("b.c"));
        assert!(i.identifiers.contains("x"));
        assert!(i.identifiers.contains("y"));
        assert!(!i.identifiers.contains("i"));
        assert!(!i.identifiers.contains("w"));
        assert!(!i.identifiers.contains("c"));
    }

    #[test]
    fn dev_null_is_not_a_file() {
        let d = "diff --git a/gone.c b/gone.c\ndeleted file mode 100644\n\
                 --- a/gone.c\n+++ /dev/null\n@@ -1 +0,0 @@\n-int x;\n";
        let i = parse_diff(d);
        assert_eq!(i.files.len(), 1);
        assert!(i.files.contains("gone.c"));
    }

    #[test]
    fn empty_diff() {
        let i = parse_diff("");
        assert!(i.files.is_empty());
        assert!(i.functions.is_empty());
        assert!(i.identifiers.is_empty());
    }
}
