> Thank you for considering a contribution to **SafeNova**. This document explains how to do it properly so your effort isn't wasted and the review process goes smoothly.

<a id="toc"></a>

## 📚 Table of Contents

-   [🧭 Before you start](#before-you-start)
-   [🐛 Reporting bugs](#reporting-bugs)
-   [💡 Suggesting features](#suggesting-features)
-   [🔀 Submitting a pull request](#submitting-a-pull-request)
    -   [Setting up the environment](#setup)
    -   [Branch naming](#branch-naming)
    -   [Commit messages](#commit-messages)
    -   [Pull request checklist](#pr-checklist)
-   [🎨 Code style](#code-style)
    -   [General rules](#style-general)
    -   [JavaScript specifics](#style-js)
    -   [HTML & CSS](#style-html-css)
-   [🔐 Security contribution rules](#security-rules)
-   [🚫 What we do NOT accept](#not-accepted)

---

<a id="before-you-start"></a>

## 🧭 Before you start

SafeNova is a security-first project. Before touching anything, spend time understanding how it actually works:

-   Read the full [README](./README.md) — especially the [SafeNova Proactive](./README.md#safenova-proactive), [Encryption](./README.md#encryption), and [How containers work](./README.md#how-containers-work) sections
-   Understand the [project structure](./README.md#project-structure) — each file has a specific, narrow responsibility
-   Look at the existing code style before writing a single line

> **The codebase is small and intentional.** There are no dead files, no legacy layers, no placeholder code. If something looks unusual, there is almost always a documented reason for it — read the surrounding comments before assuming it is wrong.

---

<a id="reporting-bugs"></a>

## 🐛 Reporting bugs

Use [GitHub Issues](https://github.com/DosX-dev/SafeNova/issues) to report bugs. Before opening a new issue:

-   Check if the issue already exists
-   Reproduce the bug on the latest version
-   Make sure it happens in a supported browser (Chrome 90+, Firefox 90+, Safari 15+, Edge 90+)

A good bug report includes:

| Field           | What to provide                                                               |
| --------------- | ----------------------------------------------------------------------------- |
| **Description** | What happened vs. what you expected                                           |
| **Steps**       | Exact numbered steps to reproduce                                             |
| **Environment** | Browser name + version, OS, online vs. local                                  |
| **Logs**        | DevTools console output if relevant — paste as text, not a screenshot         |
| **Severity**    | Does it cause data loss? Does it affect security? Does it only affect the UI? |

> **If the bug is security-related** (data exposure, bypass of any protection layer, key material leakage), do **not** file a public issue. See [Security contribution rules](#security-rules) below.

---

<a id="suggesting-features"></a>

## 💡 Suggesting features

Open a [GitHub Issue](https://github.com/DosX-dev/SafeNova/issues) with the `enhancement` label. Describe:

-   **What problem it solves** — not just what it does, but why it matters
-   **Who benefits** — casual user, power user, security-conscious user?
-   **Alternatives you considered** — shows you thought it through
-   **Any security implications** — SafeNova handles encrypted data; new features can introduce new attack surface

Features that don't have a clear security story or that add complexity without proportional value will likely be declined. That's not a rejection of effort — it's a design constraint.

---

<a id="submitting-a-pull-request"></a>

## 🔀 Submitting a pull request

<a id="setup"></a>

### Setting up the environment

There is no build step. The project runs as static files:

```powershell
# Clone the repo
git clone https://github.com/DosX-dev/SafeNova.git
cd SafeNova

# Start the local server
.\.server.ps1
```

The server starts on port `7777` (or the next free port) and opens the app in your browser. Edit files directly in `src/` — no bundler, no transpiler, no `npm install`.

<a id="branch-naming"></a>

### Branch naming

| Prefix      | Use for                                      | Example                          |
| ----------- | -------------------------------------------- | -------------------------------- |
| `fix/`      | Bug fixes                                    | `fix/export-blob-url`            |
| `feature/`  | New functionality                            | `feature/keyboard-shortcut-copy` |
| `refactor/` | Code cleanup with no behavior change         | `refactor/vfs-node-validation`   |
| `docs/`     | Documentation only                           | `docs/contributing-guide`        |
| `security/` | Security improvements (discuss in DMs first) | `security/csp-worker-src`        |

<a id="commit-messages"></a>

### Commit messages

Keep them short and imperative:

```
Fix export producing HTML instead of blob data
Add keyboard shortcut for container lock
Refactor VFS orphan detection to O(n) pass
```

No issue numbers in the subject line — put those in the PR description instead. No `WIP:` commits in the final branch.

<a id="pr-checklist"></a>

### Pull request checklist

Before marking the PR as ready for review:

-   [ ] Tested in at least one supported browser
-   [ ] No `console.log` or debug artifacts left in the code
-   [ ] No new external dependencies introduced
-   [ ] Existing behavior is not broken for cases you didn't touch
-   [ ] If you changed `daemon.js` — read [Security contribution rules](#security-rules) first
-   [ ] PR description explains **what** changed and **why**, not just **how**

---

<a id="code-style"></a>

## 🎨 Code style

<a id="style-general"></a>

### General rules

-   **Match the style of the file you're editing.** Indentation, spacing, quote style, comment language — all of it. Don't mix styles within a file
-   **No unnecessary abstractions.** Don't create a helper for something used once. Don't design for hypothetical future requirements
-   **Comments explain _why_, not _what_.** If the code is obvious, don't comment it. If it isn't obvious, explain the reasoning — not the mechanics
-   **No dead code.** Don't comment out unused blocks and leave them — delete them

<a id="style-js"></a>

### JavaScript specifics

The codebase is vanilla ES2020+ JavaScript — no frameworks, no TypeScript. A few conventions to follow:

-   Use `const` for everything that doesn't need reassignment, `let` otherwise. No `var`
-   Prefer early returns over deep nesting
-   Async functions use `async/await` — no raw `.then()` chains unless combining with `Promise.allSettled` or similar
-   String concatenation uses template literals `` `${x}` `` for readability; the concatenation operator `'' + x` is reserved for places where `String()` calls must be avoided for security reasons (see `daemon.js` for context)
-   `for` loops with index variables for performance-critical paths; `for...of` for readability in non-critical paths
-   Group related declarations on one line when they are semantically linked:
    ```js
    // Good — same logical unit
    let offset = 0,
        count = 0,
        valid = true;
    ```

<a id="style-html-css"></a>

### HTML & CSS

-   HTML attributes stay on one line unless there are more than ~4 and readability suffers
-   CSS follows the existing class naming — BEM is not enforced, but names should be descriptive and scoped to their component
-   No inline styles in HTML except where dynamic values make them unavoidable (e.g. `style="left: ${x}px"`)
-   No `!important` except where intentional override is the documented purpose (e.g. lockdown veil)

---

<a id="security-rules"></a>

## 🔐 Security contribution rules

SafeNova handles **encrypted data and derived cryptographic keys in a live browser environment**. This makes security changes fundamentally different from normal feature work.

**If your change touches any of the following, open a discussion issue or contact the maintainer before writing code:**

-   `daemon.js` — the Proactive anti-tamper runtime guard
-   `crypto.js` — AES-256-GCM + Argon2id layer
-   `state.js` — session key storage and three-source key wrapping
-   `db.js` — IndexedDB abstraction (container and file record layout)
-   The Content Security Policy in `index.html`
-   Any change that relaxes an existing restriction (e.g. whitelisting a new URL scheme, removing a hook)

> **Why the extra step?** Security changes that look correct can introduce subtle regressions. The Proactive guard in particular has carefully documented reasons for every design decision — a change that seems like a simplification may silently remove a specific defense. Discussing first prevents a PR that cannot be merged from wasting your time.

**Responsible disclosure for vulnerabilities:** If you find a security vulnerability (bypass of the Proactive guard, key material leakage, CSP bypass, etc.), please **do not file a public issue**. Contact the maintainer directly through GitHub. You will get credit in the changelog.

---

<a id="not-accepted"></a>

## 🚫 What we do NOT accept

To save everyone's time — PRs in the following categories will be closed without merge:

| Category                           | Reason                                                                                                  |
| ---------------------------------- | ------------------------------------------------------------------------------------------------------- |
| External runtime dependencies      | SafeNova has zero external dependencies by design. Adding `npm` packages is a non-starter               |
| Framework migrations               | React, Vue, Svelte, etc. — no. The codebase is intentionally framework-free                             |
| TypeScript conversion              | Not planned.                                                                                            |
| Weakened security controls         | Any change that removes or relaxes an existing Proactive check, CSP directive, or encryption constraint |
| UI cosmetic overhauls              | Minor tweaks are fine; wholesale redesigns need prior discussion                                        |
| Localization / i18n infrastructure | Out of scope for the current version                                                                    |

---

If you're unsure whether your idea fits — just open an issue and ask. It's faster than writing code that doesn't land.
