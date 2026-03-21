![](./pics/intro.png)

> ### Try it online: [https://safenova.dosx.su/](https://safenova.dosx.su/)

## ❔ What it is

SafeNova is a single-page web app that lets you create encrypted **containers** — isolated vaults where you can organize files in a folder structure, much like a regular desktop file manager. Everything is encrypted client-side before being written to storage. Nothing ever leaves your device.

![](./pics/screenshot.png)

Key properties:

-   **Zero-knowledge** — the app never sees your password or plaintext data
-   **Offline-first** — works entirely without network access
-   **No installation** — start the local server and you're running (or use online)

---

## ⚙️ Features

-   **Multiple containers** — each with its own password and independent storage limit (8 GB per container)
-   **Virtual filesystem** — nested folders, drag-to-reorder icons, customizable folder colors
-   **File operations** — upload (drag & drop or browse; folder upload with 4× parallel encryption), download, copy, cut, paste, rename, delete
-   **Built-in viewers** — text editor, image viewer, audio/video player, PDF viewer
-   **Hardware key support** — optionally use a WebAuthn passkey to strengthen the container salt
-   **Session memory** — optionally remember your session per tab or per browser
-   **Container import / export** — portable `.safenova` container files
-   **Export password guard** — configurable setting (on by default) to require password confirmation before exporting; when disabled, active-session key is used directly
-   **Sort & arrange** — sort icons by name, date, size, or type; drag to custom positions
-   **Container integrity scanner** — 27 automated checks (21 VFS structural + 6 database-level) with one-click auto-repair, **Deep Clean** (flattens over-nested folder trees, repairs all metadata), and a backup prompt before any destructive operation
-   **Settings** — three tabs: personalization, statistics, activity logs
-   **Keyboard shortcuts** — `Delete`, `F2`, `Ctrl+A`, `Ctrl+C/X/V`, `Ctrl+S` (save in editor), `Escape`
-   **Mobile-friendly** — touch drag, rubber-band selection, single/double-tap gestures

---

## 🔐 Encryption

| Layer           | Algorithm                                       |
| --------------- | ----------------------------------------------- |
| Key derivation  | Argon2id (19 MB memory, 2 iterations, 1 thread) |
| File encryption | AES-256-GCM (random 12-byte IV per file)        |
| VFS encryption  | AES-256-GCM (same key as files)                 |
| Integrity check | AES-256-GCM verification blob on unlock         |

Every file is encrypted individually. The virtual filesystem structure is also encrypted as a separate blob. The plaintext password is never stored — only the derived key is held in memory during an active session.

---

## 📋 Requirements

-   A modern browser: **Chrome 90+**, **Firefox 90+**, **Safari 15+**, or **Edge 90+**
-   Web Crypto API must be available — this requires either **HTTPS** or **`localhost`**
-   No plugins, no extensions, no backend

---

## 🚀 Getting started

### Option A — Use online version

SafeNova is hosted on: [https://safenova.dosx.su/](https://safenova.dosx.su/)

### Option B — Local server

A zero-dependency PowerShell server is included:

```powershell
.\\.server.ps1
```

Or right-click the file → **Run with PowerShell**. It starts an HTTP server on port `7777` (or the next free port) and opens the app in your default browser.

No external installs needed — it uses the Windows built-in `HttpListener`.

---

## 📁 Project structure

```
SafeNova/
│
├── index.html          # Single-page app entry point
├── favicon.png         # Application icon
├── .server.ps1         # Local PowerShell dev server (Windows)
│
├── css/
│   └── app.css         # All application styles
│
└── js/
    ├── argon2.umd.min.js # Argon2id WASM/JS implementation
    ├── constants.js    # Shared constants, utilities, icon SVGs
    ├── state.js        # App state singleton (key, container, session)
    ├── crypto.js       # AES-256-GCM + Argon2id encryption layer
    ├── db.js           # IndexedDB abstraction (containers / files / vfs)
    ├── vfs.js          # In-memory virtual filesystem
    ├── fileops.js      # Upload, download, copy/paste, rename, delete
    ├── home.js         # Container management (create, unlock, import, export)
    ├── main.js         # Event binding and app boot
    └── desktop.js      # Desktop UI — icons, folder windows, drag & drop
```

---

## 🔒 How containers work

1. **Create** a container with a name and password
2. **Unlock** the container — Argon2id derives the key from your password
3. Files you upload are encrypted with AES-256-GCM before being saved to IndexedDB
4. The virtual filesystem (folder tree + icon positions) is also encrypted and saved separately
5. **Lock** the container — the key is wiped from memory

All container data is scoped to the current browser and device. Use **Export Container** to back up or transfer to another device.

---

## 🛡️ Container Integrity Scanner

The built-in scanner performs a deep analysis of the virtual disk image, encrypted file table, folder hierarchy, desktop layout, and workspace environment. It runs **27 checks** in two phases:

### Phase 1 — VFS structural checks (21 steps, synchronous)

| #   | Check                        | Repairs                                                                        |
| --- | ---------------------------- | ------------------------------------------------------------------------------ |
| 1   | Root node integrity          | Recreates missing root; fixes type and parentId                                |
| 2   | Node field validation        | Fixes IDs, names, types; restores missing/invalid ctime and mtime to today     |
| 3   | Node ID format validation    | Reassigns malformed IDs; migrates position data                                |
| 4   | Timestamp anomaly detection  | Detects mass-identical ctimes; spreads them across a 1-second window on repair |
| 5   | File name validation         | Sanitizes invalid characters, truncates long names                             |
| 6   | Orphaned node detection      | Reattaches to root                                                             |
| 7   | Parent type validation       | Reattaches nodes whose parent is a file                                        |
| 8   | Parent-child cycle detection | Breaks cycles by reattaching to root                                           |
| 9   | Node reachability analysis   | O(n) memoized; reattaches unreachable nodes                                    |
| 10  | Timestamp integrity          | Fixes invalid/future timestamps                                                |
| 11  | File size validation         | Resets negative/invalid sizes                                                  |
| 12  | File metadata validation     | Strips unknown properties                                                      |
| 13  | Duplicate name detection     | Auto-renames collisions                                                        |
| 14  | Empty folder chain detection | O(n) iterative post-order DFS; informational                                   |
| 15  | Position table cleanup       | Removes stale entries                                                          |
| 16  | Folder position maps         | Creates missing position maps                                                  |
| 17  | Position entry completeness  | Only checks visited (opened) folders; auto-positions on repair                 |
| 18  | Position collision detection | Relocates overlapping icons                                                    |
| 19  | Grid alignment verification  | Snaps off-grid positions                                                       |
| 20  | Folder depth analysis        | O(n) memoized; warns when nesting > 50 levels                                  |
| 21  | Node count summary           | Informational — file/folder/position counts                                    |

### Phase 2 — Database-level checks (6 steps, async)

| #   | Check                      | Repairs                                                                                                             |
| --- | -------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| 1   | File data existence        | Removes VFS nodes whose encrypted blob is missing from IndexedDB                                                    |
| 2   | Encryption IV integrity    | Accepts Array/Uint8Array/ArrayBuffer (canonical: plain Array); coerces base64 strings; purges only if truly invalid |
| 3   | File blob integrity        | Resets declared size to 0 if blob is empty                                                                          |
| 4   | Orphaned storage records   | Deletes DB records not referenced by any VFS node                                                                   |
| 5   | Record container binding   | Fixes records bound to wrong container ID                                                                           |
| 6   | Container size consistency | Recalculates totalSize from live VFS nodes                                                                          |

Before auto-repair runs, a **confirmation dialog** recommends exporting the container as a `.safenova` backup — you can do this without leaving the scanner. After a successful repair, a verification scan runs automatically to confirm all issues are resolved.

If auto-repair cannot fix the remaining issues, a **Deep Clean** option becomes available. It performs an aggressive structural rebuild in five O(n) passes:

1. Scan DB storage records
2. Purge dead nodes — remove every VFS node with no real encrypted data behind it
3. Flatten deep folder chains — files nested more than 50 levels deep are reparented to their closest ≤50-level ancestor; all file data is preserved
4. Repair metadata — each node with a missing or invalid `ctime`/`mtime` gets today's date
5. Clean storage records — remove orphaned DB entries in a single batch transaction

After Deep Clean, a verification scan runs automatically. A backup is offered before Deep Clean runs, same as for auto-repair.
