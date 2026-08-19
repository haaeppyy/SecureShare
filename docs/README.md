# SecureShare — System Design & Project Understanding

A complete, code-verified explanation of how the SecureShare project works,
written for a developer who knows how to program but has never seen this
codebase.

## What this documentation is

This is not an API reference. It is a guided walkthrough: what the
application does, how it starts, how information moves through it, what
every major piece is for, and where each behavior lives in the code. Every
statement is derived from the actual source. Claims that could not be fully
verified from the repository are explicitly marked.

**Accuracy markers used throughout:**

| Marker | Meaning |
|---|---|
| *Confirmed from code* | Directly readable in the source (default for most statements) |
| *Likely but not fully confirmed* | Strongly implied by the code, but depends on runtime/OS behavior not observable in this repo |
| *Not determinable from the repository* | Genuinely unknown without running on real hardware / two real machines |

## Reading order

Read the files in order. Each builds on the previous one.

| # | File | What it teaches |
|---|---|---|
| 0 | `README.md` (this file) | How to navigate the documentation |
| 1 | `01-overview.md` | What the project is, who uses it, the "60-second" summary |
| 2 | `02-architecture.md` | The big picture: components and how they talk to each other |
| 3 | `03-startup-and-lifecycle.md` | What happens from launch to shutdown |
| 4 | `04-data-flow.md` | Data-flow diagrams: where information enters, moves, and lands |
| 5 | `05-user-workflows.md` | Every major thing a user can do, step by step |
| 6 | `06-sequence-diagrams.md` | Time-ordered interaction diagrams for the key flows |
| 7 | `07-storage-and-trust.md` | What is stored on disk, when, and why |
| 8 | `08-authentication-and-security.md` | Pairing, trust, encryption, and access control |
| 9 | `09-external-dependencies.md` | Every outside service/facility the app relies on |
| 10 | `10-kvm-deep-dive.md` | The keyboard & mouse sharing engine in full detail |
| 11 | `11-business-logic.md` | The important calculations and decisions |
| 12 | `12-key-functions-by-purpose.md` | What the important parts of the code actually do |
| 13 | `13-deployment-and-build.md` | How the app is run, packaged, and shipped |
| 14 | `14-project-structure.md` | Why each file exists, grouped by responsibility |
| 15 | `15-end-to-end-example.md` | One complete action traced through every layer |
| 16 | `16-mental-model.md` | The simplest way to remember how it all works |
| — | `glossary.md` | Plain-English terms used in the project |

## How this documentation was produced

Every claim was checked against the source in `core/`, `tray/`, `tests/`,
`scripts/`, `native/`, and the PyInstaller specs. File/line references point
at the code that implements the described behavior. The behavioral contract
is additionally pinned by the pytest suite (`tests/`, ~104 tests across
`unit` and `socket` groups).