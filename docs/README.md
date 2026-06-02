# Dilithion Documentation

Technical documentation for Dilithion, a post-quantum cryptocurrency.

This directory holds reference documentation that's maintained as part of the
codebase. Marketing-facing content lives on [dilithion.org](https://dilithion.org).

---

## Start here

| If you want to... | Read |
|-------------------|------|
| Understand what Dilithion is | [../README.md](../README.md) |
| Read the whitepaper | [WHITEPAPER.md](WHITEPAPER.md) · [../Dilithion-Whitepaper-v1.0.pdf](../Dilithion-Whitepaper-v1.0.pdf) |
| See the threat model | [THREAT-MODEL.md](THREAT-MODEL.md) |
| Start mining | [mining/MINING_GUIDE_LINUX.md](mining/MINING_GUIDE_LINUX.md) · [mining/MINING_GUIDE_MACOS.md](mining/MINING_GUIDE_MACOS.md) · [mining/MINING_GUIDE_WINDOWS.md](mining/MINING_GUIDE_WINDOWS.md) · [mining/MINING_GUIDE_DILV.md](mining/MINING_GUIDE_DILV.md) |
| Set up and run a node | [GETTING-STARTED.md](GETTING-STARTED.md) |
| Use the wallet | [HD_WALLET_USER_GUIDE.md](HD_WALLET_USER_GUIDE.md) · [USER-GUIDE.md](USER-GUIDE.md) |
| Report a vulnerability | [../SECURITY.md](../SECURITY.md) |

---

## Top-level reference documents

**Protocol & consensus**
- [ARCHITECTURE.md](ARCHITECTURE.md) — system overview
- [CONSENSUS-RULES.md](CONSENSUS-RULES.md) — consensus rules of record
- [BITCOIN-DIFFICULTY-ENCODING.md](BITCOIN-DIFFICULTY-ENCODING.md) — compact target format
- [DIGITAL-DNA-WHITEPAPER.md](DIGITAL-DNA-WHITEPAPER.md) — 8-dimension node fingerprinting
- [DILITHIUM-MODIFICATIONS.md](DILITHIUM-MODIFICATIONS.md) — our changes on top of the pqcrystals reference impl
- [TX-RELAY-PROTOCOL.md](TX-RELAY-PROTOCOL.md), [TX-VALIDATION-INTEGRATION.md](TX-VALIDATION-INTEGRATION.md) — transaction pathway

**Security**
- [THREAT-MODEL.md](THREAT-MODEL.md) — threat model, reviewed quarterly
- [SECURITY-AUDIT.md](SECURITY-AUDIT.md) — internal audit checklist
- [SECURITY-BEST-PRACTICES.md](SECURITY-BEST-PRACTICES.md) — operator guidance
- [SECURE_REMOTE_WALLET_ACCESS.md](SECURE_REMOTE_WALLET_ACCESS.md) — RPC-over-SSH pattern
- [COVERITY-THIRD-PARTY-ISSUES.md](COVERITY-THIRD-PARTY-ISSUES.md) — static-analysis notes on dependencies

**Wallet**
- [HD-WALLET-SPEC.md](HD-WALLET-SPEC.md) — BIP32/BIP44 derivation as applied
- [HD_WALLET_USER_GUIDE.md](HD_WALLET_USER_GUIDE.md) — user-facing guide
- [HD_WALLET_UI_AND_FEATURES.md](HD_WALLET_UI_AND_FEATURES.md) — UI features + auto-backup
- [HD_WALLET_SECURITY_AUDIT.md](HD_WALLET_SECURITY_AUDIT.md) — wallet security review
- [WALLET-FILE-FORMAT.md](WALLET-FILE-FORMAT.md) — wallet.dat format
- [WALLET-INTEGRATION.md](WALLET-INTEGRATION.md) — how the wallet plugs into the node
- [DEFAULT_WALLET_SETUP_FOR_USERS.md](DEFAULT_WALLET_SETUP_FOR_USERS.md) — first-run defaults

**RPC & API**
- [API-DOCUMENTATION.md](API-DOCUMENTATION.md) — API reference
- [RPC-API.md](RPC-API.md) — JSON-RPC reference
- [RPC-AUTHENTICATION.md](RPC-AUTHENTICATION.md) — cookie + password auth
- [rpc-permissions-architecture.md](rpc-permissions-architecture.md), [rpc-permissions-guide.md](rpc-permissions-guide.md), [rpc-permissions-model.md](rpc-permissions-model.md) — RBAC

**Mining**
- [MINING-GUIDE.md](MINING-GUIDE.md) — general mining guide
- [MINING-INTEGRATION.md](MINING-INTEGRATION.md) — integrating miners with the node
- [EXTERNAL-MINER-VERIFICATION.md](EXTERNAL-MINER-VERIFICATION.md) — verifying third-party miners
- [QUICK_START_MINERS.md](QUICK_START_MINERS.md) — 5-minute start
- [mining/MINING_GUIDE_{DILV,LINUX,MACOS,WINDOWS}.md](mining/) — per-platform mining guides

**Testing & quality**
- [TESTING.md](TESTING.md) — how to run the test suites
- [FUZZING.md](FUZZING.md) — fuzzing overview
- [FUZZING-BUILD-SYSTEM.md](FUZZING-BUILD-SYSTEM.md) — how fuzzer harnesses are built
- [COVERAGE.md](COVERAGE.md) — coverage tooling
- [CODECOV-SETUP.md](CODECOV-SETUP.md) — Codecov integration
- [STATIC-ANALYSIS.md](STATIC-ANALYSIS.md) — Coverity/clang-tidy/cppcheck setup
- [PERFORMANCE-BENCHMARKS.md](PERFORMANCE-BENCHMARKS.md) — benchmark results

**Operations**
- [SETUP.md](SETUP.md) — node setup
- [GETTING-STARTED.md](GETTING-STARTED.md) — set up and run a node (DIL or DilV)
- [MAINTENANCE.md](MAINTENANCE.md) — ongoing maintenance
- [MANUAL-PEER-SETUP.md](MANUAL-PEER-SETUP.md) — manual peering
- [TROUBLESHOOTING-WINDOWS.md](TROUBLESHOOTING-WINDOWS.md) — Windows-specific issues
- [DEVELOPMENT.md](DEVELOPMENT.md) — contributor dev-env setup

**Reference**
- [GLOSSARY.md](GLOSSARY.md) — project terminology

---

## Subdirectories

| Directory | Contents |
|-----------|----------|
| [user/](user/) | User-facing guides, CLI wallet, how-to-transfer |
| [developer/](developer/) | Contributor-focused reference (Bitcoin Core gap analysis, fuzz-testing research) |
| [development/](development/) | Active development notes |
| [mining/](mining/) | Per-platform mining guides |
| [operations/](operations/) | Deployment, infrastructure, seed-node setup |
| [security/](security/) | Security audits, patch sets, disclosures |
| [testing/](testing/) | Test reports, coverage analyses, fuzzing campaigns |
| [specs/](specs/) | Formal specifications (e.g. DFMP v2) |
| [proposals/](proposals/) | Protocol proposals (e.g. VDF lottery) |
| [planning/](planning/) | Historical planning documents |
| [bugs/](bugs/) | Written-up bug investigations |
| [reports/](reports/) | Point-in-time reports and analyses |
| [research/](research/) | Experimental / research notes |
| [analysis/](analysis/) | Chain/network analyses |
| [sessions/](sessions/) | Development session summaries |

Historical notes (pre-April 2026 session reports, `docs/archive/`, and the
`audit/` fix-completion reports) were moved off `main` to keep the primary
branch focused on evergreen documentation. They remain fully available on the
[`docs-archive-snapshot`](https://github.com/dilithion/dilithion/tree/docs-archive-snapshot)
branch.

---

## Conventions

- **Evergreen reference docs** live at the top level of `docs/` and are updated as the code changes.
- **Dated docs** (e.g. containing `YYYY-MM-DD` in the filename) are point-in-time snapshots. They live under `archive/`, `sessions/`, or a category subdirectory; they are not maintained after the fact.
- **Specs** under `specs/` follow semantic versioning and document changes in the file itself.
- **Markdown style:** default to GitHub-flavored markdown. Tables are fine.

---

*This index is maintained by hand — if you add or move a top-level doc, please update this file in the same commit.*
