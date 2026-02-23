# PATENT-PRIORITY.md

## Priority Date Documentation — SIGIL Protocol

> This file constitutes official public disclosure of the priority date claim
> for the SIGIL Protocol utility model patent application.

---

## Patent Status

**Status:** Patent Pending  
**Type:** German Utility Model (Gebrauchsmuster gemäß § 4 GebrMG)  
**Filed with:** Deutsches Patent- und Markenamt (DPMA), München  
**Priority Date:** **2026-02-23**  
**Applicant / Inventor:** Benjamin Küttner, Garmischerstrasse 46 B, 86163 Augsburg, Deutschland  
**Contact:** <benjamin.kuettner@icloud.com> · <ben@sigil-protocol.org>

---

## Invention Title

**German:**  
Modulares Sicherheitsprotokoll für die Identitätsbindung, regelbasierte Inhaltsredaktion und manipulationssichere Protokollierung in vernetzten Systemen  
*(SIGIL — Sovereign Identity-Gated Interaction Layer)*

**English:**  
Modular Security Protocol for Identity Binding, Rule-Based Content Redaction and Tamper-Evident Audit Logging in Networked Systems

---

## Core Claims Summary

The patent application covers the following inventive contributions:

1. **Modular Security Envelope** — A composable, transport-neutral security protocol with five independently replaceable interfaces: identity provider, sensitivity scanner, vault provider, audit logger, and security policy.

2. **eIDAS-Compatible Trust Levels** — Discrete, ordinal trust levels (Low / Medium / High) mapped to the eIDAS Regulation (EU) No 910/2014 assurance levels, used as first-class parameters in agent policy enforcement.

3. **Pure-Function Scanner Interface** — A synchronous, side-effect-free content scanner defined as a type-level constraint (`fn(&str) -> Option<Match>`) that structurally prevents network I/O and state mutation, making exfiltration prevention a design-level guarantee rather than a policy-level restriction.

4. **HMAC-SHA256 Audit Chain** — Every security decision is recorded as a structured, HMAC-signed entry; post-hoc modification of any field invalidates the chain.

5. **Browser Extension / Signet** — A browser extension that intercepts SSE streams via `ReadableStream.tee()` in the MAIN JavaScript world, signs interaction receipts using an Ed25519 key isolated in a WASM sandbox, and verifies receipts against registry-registered keys.

---

## Evidence of Development (Priority Chain)

The following public, timestamped artefacts document the development predating the priority date:

| Date | Evidence | Verifiable |
|---|---|---|
| Pre-2026-02-23 | GitHub commit history — sigil-rs, sigil-ts, sigil-inspector | Public: github.com/sigil-eu/sigil |
| Pre-2026-02-23 | Domain registration: sigil-protocol.org | WHOIS public record |
| Pre-2026-02-23 | registry.sigil-protocol.org live (VPS Frankfurt) | DNS + server logs |
| Pre-2026-02-23 | sigil-protocol npm package published | npmjs.com |
| Pre-2026-02-23 | crates.io: sigil-protocol v0.1.x | crates.io public |
| 2026-02-23 | Einschreiben mit Rückschein — DPMA München | Postal tracking receipt |

---

## EPO / PCT Deadline

Under the Paris Convention (Art. 4), a priority-claiming EPO or PCT application must be filed within **12 months** of the priority date:

> **Deadline: 2026-02-23** — *this date is informational; the actual PCT/EPO deadline is 2027-02-23.*

---

## Notice to Third Parties

Any product, service, or open-source implementation that incorporates the patented inventions listed above may be subject to licensing requirements after patent registration. For licensing enquiries, contact:

**<benjamin.kuettner@icloud.com>** · **<ben@sigil-protocol.org>**

SIGIL Protocol source code remains available under the **EUPL-1.2** open-source licence. The patent covers the architectural inventions described above; it does not restrict use of the open-source implementation for non-commercial and open-source purposes under the terms of the EUPL-1.2.

---

*Last updated: 2026-02-23*
