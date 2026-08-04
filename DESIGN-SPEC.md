# BitLocker Manager — System Design Specification

| | |
|---|---|
| **Reference** | R-DSE-BLM-1 |
| **Version** | 0.5 (draft) |
| **Status** | Design — Phases 1–6 complete; build not started |
| **Prepared by** | Rex Irvin Carpen — Desktop Support Engineer, OAMPI Inc. |
| **Date** | July 30, 2026 |

> Living document. Edit freely as the design evolves. Anything marked **OPEN** is an
> unresolved decision, not a finalized choice.

---

## 1. Overview & purpose

A tool to manage BitLocker key material across OAMPI's device fleet (100+ machines,
multi-site: Filandia and Matina) and to unlock a machine that has dropped into BitLocker
**recovery mode** — without the IT operator ever seeing the key.

**Primary scenario.** A user fails pre-boot authentication enough times to trigger BitLocker
recovery. They call IT. An operator authenticates to the app, selects the device, and the
app provisions a single-use USB that supplies the recovery key to that specific machine.
The device unlocks; the operator never reads the key; the key is rotated and the event is
logged.

**Why the app exists (value over native tooling).** BitLocker has no native concept of an
ephemeral, single-use, self-revoking unlock token. This tool adds exactly that: scoped
checkout, no key disclosure to humans, mandatory rotation after use, and a tamper-evident
audit trail.

**Two co-equal core drivers.** Neither is secondary to the other:

1. **Custody & accountability.** Stop losing recovery keys; record who set up each device's
   BitLocker and when (FR6, FR7). Solves the current pain of missing keys and no ownership.
2. **Plug-and-play unlock with desk-side confidentiality.** Recover a locked machine in seconds
   by inserting a prepared USB — no hunting for the key, no slow manual entry, and no reading
   the 48-digit key aloud or typing it in front of the user during troubleshooting. The
   operator never opens the key; it travels vault → USB → device only.

> Confidentiality limit (real hardware): where the mechanism is `HidInjection`, the device
> auto-types the key in ~1 second. The operator never exposes it, but the BitLocker recovery
> field is unmasked, so the digits briefly appear on the target screen as they are injected.
> A one-second burst of 48 digits is not memorable, and it is a large improvement over manual
> entry — but it is not literally invisible.

### Terminology note

The unlock USB is a **HID keyboard emulator** (keystroke *injection*) or a **native
BitLocker key carrier**, not a "keylogger." A keylogger *records* input; this device
*supplies* input. See §4 and §7 for which mechanism applies.

---

## 2. Requirements

### 2.1 Functional

| ID | Requirement |
|----|-------------|
| FR1 | Device database: inventory every BitLocker device (hostname, serial, volume GUID, site, department, encryption status). |
| FR2 | Key store: hold each device's key material (recovery key and/or startup `.BEK`), captured at encryption time — replacing the manual tracker. |
| FR3 | USB provisioning: write the selected device's key onto a flash drive for unlock, then expire/wipe it after use. |
| FR4 | Unlock: provisioned USB supplies the correct key to the target at pre-boot / recovery, with no key shown to the operator. |
| FR5 | Operator access: authenticate to the app, authorize which keys an operator may pull, and log every checkout. |
| FR6 | Enrollment & backfill: capture a device's recovery key at BitLocker setup, and backfill already-encrypted machines by reading the current key (`manage-bde -protectors -get`) while they are still unlocked/accessible. |
| FR7 | Setup accountability: record who enrolled/captured each key and when, so BitLocker setup is always attributable. |
| FR8 | Tiered visibility: the normal UI shows hostname + Recovery Key ID only, never the key (SR2), so unlock work is safe to delegate to junior staff. A **break-glass reveal** of the plaintext key is available to Super Admins for troubleshooting, under the controls in SR9. |

### 2.2 Non-functional

| ID | Requirement |
|----|-------------|
| NFR1 | Security: keys encrypted at rest; a USB only ever carries the minimum, time-limited key(s) checked out — never a full-fleet master USB. |
| NFR2 | Scale: 100+ devices, multi-site. |
| NFR3 | Auditability: every key access and USB checkout logged. |
| NFR4 | Self-contained: no dependency on AD / Entra / Intune (the fleet is not centrally managed). |
| NFR5 | Usability: provisioning is a few clicks; target-side unlock needs no typing. |

**Standing risk.** The current manual tracker stores recovery keys in clear text. The new
system must retire that data into encrypted storage.

---

## 3. Security design

### 3.1 Threat model (in scope)

| Threat | Nature | Primary controls |
|--------|--------|------------------|
| Interception of keys in storage/transit | Keys at rest, in transit to the USB, and on the USB | Envelope encryption at rest; TLS + end-to-end ciphertext in transit; single-use + auto-wipe on the USB |
| Malicious / curious IT insider | An *authorized* operator — cannot be "encrypted out" | Least privilege + scope; no bulk export; **key rotation after every unlock** so a captured key is already dead; tamper-evident logging; separation of duties |

**Out of scope (already covered elsewhere).** A stolen laptop is handled by BitLocker itself
(the disk is encrypted). A stolen unlock USB is covered by single-use + auto-wipe + rotation.

### 3.2 AAA

- **Authentication** — self-contained identity store; passwords hashed with Argon2; **MFA
  required** (TOTP minimum, hardware token preferred). Login *participates in* decrypting the
  key store, so a stolen database with no valid login is useless.
- **Authorization** — RBAC with **separation of duties**: *Operator* (pull keys within scope,
  never sees plaintext), *Admin* (manage devices/users/enrollment), *Auditor* (read logs,
  cannot pull keys), *Super Admin* (the **only** role that can break-glass reveal a plaintext
  key, under SR9). Whoever pulls or reveals keys cannot edit their own audit trail or grant
  themselves rights. Because Operators never see plaintext, the routine unlock queue can be
  delegated to junior staff safely.
- **Accounting** — append-only, **hash-chained** audit log: operator, device, timestamp,
  ticket ref, USB serial, plus wipe-and-rotation confirmation. Restricted to Admin/Auditor.

### 3.3 Security requirements

| ID | Requirement |
|----|-------------|
| SR1 | No plaintext keys at rest (envelope encryption; store unlocks only via operator auth). |
| SR2 | Key never rendered to a human — store → USB → target only. Sole exception: SR9 break-glass reveal. |
| SR3 | Single key per checkout; USB auto-wipes after unlock or timeout. |
| SR4 | Mandatory key rotation before an incident can close (hard gate). |
| SR5 | Scoped least privilege; no bulk export; anomaly flag on rapid pulls. |
| SR6 | Strong auth + MFA; login gates key-store decryption. |
| SR7 | RBAC with separation of duties (Operator / Admin / Auditor / Super Admin). |
| SR8 | Tamper-evident, append-only audit log, restricted from operators. |
| SR9 | Break-glass reveal: Super Admin only; requires reason + ticket and **step-up MFA** at reveal time; logged as a high-severity event in the hash-chained log; **flags the revealed key for mandatory rotation** (rotate at next device access if currently locked); optional four-eyes approval for designated sensitive devices. |

### 3.4 Critical constraint

Rotation (SR4) is the linchpin of the insider defense. But because the fleet is **not**
centrally managed (NFR4), a BitLocker recovery key can only be rotated **on the device, while
it is unlocked and booted** (`manage-bde` deletes the old numeric protector and adds a new
one). There is no remote push. Therefore rotation must be an **enforced on-device step** in the
unlock workflow — the incident cannot be marked closed until the app confirms the old key is
revoked and the new one stored. If operators can skip it, the insider protection collapses.

---

## 4. Architecture

### 4.1 Principle — API-first

Build the core as a service behind a REST API. The standalone web UI is the *first* consumer;
the company inventory system becomes a *second* consumer of the same contract later. **All
business logic (AAA, single-use, rotation gate, scoping) lives in the service layer, never in
the UI.**

### 4.2 Layers

```
Consumers:   Standalone web UI (now)      Inventory system (future)
                     |                             |
                     +-------------+---------------+
                                   v
REST API (versioned)  ...........  integration boundary
                                   v
Service layer  ..................  AAA · single-use · rotation gate
             |                                   |
             v                                   v
   Key vault (isolated, own KEK)        Audit log (append-only)

Service layer --> Local provisioning agent --> Single-use USB --> Locked device
```

### 4.3 Key findings

- **Finding 1 — integrate at the API, never at the database.** When the inventory system is
  approved, it talks to the same REST API as every other consumer. The **key vault stays
  isolated with its own encryption** and is never a table inside the inventory database. This
  preserves SR1, SR2, SR5 through integration.
- **Finding 2 — a web app cannot touch the USB.** Browsers are sandboxed from the OS: no
  `manage-bde`, no `.BEK` writes, no programming a smart injection USB. So the physical step
  needs a small **native agent on the operator's Windows machine**. Even in "standalone" mode
  the system is therefore two pieces (web/API service + local agent). On future integration,
  only the web service moves centrally; the agent stays on each operator box unchanged.
- **Agent double duty.** The same agent also performs the on-device **rotation** (§3.4) on the
  target after it boots.

### 4.4 Deployment

Standalone now, built for easy embedding later. Target front-end stack matches the existing
inventory system: **Bootstrap 4 / SB Admin 2** (stock primary `#007bff`), so the UI drops in
with minimal restyling once integration is approved. (Bootstrap 4 is a version behind BS5;
matching the live system takes priority over being current.)

### 4.5 Front doors (one app, three homes)

The API-first design means the app has a single build with up to three interchangeable
front doors — no fork:

1. **Standalone web UI** (now).
2. **Company inventory system** (future, if approved) — a REST *client*, per Finding 1.
3. **DSE Google Site** (fallback) — a *front door only*, not a host.

**Google Sites cannot host the app** — it is a presentation layer that embeds content in a
sandboxed iframe or links out. It cannot run the API, the database, or the vault, and cannot
reach the local agent. The app always runs on an internal server; the Site merely points to
it. Recommended: a **link-out tool card** on the DSE Tools page (same pattern as the FortiGate
CLI Generator card) opening the app in a new tab. An iframe embed is possible but inherits
cross-site auth quirks and is only worth it for in-page rendering.

> Note: unlike the FortiGate CLI Generator (pure client-side HTML, embeds as a self-contained
> snippet), the BitLocker Manager has a real backend + local agent, so a Site can only *point*
> to it — never embed it standalone.

**Two design rules that make the app embed cleanly anywhere** (locked by the Sites goal):

- **Token-based auth, not cookie sessions.** A cross-site iframe on `sites.google.com` trips
  third-party-cookie rules; a bearer token in the app's own storage sidesteps that. Use
  JWT / opaque tokens (see §6).
- **The agent connects *outbound* to the service; the browser never calls `localhost`.** An
  embedded UI cannot reach a local agent at `localhost` (mixed-content + private-network
  rules). Instead the agent dials out to the service over mTLS and waits for provisioning
  jobs. The UI then needs only one HTTPS endpoint, which embeds on any site.

Plus one config: restrict the app's `frame-ancestors` (CSP) to the DSE Sites domain and the
inventory system, so only approved hosts can frame it.

---

## 5. Data model

### 5.1 Entities

**DEVICES** — `id` (PK), `hostname`, `serial`, `volume_id` (GUID), `site`, `department`,
`encryption_status`, `created_at`, `updated_at`.

**KEY_VERSIONS** — `id` (PK), `device_id` (FK), `key_type` (recovery | startup),
`encrypted_material` (ciphertext), `key_identifier` (protector GUID / recovery key ID),
`status` (active | revoked), `rotated_from` (FK → KEY_VERSIONS.id), `created_by`
(FK → OPERATORS.id — **who enrolled/captured this key, FR7**), `source` (setup | backfill |
rotation), `created_at`, `revoked_at`.

**OPERATORS** — `id` (PK), `username`, `password_hash` (Argon2), `role`
(operator | admin | auditor | super_admin), `scope` (site), `mfa_secret`, `status`.

**CHECKOUTS** — `id` (PK), `device_id` (FK), `operator_id` (FK), `ticket_ref`, `usb_serial`,
`provisioned_at`, `unlocked_at`, `wiped_at`, `rotation_confirmed` (bool), `status`.

**AUDIT_LOG** — `id` (PK), `timestamp`, `operator_id` (FK), `checkout_id` (FK), `action`,
`device_id`, `prev_hash`, `hash`.

### 5.2 Relationships

- `DEVICES` 1—N `KEY_VERSIONS`
- `DEVICES` 1—N `CHECKOUTS`
- `OPERATORS` 1—N `CHECKOUTS`
- `CHECKOUTS` 1—N `AUDIT_LOG`; `OPERATORS` 1—N `AUDIT_LOG`
- `KEY_VERSIONS` → `KEY_VERSIONS` (self, via `rotated_from`) for key lineage

### 5.3 Load-bearing design choices

| Choice | Traces to |
|--------|-----------|
| Keys are **versioned, never overwritten** — rotation inserts a new row and flips the old to `revoked`. Makes "a captured key is already dead" provable and preserves history. | SR4 |
| `encrypted_material` holds **ciphertext only**; plaintext exists only in service-layer memory at provisioning time. | SR1 |
| `AUDIT_LOG` is **hash-chained** (`hash` folds in `prev_hash`); a deleted/edited row breaks the chain detectably. | SR8 |
| `OPERATORS.scope` enforces per-site visibility (Filandia vs Matina). | SR5 |

---

## 6. REST API (v1)

| Method & path | Purpose | Access |
|---------------|---------|--------|
| `POST /auth/login` | Credentials → MFA challenge | public |
| `POST /auth/mfa` | Complete MFA → session token | public |
| `GET /devices` | List devices (scope-filtered) | operator+ |
| `GET /devices/{id}` | Device detail | operator+ |
| `POST /devices` | Enroll a device + capture key at encryption time | admin |
| `PATCH /devices/{id}` | Update device metadata | admin |
| `POST /checkouts` | Open an incident (device_id, ticket_ref) → checkout + agent provisioning token | operator+ |
| `POST /checkouts/{id}/provision` | Agent confirms USB written (usb_serial) | agent |
| `POST /checkouts/{id}/rotate` | Agent submits new protector after on-target rotation | agent |
| `POST /checkouts/{id}/close` | Close incident — **fails unless wiped AND rotated** | operator+ |
| `GET /audit` | Read the hash-chained log | auditor / admin |
| `POST /devices/{id}/reveal` | Break-glass reveal of the plaintext key (reason + step-up MFA; logs high-severity event; flags key for rotation) | super admin |

The checkout lifecycle endpoints enforce SR3 and SR4 server-side.

---

## 7. Vault encryption

Envelope encryption:

1. Each `KEY_VERSIONS.encrypted_material` is encrypted with a per-record **data key (DEK)** —
   AES-256-GCM.
2. Each DEK is wrapped (encrypted) by the **key-encryption key (KEK)**.
3. The KEK is never stored in plaintext. Operator login unlocks KEK access (SR6).
4. Plaintext key material appears only in service-layer memory, only at provisioning time.

### 7.1 OPEN — where the KEK lives

Because the system is self-contained (NFR4), pick one:

- **Hardware-backed (recommended).** A YubiKey / HSM, or the server TPM, holds the KEK and
  performs unwrap operations. The master key never exists in extractable form. Appropriate for
  a store guarding 100+ master keys.
- **Software (pragmatic v1 default).** KEK derived from operator credentials (Argon2) and/or
  protected by Windows DPAPI. No extra hardware; a server admin could in principle extract it.

Implemented behind an `IKekProvider` interface (see §9), so this is a config swap, not a
rebuild. v1 ships with the software provider; hardware is dropped in when a token is procured.

---

## 8. Decision log

| Decision | Resolution |
|----------|------------|
| API / service language | **Python + FastAPI** (chosen). |
| Local agent language | **.NET (C#)**, signed Windows service — required for `manage-bde`, CNG, TPM. |
| Database | PostgreSQL (portable) or SQL Server Express (least friction). **Lean: PostgreSQL.** |
| Auth transport | **Token-based (JWT / opaque)**, not cookie sessions — for cross-site embedding. |
| Agent connectivity | **Outbound agent → service over mTLS**; browser never calls `localhost`. |
| Front-end | Bootstrap 4 / SB Admin 2 over the REST API. |
| Front door | Standalone now; inventory system and/or DSE Google Site later (link-out card). |
| KEK location | Pluggable `IKekProvider`; **software provider for v1**, hardware later. |
| Unlock mechanism | Pluggable `IUnlockMechanism`; chosen per device model by hardware test. |

**Test-gated (not blocking — resolved by a cheap test, see M0):**
1. Recovery-screen unlock: native `.BEK` read vs HID injection, per device model.
2. KEK hardware upgrade: when/if a TPM/HSM/YubiKey budget is approved.

---

## 9. Detailed design (Phase 5)

### 9.1 Cross-language contract discipline

Because the service is Python and the agent is .NET, they share **no** code. The agent↔service
contract must therefore be explicit and language-neutral — **JSON over mTLS**, every field and
type pinned in §9.4 — rather than implied by shared models. Treat that contract as the source
of truth for both codebases.

### 9.2 Pluggable interfaces

Two decisions are deferred safely by making them strategy interfaces:

- **`IUnlockMechanism`** — implementations `NativeBek` and `HidInjection`. The agent selects
  per device via config. The hardware test (M0) only flips which one runs — never a redesign.
  `HidInjection` emits **digits 0–9 and Enter only** — the 48-digit recovery key is numeric, so
  the recovery field ignores letters. Emit **numpad key codes** (layout-stable) or confirm a US
  layout before releasing keystrokes (see §9.6).
- **`IKekProvider`** — implementations `Dpapi` / `Passphrase` (software, v1) and `Tpm` / `Hsm`
  (hardware, later). Swapping is a config change.

### 9.3 Component stack

| Layer | Choice |
|-------|--------|
| Service / API | Python + FastAPI |
| Data key cipher | AES-256-GCM |
| MFA | TOTP (RFC 6238); optional FIDO2 for hardware tokens |
| Agent ↔ service | mTLS (mutual certificate auth) |
| UI ↔ service | HTTPS + bearer token |
| Local agent | .NET (C#) signed Windows service |
| Database | PostgreSQL (lean) / SQL Server Express |
| Front-end | Bootstrap 4 / SB Admin 2 |

### 9.4 Checkout protocol (the security spine)

mTLS throughout. Each step maps to the SR it enforces.

1. Operator opens a checkout (device + ticket). Service checks **scope** (SR5), creates the
   `CHECKOUTS` row, and issues a **single-use, short-TTL token** bound to that checkout and
   agent.
2. Agent redeems the token. Service unwraps the key **in memory** (DEK via `IKekProvider`) and
   returns it over mTLS. Agent writes it to the USB via `IUnlockMechanism` and reports
   `usb_serial`. Plaintext key never persists (SR1, SR2).
3. Operator inserts the USB → device unlocks → boots.
4. Agent rotates **on the target**: `manage-bde` deletes the old numeric protector, adds a
   fresh one, reports the new encrypted material to `/checkouts/{id}/rotate`.
5. Service inserts a new `active` `KEY_VERSIONS` row, marks the old one `revoked`, sets
   `rotation_confirmed` (SR4).
6. Agent wipes the USB, zeroes the in-memory key bytes, reports (SR3).
7. `/checkouts/{id}/close` succeeds **only** when wiped **and** `rotation_confirmed` — else the
   incident stays open. SR3 + SR4 enforced by the protocol, not by operator discipline.

### 9.5 UI screens (Bootstrap 4 / SB Admin 2)

- **Device list** — scope-filtered table; **hostname + Recovery Key ID + status only, never the
  key**; status badges; search. Safe for junior staff.
- **Checkout flow** — select device → enter ticket → provisioning progress → unlock →
  rotation confirmation → close. Never displays key material.
- **Break-glass reveal** (Super Admin only) — reason + ticket entry → step-up MFA → time-limited
  key display with no clipboard persistence; fires the rotation flag on close.
- **Audit view** — read-only, Auditor/Admin; shows the hash-chained log with integrity status.
- **Admin** — device enrollment, operator/role management.

### 9.6 Recovery-screen field notes (observed)

From a real locked machine ("You're locked out!" recovery variant, triggered by too many
failed sign-ins):

- **Recovery Key ID is shown on screen** (e.g. `F70F2436-E285-40B3-AB51-B50CBF6EC24C`). This is
  the `KEY_VERSIONS.key_identifier` lookup handle — it identifies *which* stored key is needed;
  it is **not** the key and cannot unlock anything. Safe to read/transcribe.
- **Input is numeric-only.** Alphabetic keys are ignored; only digits register. Confirms the
  48-digit recovery key is numeric and that `HidInjection` needs to emit digits + Enter only.
- **No USB-read option** on this UEFI recovery screen (only: type the key, find a text file,
  `aka.ms/recoverykeyfaq`, or reset). → This model maps to **`HidInjection`**, not `NativeBek`.
- **Keyboard Layout: US** is displayed. `HidInjection` should emit numpad codes or confirm US
  before releasing keystrokes.

**Per-model M0 log** (extend as models are tested):

| Device model | USB key read at recovery? | Mechanism |
|--------------|---------------------------|-----------|
| (this test unit) | No | `HidInjection` |

---

## 10. Build plan (Phase 6)

### 10.1 v1 scope (MVP)

**In:** device DB + encrypted vault (retire the plaintext tracker); auth + MFA + RBAC;
hash-chained audit; checkout lifecycle with the rotation gate; **one** unlock mechanism (chosen
by M0); software KEK provider; standalone Bootstrap 4 UI; DSE Site link-out card.

**Deferred:** hardware KEK (TPM/HSM); the second unlock mechanism; inventory-system
integration; iframe embed; anomaly-detection tuning.

### 10.2 Milestones

| # | Milestone | Notes |
|---|-----------|-------|
| **M0** | **Hardware test** — does the recovery screen read a USB key, per device model? | No code. Do first; it decides `IUnlockMechanism`. |
| M1 | Data layer + encrypted vault (software KEK); migrate the tracker. | Early security win even before USB flow works. |
| **M1b** | **Backfill script** — read current recovery keys (`manage-bde -protectors -get`) from every still-accessible machine into the vault, tagged with `created_by`. | Stops the key bleed immediately (FR6/FR7). Runs before the full agent exists. |
| M2 | FastAPI service: auth/MFA/RBAC, devices, hash-chained audit. | |
| M3 | Checkout lifecycle endpoints + rotation gate. | The security spine (§9.4). |
| M4 | .NET agent: outbound mTLS, provisioning (chosen mechanism), on-target rotation, USB wipe. | |
| M5 | Bootstrap 4 / SB Admin 2 UI. | |
| M6 | End-to-end test on real hardware; DSE Site link-out card. | |
| Later | Hardware KEK; second mechanism; inventory integration. | |

### 10.3 Sequencing notes

- **M0 is a no-code, do-it-this-week task** and it unblocks a core component — run it before
  writing agent code.
- **M1 delivers value on its own**: moving recovery keys out of the plaintext tracker into an
  encrypted store is a security improvement even before a single USB is provisioned.
- **M1b is the fastest route to the core problem.** The stated pain — lost keys, no
  accountability — is largely solved the moment every still-accessible machine's key is
  captured with a `created_by` name attached. This can ship before the agent, the UI, or any
  USB work. Prioritise it.
- M3 is the highest-risk, highest-value milestone — the rotation gate is what the whole insider
  defense rests on. Test it hard.

---

## 11. Future ideas & product tiers (footnotes, not yet built)

Captured for the roadmap. None of this is implemented; it records design intent and
open questions so the thinking isn't lost.

### 11.1 Product tiers

- **Standard (current build).** Vault, accountability, hash-chained audit, and on-site
  plug-and-play unlock using a plain ~$4 Raspberry Pi Pico as the HID keyboard. Runs entirely
  in-house; no recurring cost. This is the baseline product.
- **Premium — "Remote Unlock" (v2 R&D).** A sealed, 3D-printed cellular unlock dongle for
  off-site / field machines. Sold as a hardware + capability add-on for organisations with
  distributed assets. Same vault, same audit trail; different last-mile delivery.

### 11.2 Premium "Remote Unlock" concept

Goal: unlock a remote/field laptop stuck at the BitLocker recovery screen without shipping IT
to site and without ever exposing the recovery key to the user.

Design notes from brainstorming:
- **Why not just SMS/email the key to the user?** A texted 48-digit key lands in the user's
  message history permanently — a leak by design, and it breaks the "operator never sees the
  key" principle. A sealed device that *consumes* the key and types it, never displaying it,
  preserves that guarantee.
- **Hardware sketch:** Pico (or Pico W for Wi-Fi) + a low-power LTE module (e.g. Cat-M/NB-IoT
  such as SIM7080; avoid classic 2G SIM800L) + a small battery or supercapacitor, sealed in a
  tamper-resistant 3D-printed enclosure.
- **Power:** the pre-boot USB port supplies little current, and cellular radios spike hard on
  transmit (2G worst). Fix: the on-board battery/cap powers the radio's spike; the starved USB
  port only has to run the Pico. This resolves the main power objection.
- **Key delivery:** the device receives the correct machine's key over the air (cellular/Wi-Fi),
  decrypts it inside the sealed enclosure, and types it — payload never exposed.

### 11.3 The one unknown to validate before promising it

Whether the sealed cellular device **enumerates as a plain USB keyboard at the pre-boot
recovery screen, reliably, across the real fleet's laptop models.** Pre-boot USB stacks are
picky and model-specific. This is the sole remaining risk and can only be settled by
prototyping one unit and testing on real hardware. Sell as "roadmap / prototype in progress,"
never "available today."

### 11.4 Sequencing

Prove the plain on-site Pico unlock first (removes all software risk and validates the core
keystroke-injection mechanism on real hardware). The premium dongle is then "the same trick,
sealed and cellular" — prototype it as an isolated experiment testing only the new variables.

### 11.5 Adjacent idea — dedicated operator phone

A cheap dedicated Android "utility phone" could serve as an operator console (run the UI, hold
MFA, open checkouts, load the Pico over USB) — playing to the phone's strengths while the Pico
does the one reliable pre-boot job. Using the phone *itself* as the pre-boot injector is
possible but hits the same enumeration/timing wall as above; treat as a separate experiment.
