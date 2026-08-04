# BitLocker Manager — User Guide

## Who does what

| Role | Can |
|------|-----|
| **Operator** | See devices in their site; run the unlock workflow. **Never sees a key.** Safe for junior staff. |
| **Admin** | Enrol devices, manage operators. |
| **Auditor** | Read the audit log. Cannot pull keys. |
| **Super Admin** | Everything above + break-glass reveal (logged, step-up MFA). |

Sign in at `/ui/`: username + password, then your 6-digit MFA code.

---

## 1. Day one — backfill the fleet

The single most valuable step. On each reachable machine, run `backfill.ps1` (see INSTALL §5).
Every machine's current recovery key lands in the vault, stamped with who captured it. From
here on, no key is lost and every setup is attributable. Retire the plaintext tracker once
you've confirmed coverage in the **Devices** list.

---

## 2. Enrol a new device

When you BitLocker a new machine, capture its key immediately:

- **Admin** creates the device (UI/API or the backfill script on first run), then
- run the backfill script on that machine, **or** POST its key to `/devices/{id}/keys`.

The Devices list shows the hostname, its **Recovery Key ID**, and a "key on file" badge — never the key itself.

---

## 3. Unlock a locked machine (the main workflow)

A user is stuck at "You're locked out!". Steps:

1. **In the UI**, find the device → **Unlock…** → enter the ticket. A checkout opens and shows a
   single-use **provisioning token**. (The browser never sees the key.)
2. **On your PC**, load the key onto the Pico:
   ```powershell
   .\blm-agent.ps1 provision -Api https://<server> -CheckoutId <id> -Token <token> -Mode pico -PicoDrive E:
   ```
3. **Insert the Pico** into the locked machine at the recovery screen. It types the key; the
   machine unlocks and boots. (You never read or type the key — the confidentiality win.)
4. **On the now-unlocked target**, rotate the key so the one that was on the USB is dead:
   ```powershell
   .\blm-agent.ps1 rotate -Api https://<server> -CheckoutId <id> -Drive C:
   ```
5. **Wipe and close:**
   ```powershell
   .\blm-agent.ps1 wipe  -Api https://<server> -CheckoutId <id> -Mode pico -PicoDrive E:
   .\blm-agent.ps1 close -Api https://<server> -CheckoutId <id> -AccessToken <your token>
   ```

The service refuses to close the checkout until both the wipe and the rotation are confirmed —
so a used key can't quietly stay in circulation.

---

## 4. Break-glass reveal (Super Admin only)

When the USB path fails and you must read the key by hand: **Break-glass reveal** tab → pick the
device → enter a reason/ticket → enter a fresh MFA code → **Reveal key**. The key shows on screen,
the event is logged high-severity, and the key is flagged for rotation. Rotate that device as
soon as it's accessible.

---

## 5. Audit

**Audit** tab (Auditor/Admin/Super Admin): every login, enrolment, provision, rotation, reveal,
and close, newest first. A green **chain intact** badge means nothing has been altered; a red
badge means a past entry was tampered with.

---

## 6. Field-test checklist

Please try and give feedback on:

- [ ] **Backfill** on a few machines — does the key land in the vault with your name on it?
- [ ] **Pico unlock** on the tested model — does it type the key and unlock cleanly? Timing OK, or does `ARM_DELAY_S` in `code.py` need tuning?
- [ ] **Other models** — does any model's recovery screen read a USB file (`-Mode native`)? Note which, for the per-model table in the spec.
- [ ] **Rotate** — does `manage-bde` parsing work on your Windows build? (Output format can vary.)
- [ ] **Close gate** — confirm you cannot close without wipe + rotate.
- [ ] **Reveal** — confirm operators are blocked and super-admin needs a fresh code.
- [ ] **Scope** — confirm a Filandia operator can't see Matina devices.

### Likely rough edges (expected — that's what field testing is for)
- `manage-bde` output parsing in `rotate`/`backfill` may need a tweak for your locale/OS build.
- Pico timing (`ARM_DELAY_S`) may need adjusting so the field is focused before typing starts.
- The agent uses HTTPS in the field; make sure certs are trusted or the PowerShell calls will fail.

Send back what broke and I'll fix it before we move to production hardening.
