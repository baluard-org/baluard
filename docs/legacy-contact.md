# Legacy Contact

Baluard keeps one promise above all: your vault is yours, and nobody can open it without your master password. Legacy Contact is the planned exception — the one you choose in advance, for the day you cannot speak for yourself.

## What it is

You pick one person you trust. You hand them a single file (the kit letter) and a passphrase. If you stop checking in, they can open a read-only copy of your vault — look at everything, copy anything, change nothing. Until then, they can open nothing.

There is no server in the middle and no company account. The whole mechanism runs on the same private git repository your vault already syncs to.

## How it works, in plain terms

- **Arming.** In Settings → Legacy Contact you pick a waiting window (14 to 365 days), write a note to your contact, and get two things: the kit letter (a file) and a four-word passphrase. Give the person the file and tell them the words — through different channels, never the same one.
- **Staying alive.** Every device that unlocks your vault quietly records a check-in. No banners, no prompts, nothing to remember.
- **The waiting period.** If none of your devices has checked in for the window you picked, the contact can open the kit. Baluard fetches a private copy of your vault using a read-only key, verifies the kit was not tampered with, and shows the vault read-only. Before the window ends, opening is refused with the days remaining.
- **Your veto.** While you are around, the banner in your own app (Settings → Legacy Contact) shows when the waiting period has begun for any kit, with a one-tap **Deny** that closes it permanently and rotates the vault keys — a kit that was already copied becomes useless.
- **Closing it yourself.** Disarm deletes the kit's online pieces (no key rotation). Replace retires the old kit completely and hands you a fresh one. A closed kit can never be reused; replacing always mints a new kit id.
- **Losing the letter.** Resend re-exports the exact same letter, byte for byte, from your vault. The passphrase is never stored anywhere — if you forgot it, replace the kit and pick new words.

## What the contact needs

A computer with Baluard, the kit letter file, and the passphrase. Nothing else: no account with any service, no technical knowledge. On the lock screen they choose "Open with a kit letter", pick the file, type the words, and wait while Baluard fetches and verifies the copy.

## What the contact cannot do

- Change anything. The view is read-only, enforced by the daemon, not by the UI.
- Open anything early. The waiting period is verified against owner-signed check-ins.
- Reuse a replaced or denied kit. Closed kits carry the reason and are terminal.
- Pretend to be you. The kit holds no owner credential; the online copy is fetched with a read-only deploy key scoped to your one repository.

## Honest limits

The waiting period is a social control, not a cryptographic one: someone with modified software or a forged clock could bypass it. What stays cryptographic is the rest — a kit that was never released opens nothing, a denied kit opens nothing, and a replaced kit opens nothing. The kit letter plus the passphrase is the only key that matters; keep them apart, and treat the letter like the spare key to your house.
