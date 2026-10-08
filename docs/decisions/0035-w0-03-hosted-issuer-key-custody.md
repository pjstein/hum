# 0035 · Who holds the issuer key for a platform-hosted verifier

**Status:** accepted by the owner 2026-10-07: the host holds the issuer key for platform-hosted verifiers

*2026-10-07:* The owner accepted the drafted default. Previous status: open (W0-03, 2026-10-06), needs the owner.

## Context

Organizers can run an invite or approved-list verifier from day one without running a server: the platform's `issuer` service hosts the module. The verifier manifest is signed by the organizer's authority, but credentials are signed by the issuer key, and in hosted mode the host generates and holds that key. The platform can then issue a credential under an organizer's verifier without the organizer's involvement.

This doesn't let the platform learn votes or link identities (those properties come from the credential scheme), but it does let the platform mint members of a context it doesn't administer, which matters for sybil resistance in small contexts.

## Options

1. **Host holds the key** (what `verifier-runtime.md` drafts). Simple, fast issuance, no organizer device online. The disclosure summary names the operator so people know.
2. **Organizer holds the key in phone secure hardware** and co-signs each issuance. Stronger separation; issuance waits on an organizer device, and `credentials.md` needs a two-party signing step.
3. **Threshold between host and organizer.** Best properties, most work; depends on the BBS versus group-proof choice.

## Default if no reply

Option 1 for draft 0.1, with the hosted-mode fact stated in the disclosure summary, and option 3 noted for the outside cryptography review.
