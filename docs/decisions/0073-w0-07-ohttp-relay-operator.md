# 0073 · Who runs the OHTTP relay

**Status:** accepted by the owner 2026-10-07: two relays that phones rotate between, never the operator. Who runs them is open

*2026-10-07:* The owner accepted the recommended arrangement. Previous status: open (W0-07, 2026-10-06); needs the owner.

## Context

Every request a phone makes that is tied to a context or a person goes through an Oblivious HTTP relay (RFC 9458). The relay sees client IPs and encrypted requests; the gateway, run by the operator, sees requests and relay connections. If one party runs both, every anonymous request becomes attributable to an IP address. The design doc counts the operator among the adversaries, so the operator cannot run the relay.

## Options

1. **A commercial OHTTP relay** (the arrangement Apple and Fastly or Cloudflare use for Private Relay and Privacy Pass). Fast to set up, well-run, with a published no-logging policy. Trust rests on a contract and on the vendor's reputation.
2. **A non-profit or academic partner** running the relay on Hum's open-source relay build. More credible independence; more operational risk and cost.
3. **Two relays, one of each,** with phones rotating between them per request class. Doubles the cost; a collusion needs both.

## Recommendation

Option 3 if a partner is available at launch, else option 1 with a second relay added before the first large context. In every case:

- Each relay publishes a `service` manifest of `kind: relay` under its own authority, with its endpoints and jurisdiction. The app ships the reference relays' authority CIDs as protocol constants, a context may name more in its manifest, and the app shows each relay's operator and jurisdiction on the context's services screen (`services.md`, "Who runs it, and how a phone finds one").
- A phone refuses a relay whose manifest is signed by the same authority as the gateway it is paired with (`services.md`, rule O-5).
- Relays keep per-IP counts for rate limiting and nothing else beyond 24 hours (`services.md`, rule O-1).
- A context may name its own relay in its manifest for members who prefer it; the protocol does not care which relay a request used.

## Consequences

- The Helper aggregator's operator, also an open decision, should be a different organization from the relay operator, or phase 2's two independent parties collapse to one.
- The relay's cost scales with every fetch, which is one more reason phones fetch whole bundles and share them in channels.
