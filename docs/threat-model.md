# Hum Threat Model — Draft 0.1

Oct 6, 2026 · W0-07

## How to read this

This is the document every reviewer checks a spec, a PR or a simulator report against. It names what Hum protects, who it protects it from, what each party can see, what each party must never see, and which spec rule keeps it that way. Where a protection rests on an assumption, it says what breaks when the assumption fails.

The eight invariants in [CLAUDE.md](../CLAUDE.md) are the summary. This document is the long form. When a spec and this document disagree, the spec wins for its own formats and this document wins for who may see what; flag the disagreement either way.

Spec references use the file name and section. Sibling specs that had not landed when this was written are named with the section this document assumes they will have; the [assumptions list](#assumptions-about-sibling-specs) at the end says which.

## Assets

| Asset | What it is | Where it lives | Who may see it |
| --- | --- | --- | --- |
| A vote | One person's answer to one card | The phone's hand; a ballot in flight; an aggregator's intake set until release (phase 1) | The person. Phase 1 aggregator sees it under a pseudonym. Phase 2: nobody but the person |
| A hand | All of one person's votes in a deck | The phone only | The person |
| A shield | A person's remaining yearly privacy budget and its spend history | The phone only | The person |
| The sealed backup and its recovery phrase | The chat identity key, edit root, credentials with their nym secrets and the person's context list, sealed under a key wrapped to a 12-word phrase ([credentials.md, The sealed backup](specs/credentials.md#the-sealed-backup); ADR 0023). Never a hand, shield, receipt or card order | The platform's backup container (iCloud or Android backup); the phrase with the person | The person. The platform provider holds ciphertext it cannot open |
| The identity link | Any join between the resident card, a voting pseudonym and a chat name | Nowhere | Nobody |
| Membership | Who is in a context, and who is in which channel | Phones in the group (MLS leaves); the organizer's admitted list, if the context keeps one | Members per the context's member-list setting; the organizer knows who was admitted |
| Participation | Whether a given person voted in a deck at all | The phone | The person |
| Chat content | Messages, reactions, edits | Phones; ciphertext in the delivery queue and history archives | Channel members |
| Files | Attachments, folders, archives, issue-map text and evidence in members-only contexts | Sealed blobs in stores; keys in MLS messages and keyrings | Members of the channel, folder or context |
| Evidence | What a person showed a verifier | The verifier, for its declared retention | The verifier, under its manifest |
| Metadata | Timing, sizes, which channel or context, IP addresses | Delivery service, stores, relay, gateway, each partially | Minimized per party, see below |
| Releases and the issue map in public contexts | Noised totals, positions, arguments, takes | The log, resolvers, mirrors | Everyone, by design |

Everything in the public row is safe to publish because it was built from the rows above through a mechanism that is checked at the edge: differential privacy for releases, and deliberate authorship for the issue map.

## Parties and adversaries

The design doc names the operator, a breach or subpoena, organizers, other members who know you, and the public. This document adds a malicious verifier, a malicious or compromised agent, a compromised phone, colluding servers, a network attacker and a modified client. Each is treated as able to do everything a party in that position can do, plus whatever lying its position allows.

Honest-but-curious means the party runs the protocol correctly and tries to learn from what it sees. Malicious means it also deviates. Phase 1 assumes an honest-but-curious operator for the aggregation itself and a malicious everyone for everything else; phase 2 removes the aggregation assumption.

## What each party sees and must never see

The mechanism column names what keeps the never-sees column true, and the spec that defines it. A reviewer who finds a code path, log line, cache key or metric that would move an item from the never-sees column into the sees column has found a blocker.

| Party | Sees | Must never see | Mechanism and spec |
| --- | --- | --- | --- |
| Your phone | Everything you did: hand, shield, credentials, chat | Anyone else's votes or hand | Ballots are the only thing carrying votes and they go to aggregators only. Receipts are checked against a whole receipt page, never a per-leaf query. [ballot.md](specs/ballot.md); [services.md, Receipts](specs/services.md#receipts) |
| Organizer | Who accepted an invite or was admitted; session outcomes of the invite and approved-list verifiers the organizers run themselves ([verifier-runtime.md, Transparency](specs/verifier-runtime.md#transparency-who-sees-what)); the noised daily count; releases; the issue map; who signed what in chat | A vote, a hand, whether a given member voted, a live count; sessions of a verifier they merely accept | Membership is an anonymous group: ballots carry a pseudonym proof, not a chat identity. The daily count is differentially private and drawn once per day. [credentials.md](specs/credentials.md); [context.md, The noised daily count](specs/context.md#the-noised-daily-count); [services.md, The daily count](specs/services.md#the-daily-count) |
| Moderator | A reported message in the clear, its attachment reference and the sender's chat identity, delivered to the organizers group by a franked report whose MLS sender is the reporter ([chat.md §11.3](specs/chat.md#113-reports)) | Anything about votes; messages nobody reported; who the sender votes as | Franking proves the message was sent without the moderator reading anything else; the chat identity links to no vote. [chat.md §11](specs/chat.md#11-moderation-and-franking) |
| Other members | What you say under your chat name; that you are in the channel; positions you sign; every join and leave in the channel, directly in the MLS tree | How you voted, whether you voted, your pseudonym, your resident card attributes beyond what the context's policy proves to the group as a whole | The chat identity key is an independent key. The voting nullifier, the authorship nullifiers and the token-issuance scopes are all derived from one credential secret under different scopes, and what keeps them apart is scope separation inside the proof system, which credentials.md delivers with one BBS credential system and per-scope pseudonyms unlinkable under DDH ([credentials.md, Scopes and nullifiers](specs/credentials.md#scopes-and-nullifiers); ADR 0020) and the cross-spec identifier trace checks ([issue-map.md, Membership proofs](specs/issue-map.md#membership-proofs); [storage.md §6.1](specs/storage.md#61-tokens)). Cards are dealt and the app shows no running result. DP holds against members who know every other vote. [deck.md](specs/deck.md); [release.md](specs/release.md) |
| Chat delivery service | Ciphertext, arrival time, which group and which context it was registered under, padded size bucket, message kind, the epoch number and so the rate of joins and leaves, how many Welcomes a commit carried, token issuance counts per channel ([chat.md §12.10](specs/chat.md#1210-what-the-ds-sees)) | Content, the member list or its size beyond what commit sizes suggest, who sent a message, who fetched, which device | MLS end-to-end encryption; per-channel blind tokens issued against a per-epoch delivery secret, through the relay; padding to buckets; no fetch cursors. [chat.md §12](specs/chat.md#12-the-delivery-service); [services.md, Tokens](specs/services.md#tokens) |
| Blob store | Ciphertext, padded sizes, timing, which context's quota, a per-context token | Contents, file names, which channel, which member uploaded or fetched, a sealed key | Sealed blobs padded with Padmé; keys travel only inside MLS messages or sealed indexes; tokens carry only the context; every request through the relay. [storage.md](specs/storage.md); [manifest.md, Blobs and storage](specs/manifest.md#blobs-and-storage) |
| Aggregator, phase 1 | Pseudonymous contributions for one deck with exact arrival times, in memory until release; nullifiers; the receipt pages; a disclosed attribute value beside the pseudonym when the plan has a breakdown part (a residual, see below); the diff between a person's successive round-0 hands when they re-sort before close ([ballot.md, Replacement in round 0](specs/ballot.md#replacement-in-round-0), ADR 0024); logs rounded to the minute | Who a pseudonym belongs to; a chat name; a resident card; which phone a ballot came from | Pseudonyms are per deck (scope `hum/ballot/1 ‖ deck lineage CID`, ADR 0021) with no link to the credential, so even the Leader holds one deck's profile and never a person's history across decks; ballots arrive only through the relay; contributions and nullifiers are deleted after release; logs round timestamps. [credentials.md](specs/credentials.md) pseudonym; [services.md, Ballot intake](specs/services.md#ballot-intake); [services.md, What services log](specs/services.md#what-services-log) |
| Aggregator, phase 2 | Its share of each ballot, which reveals nothing alone; the aggregate after noise | A vote, even under a pseudonym | Prio3 secret sharing between two non-colluding aggregators, each adding its share of noise. [ballot.md](specs/ballot.md) phase 2; [services.md, Phase 2](specs/services.md#phase-2-dap) |
| Helper, phase 1 | `nHat`, the receipt roots and pages, every table, the Leader's proposals | A ballot, a raw sum, a nullifier | It receives only the proposed release version and signs what it can check: parameters, floors, one release per deck. At launch the same operator may run it. [release.md, Who signs](specs/release.md#who-signs); [services.md, Publishing a release](specs/services.md#publishing-a-release) |
| Token issuer, when separate from the store | A membership proof per issuance and the count per pseudonym per day under its scope | Which blob or request a token was spent on; which member | Blind signatures; issuance and spend never share a relay connection (services.md T-4); the issuer sees nothing from the store. [storage.md §6.1](specs/storage.md#61-tokens); [services.md, Tokens](specs/services.md#tokens) |
| Platform backup provider (Apple, Google) | A sealed backup file of unknown contents, its size and when it changed | Its contents; whether the person votes; anything about a vote, since the backup never holds one | Format 1 sealed blob under a fresh key, that key HPKE-wrapped to an X25519 key derived from the recovery phrase with Argon2id; no Hum service receives the file or a locator. [credentials.md, The sealed backup](specs/credentials.md#the-sealed-backup) |
| Credential issuer and verifier | The evidence its manifest declares, including the disclosed attribute values of another card submitted as evidence; that a person got a card; a keyed dedup hash; a renewal, which is an ordinary evidence session in the last two periods of an epoch | The credential it issued; what the person joins, says or votes; any identifier, nullifier or pseudonym that a later presentation produces. The property is unlinkability, not value secrecy: a ward it saw at issuance may appear in a breakdown, but nothing ties the two | Blind issuance: the issuer signs without seeing the credential. Presentations are zero-knowledge and unlinkable to issuance. The host writes nothing from the issue request. The issuer's scope (`hum/issuance/1`) is distinct from every context scope, and there is no evidence-free renewal that could carry a linkable nullifier ([credentials.md, Every identifier](specs/credentials.md#every-identifier-where-it-lives-who-sees-it)). [credentials.md](specs/credentials.md); [verifier.md](specs/verifier.md); [services.md, Issuer and verifier host](specs/services.md#issuer-and-verifier-host) |
| Log and witnesses | The log of record is also the one party that checks the clock on authorship and sponsor proofs, a check no witness audits (see Assumptions). Manifest CIDs with type and authority, in order; who submits under an authority signature; for signed authored objects, the author's chat identity key, which it must read to count `SIGNED_PER_WINDOW`; for unsigned ones, a `(window, slot)` nullifier that links to nothing; for agents, the sponsor | Content of anything personal; a chat key joined to a vote or a resident card; a slot nullifier joined to anything; which phone submitted or looked up what | Leaves hold hashes only; manifests carry no personal data; the authorship proof is the credential, with scope-separated membership proofs and a per-log nullifier set only ([issue-map.md, Authority and authorship](specs/issue-map.md#authority-and-authorship)); every phone request, submissions included, goes through the relay ([services.md, routing table](specs/services.md#which-requests-go-through-the-relay)). [manifest.md, Transparency logs](specs/manifest.md#transparency-logs); [services.md, Log and ledger](specs/services.md#log-and-ledger) |
| Resolver, mirror, gallery | Which CIDs are fetched, from which relay connection | Which phone fetched what; sealed content | Public bytes only; whole-bundle fetches; requests through the relay; logs keep counts after 24 hours. [services.md, Resolver and mirrors](specs/services.md#resolver-and-mirrors) |
| OHTTP relay | Client IPs; encrypted requests; which gateway; sizes in buckets | Any request's content or path | OHTTP encryption to the gateway's key, pinned in a logged manifest. [services.md, OHTTP relay](specs/services.md#ohttp-relay) |
| OHTTP gateway | Decrypted requests and which relay they came through | A client IP | The relay strips it; the gateway never terminates a client connection. Same section |
| Agent, personal tier | What the person sees on their phone, including their own hand | Nothing leaves the device; it cannot send a ballot | No agent holds a voting credential; the personal agent's outputs are shown, not sent. [agent-sponsor.md](specs/agent-sponsor.md) tiers |
| Agent, shared tier | What the channel sees, as a visible MLS member | Votes, hands, shields, a vote's pseudonym; anything from a channel it is not in | It is an MLS leaf whose credential names its sponsor manifest; its sponsor credential is of verifier class `agent`, which no voting policy accepts; adding it is a visible membership event. [agent-sponsor.md](specs/agent-sponsor.md); [chat.md](specs/chat.md) agent membership event |
| Agent, public tier | Releases and public issue maps | Anything else | It has no credentials at all |
| The public | Releases, their parameters and receipts; public issue maps; takes; the log | Anything about one person | DP floors at the edges; 100-voter minimum; no common ground, movement or ratings under 300; no breakdown cell under 300; no map or groups under 800 ([context.md, Protocol constants](specs/context.md#protocol-constants-draft-01)). [manifest.md, Privacy floors](specs/manifest.md#privacy-floors); [release.md](specs/release.md) |

## Adversaries in detail

Each entry says what the adversary controls, what it wants, what it gets anyway, what stops it getting more, and what remains.

### The operator

Controls the reference log, the Leader aggregator, the gateway, the resolver, the gallery, the delivery service, the blob store, the token issuers, the core verifiers, and the published app build, which carries the bootstrap constants: the reference log's authority, origin and launch witness keys, the reference relays' authorities, and the Global context CID (services.md, Checkpoints and Who runs it). At launch it may also run the Helper ([release.md, Who signs](specs/release.md#who-signs); the Helper operator is an open decision in [DECISIONS.md](DECISIONS.md)). Phase 1 does not depend on the Helper's independence, because the Helper's signature is a separately keyed check of parameters and floors, not of the sums; phase 2 does, and that is a row in the assumptions table. Does not control the relay, the witnesses, or the phones.

Wants: votes, the identity link, membership, content.

Gets anyway: everything in the sees column for each service it runs, joined where the protocol lets the same request reach two services it runs. Timing across its services is the main residual: a token issuance, a store put and a delivery send close together are visible to the operator as events, though each is anonymous on its own.

Stopped by:

- Phase 1 votes: the operator runs the adding, so it sees pseudonymous votes. What stops it going further is that pseudonyms link to nothing it holds ([credentials.md](specs/credentials.md)), ballots arrive via a relay it does not run, and the honest-but-curious assumption for aggregation ([Assumptions](#assumptions-and-what-breaks)).
- Phase 2 votes: secret sharing with a Helper it does not run.
- Equivocation on the log: witness cosignatures from parties it does not run ([manifest.md, Transparency logs](specs/manifest.md#transparency-logs)); phones exchange checkpoint hashes in channels.
- Floors: phones, both aggregators and the log each check them. The operator's aggregator cannot publish a release the log refuses, and a release the log did not log is never displayed ([manifest.md, Privacy floors](specs/manifest.md#privacy-floors)).
- Content: MLS and sealed blobs; the operator holds no keys.
- A malicious app build: native only, reproducible builds with hashes on the log, so a build that differs from the audited source is detectable. Not preventable by the protocol; see [Out of scope](#out-of-scope).
- The identity link: no service receives two of the three identities in a form that joins them, and the services that see one each are reached through the relay. Two places hold a card-derived value beside a chat identity by design, and neither links to a ballot: the log receives a signed issue-map object whose bundle has the chat identity key, a per-object nullifier and the proof's public fields; and the organizers group holds a join nullifier beside each admitted chat identity (chat.md §5.17). The public fields are the same for every member of a context (context.md C16). The identifier list in [credentials.md](specs/credentials.md) is the thing to check. The one place the specs come close is a phase 1 breakdown contribution, which carries a disclosed attribute value beside the pseudonym; see the residual at the end of the sibling-spec section.

Remains: traffic analysis across the operator's services; a dishonest noise draw in phase 1 (verifiable DP is research-stage); the operator's legal exposure, below.

### A breach or subpoena

Controls: a snapshot of any one service's storage and logs, possibly several, at one moment, or a continuing feed.

Wants: the same as the operator, after the fact.

Gets anyway: whatever the logging table allows that service to keep ([services.md, What services log](specs/services.md#what-services-log)), for its retention window.

Stopped by: data minimization. There is no vote to hand over after release (deleted within 24 hours, AG-5), no member list at the delivery service or store, no plaintext anywhere, no identity link anywhere, no shield or hand off the phone. A subpoena for a person's votes has no addressee. A breach of the verifier gets the evidence the manifest declared it keeps, which is why retention and evidence are declared and shown before submission.

Remains: a breach of the phase 1 aggregator during an open deck gets pseudonymous votes for that deck. A breach of a verifier gets its evidence. A legal order to keep a feed of future requests is a malicious operator, above. A breach of a platform backup account yields the sealed backup, which needs the 12-word phrase (Argon2id, 64 MiB) and never holds a vote, hand, shield or receipt.

### Organizers

Control: the context manifest (within floors), who is admitted, roles, what is dealt, when decks close, the issue map's moderation, and in a small context perhaps most of the members.

Wants: to learn how particular members voted, or to steer results.

Gets anyway: the admitted list; the issue map with chat-name authorship where authors chose it; the noised daily count; releases.

Stopped by:

- Floors can only tighten: an organizer cannot set ε above the protocol maximum, the minimum below 100 voters, or more than one release per deck ([manifest.md, Privacy floors](specs/manifest.md#privacy-floors), [context.md](specs/context.md)).
- Planted members: DP holds if the organizer knows every other vote. That is why Hum has no rule like "hide results under 10 people" and relies on the floors instead.
- Closing a deck early to catch a small set of voters: the minimum voter floor is on the noised count at release, not on the deck's duration.
- Dealing a deck to one person: same floor.
- Re-dealing a deck under new rules: frozen fields; a deck's statements and plan freeze at open ([deck.md](specs/deck.md)).
- Reading the daily count fast enough to watch one person: it is computed once per day and is noised with its own budget ([context.md](specs/context.md)).
- Replacing the aggregators or log with their own: the context manifest names them and every version is logged; members see the change. A context that names a one-party aggregator pair is visible as such.

Remains: an organizer who knows a member well can guess from the issue map and from chat; the protocol protects votes, not opinions people state in public. Side information is the next adversary.

### Other members who know you

Control: their own phones, their own votes, their knowledge of you, possibly coordination among many of them.

Wants: your vote.

Gets anyway: what you say in chat under your chat name; your signed positions; the releases.

Stopped by: user-level DP covers your whole participation in a release, so a coalition that knows every vote but yours learns about yours only what ε allows ([release.md](specs/release.md); [docs/research/dp-polis](research/dp-polis/)). The results deck shows your vote next to the group's on your phone, matched locally, so nothing about the match leaves ([ballot.md](specs/ballot.md) receipts). The shield caps what repeated decks can reveal over a year ([shield.md](specs/shield.md)).

Remains: a release of a 100-person deck at ε 4 is private in the DP sense, not secret. The design doc is honest that ε 4 is a target, and the privacy targets are an open decision.

### The public

Control: everything on the log, resolvers and gallery; unlimited compute.

Wants: anything about one person.

Stopped by: the same DP guarantee, plus the size gates: no breakdown cell under 300 voters, no map or groups under 800 ([release.md](specs/release.md)). Post-processing is free, so the studio and gallery add no exposure. Public issue maps carry chat names only where authors chose them.

Remains: self-selection and weighting can mislead about a population without exposing anyone; that is a product problem, not a privacy one.

### A malicious verifier

Controls: its own code in the runtime, its manifest, its evidence store, its issuance.

Wants: to collect more than it declared; to link issuance to later presentations; to issue credentials to people who should not have them; to deny credentials to people who should.

Stopped by:

- Linking: it cannot. Blind issuance and zero-knowledge presentation hold whatever its code does ([credentials.md](specs/credentials.md)). The runtime gives verifier code no access to anything that later appears in a presentation ([verifier-runtime.md](specs/verifier-runtime.md)).
- Over-collection: transparency. The manifest declares the evidence and pins the code hash; the phone shows exactly what is asked before anything is sent; every manifest change is logged (V-1 in [services.md](specs/services.md#issuer-and-verifier-host)). It can still ask for too much and people can still agree; the defense is that it is visible and that contexts choose which verifiers to trust.
- Sybils: uniqueness is per issuer. A context that trusts a weak issuer accepts its sybil risk and can require a core uniqueness credential in addition ([trust-list.md](specs/trust-list.md)).
- Denial: no protocol remedy in draft 0.1. Each policy leaf names exactly one verifier (context.md rule C16), so a person that verifier refuses has no other issuer to go to. The organizer's remedy is a new context version that names another verifier; the refusal itself is invisible to everyone but the person.

Remains: a verifier that leaks or sells its evidence. A presentation always names the verifier that issued each card ([credentials.md, Format](specs/credentials.md#format)); it is not hidden. What stops that from narrowing a member is [context.md](specs/context.md) rule C16 (ADR 0100): in draft 0.1 every policy leaf resolves to exactly one verifier and no policy has an `any` node, so every member of a context presents the same verifiers and "which verifier someone used" is the same answer for all of them. An earlier version of this document said the issuer name was not presented where a policy allowed any issuer on a list; that was never true of the credential format.

### A malicious or compromised agent

Per tier.

- Personal: runs on your phone and sees what you see. A compromised personal agent is a compromised phone, below. It cannot send a ballot because it holds no credential, and the app, not the agent, decides what leaves the device.
- Shared: a visible MLS member. It sees the channel. It can flood the issue map, which is why it has a sponsor and per-sponsor rate limits, its content is labeled, and the issue-map spec has moderation limits ([agent-sponsor.md](specs/agent-sponsor.md); [issue-map.md](specs/issue-map.md)). An agent on the operator's servers would be the operator reading a channel, which is why adding one is a visible event naming where it runs.
- Public: sees releases. It can only mislead, and its takes are labeled and ranked like everyone else's.

Stopped from voting at every tier: a sponsor credential comes from a verifier of class `agent` and voting policies accept only class `person` ([agent-sponsor.md, Why agents never vote](specs/agent-sponsor.md#why-agents-never-vote); verifier.md rule 1 and its frozen `class`; trust-list.md step 5), aggregators verify the presentation against the policy, and a vote vector without a valid presentation is refused ([services.md, Ballot intake](specs/services.md#ballot-intake)).

Remains: a shared agent's sponsor is accountable, but a flood is still work to moderate.

### A compromised phone

Controls: everything on that phone: the hand, the shield, the credentials, the chat keys, the keyring.

Wants: that person's data, or to act as them.

Gets anyway: that person's data. There is no design that protects a person from their own compromised device, and Hum does not claim one.

Stopped by, for everyone else: a compromised phone holds one person's keys and nothing about others' votes; it can cast at most one ballot per deck under that person's pseudonym (nullifier); it cannot loosen floors for anyone else ([manifest.md, Privacy floors](specs/manifest.md#privacy-floors)); keys in secure hardware limit extraction; keyrings rotate when a member is removed so new content is out of reach ([storage.md](specs/storage.md) keyrings). A modified client that skips its own shield check harms only its user.

Remains: content the phone already received; a stolen rotate key for a context the person administers, mitigated by pre-rotation and thresholds ([manifest.md, Authorities and keys](specs/manifest.md#authorities-and-keys)). A stolen phone also carries the person's credentials and nym secrets encrypted under a hardware-wrapped key; they expire, the shield ledger on it is useless to a thief, and other devices of the person can remove its chat leaves ([credentials.md, Security considerations](specs/credentials.md#security-considerations)). A person who restores a backup onto a second phone while still voting from the first has two shield ledgers; the per-deck nullifier still counts them once per deck ([shield.md, Restore](specs/shield.md#restore)).

### Colluding servers

Which pairs matter, and what each collusion yields.

| Colluding parties | What they learn | Defense and residual |
| --- | --- | --- |
| Leader and Helper (phase 2) | Pseudonymous votes, the same as phase 1 | This is the non-collusion assumption; see below. Choice of an independent Helper is the open operator decision |
| Log and all its witnesses | They can show a split view | At least one honest witness is assumed; phones exchange checkpoint hashes in channels, which catches a split view against a subset of a context |
| Relay and gateway | Client IP joined to request content: which phone voted when, which phone fetched which context | Independent relay operator ([ADR 0073](decisions/0073-w0-07-ohttp-relay-operator.md)); phones may rotate between two relays; a context may name its own |
| Token issuer and the service spending the token | Which membership proof's token was spent on which request. The proof is anonymous, so this yields a context, which the token already carried | Tokens are blind-signed; issuance and spend are never on one connection (T-4) |
| Delivery service and blob store | Timing correlation between a send and a put: that some member attached a file to some channel | Both see only a context token; padding and the relay; residual is traffic analysis |
| Aggregator and verifier | Nothing new: the verifier never sees a pseudonym and the aggregator never sees a credential | Unlinkability is cryptographic |
| Organizer and aggregator (phase 1) | Pseudonymous votes plus the admitted list and the join tickets, still unlinked | Pseudonyms derive from the credential, not from membership admission, and the public fields of a ballot and of a join ticket are the same for every member of the context (context.md C16, ADR 0100), so they pair nobody. Residuals: a ticket made in the first hour after an issuer's epoch turns may show the old epoch; and arrival times at the Leader against activity seen in chat |
| Aggregator and log (one operator at launch) | Pseudonymous votes, and the public bundles of signed issue-map objects, which hold a chat identity key beside a membership proof | The proof's public fields are the same for every member (C16), and its nullifier is under a per-object scope unlinkable to the deck scope. Before ADR 0100 a context with an `any` node or a multi-verifier trust-list source let these fields differ, and a member alone in a combination could be matched to a ballot |
| Delivery service and log | A `promote-confirm` in a channel at time t and an object logged at t: a timing join between a chat event and a map object. For signed objects nothing new, since the object names the chat key; for unsigned objects the join reaches the channel, not the person | Relay on both paths; phones may delay the log submission |
| Gateway and any operator service | Nothing beyond the gateway alone, since the service sees the same decrypted request | The gateway logs no connection identifier beside a path (services.md logging table) |

### A network attacker

Controls: the path between a phone and the relay, or between services.

Wants: to see or alter traffic, or to learn who talks to what.

Stopped by: TLS everywhere; OHTTP on top for phone requests, so even a TLS-terminating middlebox at the relay sees nothing; every manifest and blob checked against its CID and signatures, so altered bytes are detected not trusted ([manifest.md, Verification](specs/manifest.md#verification)); checkpoints signed and cosigned, so a replayed old checkpoint fails the consistency check against the one the phone holds.

Remains: that a phone talks to a Hum relay at all is visible, and sizes are only bucketed.

### A modified client

Controls: one phone's software.

Wants: to vote twice, to vote without a credential, to make an aggregator release early, to make a log accept a bad release, to spend past the shield.

Stopped by: everything that is checked at an edge the client does not control. Nullifiers stop double voting. Presentations stop voting without a credential. Aggregators and the log check floors independently of the client ([manifest.md, Privacy floors](specs/manifest.md#privacy-floors), table). The contribution cap is enforced in the ballot encoding the aggregator checks, and in phase 2 by the VDAF's range proof ([ballot.md](specs/ballot.md)).

Remains: the shield is the person's own protection and a modified client can overspend it, harming only its user. A client can also lie to its user about anything.

## Assumptions and what breaks

| Assumption | Where it is relied on | If it fails |
| --- | --- | --- |
| Phase 1: the operator's aggregation is honest-but-curious | Noise is drawn as declared; ballots are deleted after release | Votes are still only pseudonymous, but the published release could carry less noise than claimed, and pseudonymous ballots could be kept. Nothing else in the system changes. This is why phase 2 exists |
| Phase 2: Leader and Helper do not collude | No party sees a vote | Collusion returns the system to phase 1's exposure: pseudonymous votes, still unlinked to people. The floors and the log are unaffected |
| At least one honest witness among those a phone requires | No split view of the log goes undetected | A colluding log and witnesses can show different histories to different people; the in-channel checkpoint exchange detects a split against part of a context but not a split against a whole context that never talks to anyone outside it |
| The context's log of record checks the clock on logged proofs | An authorship or sponsor proof stored in the log was made with a card valid at the time; the unsigned-slot window is the real one ([credentials.md, Validity](specs/credentials.md#validity), ADR 0101) | The author chooses the object's `issued`, and the only bound is that one log's clock at submission (within 3,600 seconds). Witnesses check consistency, never times, and later verifiers use no clock. A log of record that skips the check admits proofs from expired cards for as long as the issuer key stays listed, and unlimited unsigned objects back-dated into old windows. It cannot forge membership: the proof still needs a card the issuer signed. Votes are unaffected, because ballots are checked by the aggregator's clock against the deck. Bounding `issued` by cosignature timestamps is an open option in ADR 0101 |
| A log checks the clock on three manifest rules | A deck is not extended after it closed (deck.md D16); a release version is not logged after its deck's `expires` (release.md R13); a verifier's new attribute does not join an epoch whose cards exist (verifier.md rule 30). For decks and releases the log is the context's ledger; for a verifier manifest, which pins no context, it is whichever log accepts the version | D16 or R13 skipped, with the organizer and both aggregators acting together: publication about a deck reopens after phones dropped its shield entries, which defeats the yearly bound (phones still refuse a release version issued after the pinned deck version's `expires`, so a release must also be back-dated past the Helper). Rule 30 skipped: an attribute joins the current epoch, cards already issued carry the old message count, every verifier computes the new one, and those holders are locked out until handover because dedup blocks a re-issue. Later verifiers do not re-check rule 30 |
| The relay does not collude with the gateway | Network identity is separated from request content | Every anonymous request becomes attributable to an IP. Votes remain pseudonymous and unlinked to credentials, but participation and timing leak |
| The relay operator is independent of the operator | Network identity is separated from request content; O-5 cannot enforce this | Every anonymous request becomes attributable to an IP, the same failure as relay-gateway collusion, because it is the same party |
| The constants in the audited app build name the intended log, witnesses and relays | The first checkpoint and the first relay a phone ever trusts | The build is malicious; see Out of scope. Constants bootstrap only the first checkpoint, after which Global's logged witness list applies (services.md, Checkpoints), so they are trusted for less over time |
| Phase 2: the Helper is run by a party independent of the operator | No party sees a vote | Phase 2 collapses to phase 1's exposure. Phase 1 never relied on it |
| The cryptography holds: BBS unlinkability, the pseudonym extension, the set-membership predicate extension (ADR 0022, flagged for outside review before wave 1 builds it), Ed25519, AES-GCM, SHA-256 | Everything | A break in the credential scheme links issuance to presentation; the log and CIDs break with SHA-256. Algorithm bytes allow migration; nothing already published can be un-published |
| The DP mechanism and accounting are implemented as specified | Releases are private at the stated ε | A floating-point or sampler bug under-noises releases silently. This is why noise sampling is a seam, uses a vetted discrete sampler, and the reference implementation tests samplers statistically |
| Phones keep their keys in secure hardware and run the audited build | A person's own data is safe | A compromised or modified phone exposes its owner, nobody else |
| Verifier runtime isolation holds | A verifier cannot link issuance to anything | A runtime escape lets a verifier's code read what the host sees, which is still only the issuance session; unlinkability is cryptographic and survives |
| The context's named services are what members intended | Federation does not add trust | A context whose manifest names a one-party aggregator pair, a log with no independent witnesses, or a relay run by its gateway's operator is weaker; the last one silently removes the OHTTP guarantee. services.md rule O-5 catches only the open case where the relay and a service share an authority; against an operator who signs a relay manifest with a fresh keyset, the protection is the relay-operator assumption above, the app-shipped relay constants and the services screen that shows the context's relay choice. Every such choice is in a logged manifest members can read |

## Out of scope

Stated plainly so nobody assumes Hum covers them.

- A compromised phone's owner. Nothing protects a person from their own device.
- Coercion. A person can be made to show their phone, their hand and their results deck. There is no receipt-freeness; the receipt is designed to let the person check their ballot, which also lets a coercer who holds the phone. A coercer who does not hold the phone cannot ask the aggregator, because no per-leaf query exists ([services.md, Receipts](specs/services.md#receipts)). Deniable voting is a different design.
- Opinions a person states publicly in chat or on the issue map. Those are attributable by choice.
- Coordinated humans. Sybil resistance is per issuer and stops fake accounts, not organized groups or brigading with real credentials.
- Representativeness. A release describes who showed up.
- Operator-side availability. A malicious operator can refuse service; the protocol makes that visible and federable, not impossible.
- Verifiable noise. Nobody can yet prove a noise draw was fair. Phase 2 reduces, and does not remove, reliance on the aggregators for this.
- Platform-level traffic analysis by someone who watches the relay's and the gateway's networks at once. That is the relay-gateway collusion row with a different actor.
- Legal compulsion to change the protocol or the app build, beyond making it detectable through reproducible builds and the log.
- Side channels on the phone: screenshots, accessibility services, keyboards, backups a person enables. The app minimizes them where the platform allows and the UX spec says what it does; the protocol does not cover them.

## Seams mapped to specs

The seam list from [CLAUDE.md](../CLAUDE.md), with the spec that defines each one and the invariant it protects. A change in a seam needs the owner's review and the `seam-reviewer` agent.

| Seam | Defined in | Protects |
| --- | --- | --- |
| Signing, domain-separation strings, CID computation, canonical encoding | [manifest.md](specs/manifest.md) Encoding, Envelope; the registry of every domain string, scope prefix, exporter label and HKDF info in [services.md, Domain strings and scopes](specs/services.md#domain-strings-and-scopes), which lists each owner. The registry is the seam: a string not in it is a finding, and the owning spec's text wins over the registry when they disagree, which is also a finding | Invariant 6: nothing trusts a server; equivocation and replay are detectable |
| Key generation, storage and derivation; nonces; sealed blob format; keyrings | [storage.md](specs/storage.md); [chat.md](specs/chat.md) `hum/keyring/1`; [manifest.md](specs/manifest.md) Authorities | Invariant 4: keys never in manifests, logs or store requests; content stays sealed |
| Credential issuance and presentation, pseudonyms and nullifiers | [credentials.md](specs/credentials.md); [verifier.md](specs/verifier.md); [verifier-runtime.md](specs/verifier-runtime.md) | Invariant 2: three identities never linked; one vote per person |
| Ballot construction, contribution caps, shield accounting | [ballot.md](specs/ballot.md); [shield.md](specs/shield.md); [deck.md](specs/deck.md) release plan | Invariants 1 and 5: votes leave only as ballots; every release is a sum of bounded contributions |
| DP noise sampling, budget accounting, release tiers and floor checks | [release.md](specs/release.md); [context.md](specs/context.md) floors and daily count; [manifest.md](specs/manifest.md) Privacy floors; [docs/research/dp-polis](research/dp-polis/) | Invariant 3: floors at the edges, only stricter |
| Log proof verification and witness checks | [manifest.md](specs/manifest.md) Transparency logs, Verification step 7; [services.md](specs/services.md) Log and ledger, Witness | Invariant 6 |
| Anything that decides what leaves the phone | [ballot.md](specs/ballot.md); [services.md](specs/services.md) routing table and O-4; [chat.md](specs/chat.md); [storage.md](specs/storage.md); [agent-sponsor.md](specs/agent-sponsor.md) personal tier | Invariants 1, 2, 7 and 8 |

## Invariants and how they are tested

| Invariant | Mechanism | Continuous test |
| --- | --- | --- |
| 1. No vote is attributable | Ballots to aggregators only; DP at release; deletion after release | Simulator leak check searches every service's recorded view for any vote, hand or shield value ([prompts/wave-0/09-simulator.md](../prompts/wave-0/09-simulator.md), until `simulator.md` lands); conformance checks a client writes neither to a store |
| 2. Three identities never linked | An independent chat key; one credential secret used only under scope-separated proofs; services see at most one identity per request | Cross-spec identifier trace (W0-10); simulator joins every recorded identifier across services and fails on any pair from two identities |
| 3. Floors at the edges | Phone, aggregators and log each check; context floors only tighten | Conformance vectors for step 10 and each floor; simulator submits out-of-floor decks and releases |
| 4. No personal data in manifests; no sealed keys in manifests, logs or store requests | Type specs forbid personal fields; keys travel only in MLS and sealed indexes | Vectors reject manifests with forbidden fields; simulator scans store request logs for key material |
| 5. Every release is a sum | Ballot encoding as bounded vectors; the DAP mapping in [services.md, Phase 2](specs/services.md#phase-2-dap) | Reference implementation computes each part from vectors both ways; the twin implementation in wave 2 checks the DAP mapping |
| 6. Nothing trusts the reference | Keys in manifests; proofs before action; witnesses | Simulator's lying-log scenario; vectors for checkpoint and cosignature rejection |
| 7. Agents never vote; labeled; visible membership | Sponsor credentials come from verifier class `agent`, which no voting policy accepts; labels in every authored object; MLS event | Simulator's malicious-agent scenario; vectors for the membership event and labels |
| 8. Native only; no OTA code | App build process | Build pipeline check and reproducible-build hashes on the log; not a protocol test |

## Assumptions about sibling specs

Written against [manifest.md](specs/manifest.md) and [design.md](design.md) while the other wave-0 specs were in progress. Each of these is a claim this document makes about a sibling spec; if the spec says otherwise, the spec wins and this document is updated.

Landed and checked against this document on 2026-10-06: [context.md](specs/context.md), [deck.md](specs/deck.md), [release.md](specs/release.md), [storage.md](specs/storage.md), [chat.md](specs/chat.md), [verifier.md](specs/verifier.md), [verifier-runtime.md](specs/verifier-runtime.md), [trust-list.md](specs/trust-list.md), [issue-map.md](specs/issue-map.md), [take.md](specs/take.md), [agent-sponsor.md](specs/agent-sponsor.md), [credentials.md](specs/credentials.md), [ballot.md](specs/ballot.md), [shield.md](specs/shield.md). What they settle that this document relies on: the daily count is a per-day increment series with L2 sensitivity 1 inside the plan's budget; a store's `401` and `404` are byte-identical so nobody can probe for a sealed CID; a verifier module has no import that returns anything appearing in a presentation; release.md defines the rounds as logged versions, the Helper's phase 1 attestation and the yearly cap R14; chat.md issues per-channel tokens from a per-epoch delivery secret, never a per-member credential, and defines `agent-membership`, `promote-confirm` and `public-copy`; agent-sponsor.md defines the `agent` verifier class, `rateLimits.mapObjects` and `capabilities`. credentials.md lists every identifier with who sees it and uses one BBS credential system with per-scope pseudonyms, the ballot scope per deck lineage (ADRs 0020, 0021); ballot.md fixes the receipt leaf as a fixed-length hash over round, nonce and commitment, round-0 replacement until `closes`, and one DAP task per (round, part) (ADR 0024); shield.md charges the plan's total before the first ballot, keeps a sliding 365-day window in ρ, never backs the ledger up and rebuilds it conservatively after a restore (ADR 0025); credentials.md's sealed backup and one-voting-device rule are ADR 0023.

Every wave-0 spec this document cites has landed. `simulator.md` (W0-09) and `conformance.md` (W0-08) have landed too; where this document points at the W0-09 prompt for a simulator check, `specs/simulator.md` is now the reference.


One residual the landed specs make explicit and this document carries: the phase 1 aggregator learns a pseudonym's attribute value from a breakdown contribution ([deck.md, Open questions](specs/deck.md#open-questions)). Until the owner decides, that is a row in the aggregator's phase 1 "sees" column, not a leak of the identity link.

## Open questions

- **Receipt-freeness.** Whether a future tier should trade the ballot receipt for coercion resistance. Not for draft 0.1.
- **Timing across operator services.** Whether phones should add random delays between token issuance, store puts and delivery sends, and what that costs in UX.
- **Whole-context split views.** A log colluding with its witnesses against an entire isolated context is not caught by in-channel checkpoint exchange. Whether phones should also gossip checkpoints across contexts, or whether Global's channel is enough.
- **Verifier evidence breaches.** Whether core verifiers should be required to keep less than they are allowed to declare.
- **Privacy targets.** ε per release and the yearly shield remain the owner's decision; every residual above scales with them.
