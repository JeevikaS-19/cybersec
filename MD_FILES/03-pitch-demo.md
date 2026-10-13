# 03 · Pitch and Demo

Focus: **innovation, scalability, product ready, amazing pitch.**

**One line:** *Chains prove a log wasn't changed. We also prove it matches reality.*

---

## Round 1 · 3:00 to 4:00 PM · Idea + skeleton
We won't have the full prototype. Sell the idea and show it's real.

**Slides (5 min)**
1. **Hook:** A bank insider changes a balance at 2 a.m. and covers it up. Logs are the only evidence, and the attacker controls them.
2. **Problem:** today's logs sit on the same machine as the attacker. Admin access = edit access.
3. **Insight:** a log must prove itself to someone outside, and match reality.
4. **Three layers, three questions**
   - Sealed chain: was anything changed?
   - Outside witness: was anything hidden?
   - Truth check: does it match reality?
5. **Our innovation:** the truth check. Show the attack only we catch: a direct database edit with no log entry.
6. **Skeleton demo** (below).
7. **Plan to Round 2 and Final:** what we'll show next.

**Live demo (2 min)**
- Fake bank running, entries flowing to the witness, dashboard green.
- Edit an entry → Layer 1 goes red, shows the exact entry.
- If ready: kill the agent → silence alert.
- If anything breaks: switch to dashboard fake-data mode and walk through the story.

---

## Round 2 · 7:30 to 8:30 PM · It works
**Demo (4 min)**
1. All green.
2. Edit an entry → Layer 1 red. "Everyone catches this."
3. Kill the agent → Layer 2 red.
4. **Edit the balance directly in the database** → Layer 1 and 2 stay green, **Layer 3 red**. "Every other log system just missed this."
5. **Push a fake, correctly signed transfer** → Layer 3 red: no settlement confirmation.

**Fallback demo (if Step 8 / the feed isn't ready by the 6:30 freeze; decide by 6:30, rehearse it, never improvise live):** all green → A1 edit (Layer 1 red within 5 s via the self-check) → A4 kill agent (Layer 2 red) → A12 DB edit (Layer 3 red via the state challenge). Stop there, skip A13. Say the confirmation-feed layer is being wired in and will be in the final demo.

**Then:** progress since Round 1, what's coming for the final.

---

## Final · Day 2, 10:00 AM · Product
**Slides (7 min) + demo (4 min)**
1. Hook
2. Problem
3. Three layers
4. **Live demo** (Round 2 flow + auditor export)
5. **Innovation:** attacks caught only by us (DB edit, fake transfer, redirected transfer)
6. **Scalability**
7. **Product ready**
8. Honest limits + roadmap
9. Who it's for

### Scalability talking points
- **One agent, any platform:** the agent is a small sidecar; a platform plugs in by mapping its fields.
- **Witness scales out:** each platform's chain is independent, so witnesses split by platform.
- **Anchoring cost doesn't grow:** one hash per time interval, not one per entry.
- **Reconciliation is fast:** matching by transaction ID is a direct lookup, not a search.
- **More trust = more witnesses:** add independent witnesses run by different parties.

### Product-ready talking points
- **5-step onboarding:** install agent, register key, map fields, set policies, create accounts.
- **Two users, two jobs:** SOC sees alerts live; auditor exports proof.
- **Roles:** no one, not even admins, can edit or delete entries. Every action is itself logged.
- **Compliance fit:** CERT-In 2022 directions (log retention), RBI cybersecurity framework, PCI DSS Requirement 10 (audit logs).
- **Deploys as containers** (slide).

### Honest limits (say them, judges respect it)
- If the attacker controls the bank **and** the settlement side, reconciliation agrees with the lie. That's two organisations.
- **Our demo's feed is a stub**, not a real settlement network: the bank tells it about transfers over a side channel, because we don't have a real settlement partner to wire into a 24-hour build. In production the feed is run by a genuinely separate party (the real settlement network) with no channel from the platform into it at all. Say this before a judge finds it — it reads as rigor, not a weakness.
- Genesis must happen on a clean system.
- An attacker who steals the agent's current key can keep signing heartbeats after killing it. Silence catches a plain kill; the state challenge and the feed catch the rest.
- Future: hardware attestation (TPM).

---

## Judge questions to rehearse
| Question | Answer |
|---|---|
| What if root changes data before it's logged? | Truth check: the settlement side never confirmed it. |
| How is your balance check different from a hash chain? | It compares with sources the bank doesn't control. Show the DB-edit attack. |
| What if the witness is hacked? | Signed receipts, anchors, and the feed's own copy disagree with it. |
| What can't you catch? | Bank and settlement both compromised. |
| **Couldn't the attacker feed your "independent" feed lies too?** | **In this demo, the feed is a stub fed over a side channel from the bank — yes, a root attacker controlling that channel could lie to it too. That's a demo simplification, not how it works in production: the real feed is a separate organisation's system (actual settlement) with no channel from the platform at all.** |
| Why not just use blockchain? | We anchor to one, but you don't need a blockchain per entry. It's slower and costlier for the same guarantee. |
| How does this scale? | Scalability slide. |

## Demo rules
- Same attack order every rehearsal.
- One person drives, one person talks, one person runs attacks.
- Backup screen recording ready for every round.
- Hotspot on, laptops plugged in, notifications off.